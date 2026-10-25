package clients

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	// 4A CAS 协议端点(见 docs/sources/setup-grafana/configure-security/configure-authentication/cas/)
	casLoginPath    = "/4a/credentials/cas"
	casValidatePath = "/4a/cas/serviceValidate"
	casLogoutPath   = "/4a/cas/logout"

	casTicketQueryName = "ticket"
	// 复用 OAuthLogin 写入/删除的 oauth_state cookie(pkg/api/login_oauth.go),
	// 避免为 CAS 单独引入一套 cookie 生命周期管理
	casStateCookieName = "oauth_state"
	// state 为 base64url 编码,"." 不在其字母表内,可安全用作分隔符
	casStateSeparator = "."

	casResponseBodyLimit = 64 << 10
)

var (
	errCASDisabled      = errutil.BadRequest("auth.cas.disabled", errutil.WithPublicMessage("CAS client is disabled"))
	errCASInternal      = errutil.Internal("auth.cas.internal", errutil.WithPublicMessage("An internal error occurred in the CAS client"))
	errCASGenState      = errutil.Internal("auth.cas.state.internal", errutil.WithPublicMessage("An internal error occurred"))
	errCASMissingState  = errutil.BadRequest("auth.cas.state.missing", errutil.WithPublicMessage("Missing saved CAS state"))
	errCASInvalidState  = errutil.Unauthorized("auth.cas.state.invalid", errutil.WithPublicMessage("Provided state does not match stored state"))
	errCASTicketMissing = errutil.BadRequest("auth.cas.ticket.missing", errutil.WithPublicMessage("Missing CAS ticket"))
	errCASTicketInvalid = errutil.Unauthorized("auth.cas.ticket.invalid", errutil.WithPublicMessage("Failed to validate CAS ticket"))
)

var (
	_ authn.RedirectClient = (*CAS)(nil)
	_ authn.LogoutClient   = (*CAS)(nil)
)

func ProvideCAS(cfg *setting.Cfg) (*CAS, error) {
	tlsConfig, err := casTLSConfig(&cfg.CAS)
	if err != nil {
		return nil, err
	}
	return &CAS{
		cfg: cfg,
		log: log.New(authn.ClientCAS),
		client: &http.Client{
			Timeout:   cfg.CAS.Timeout,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig},
		},
	}, nil
}

// CAS 实现企业 4A 的 CAS 协议认证:跳转 4A 登录页 -> 回调携带 ticket -> serviceValidate 校验。
// 与 OAuth 不同,CAS 没有 token 交换,因此不走 social connector 体系(oauth2 语义),作为独立 authn client 存在。
type CAS struct {
	cfg    *setting.Cfg
	log    log.Logger
	client *http.Client
}

func (c *CAS) Name() string {
	return authn.ClientCAS
}

func (c *CAS) IsEnabled() bool {
	return c.cfg.CAS.Enabled
}

// RedirectURL 发起登录:cookie 值为 state + "." + HMAC(state, SecretKey+AppID)。
// 4A 不回传 state,回调时仅验证 cookie 系本实例签发(见 Authenticate),配合
// 一次性 ticket 与精确匹配的 service 参数防 CSRF
func (c *CAS) RedirectURL(ctx context.Context, r *authn.Request) (*authn.Redirect, error) {
	if !c.cfg.CAS.Enabled {
		return nil, errCASDisabled.Errorf("cas client is disabled")
	}

	state, mac, err := genCASState(c.cfg.SecretKey, c.cfg.CAS.AppID)
	if err != nil {
		return nil, errCASGenState.Errorf("failed to generate CAS state: %w", err)
	}

	return &authn.Redirect{
		URL: c.loginURL(),
		Extra: map[string]string{
			authn.KeyOAuthState: state + casStateSeparator + mac,
		},
	}, nil
}

// Authenticate 处理 4A 回调:校验 state cookie -> serviceValidate 校验 ticket -> 组装 Identity
func (c *CAS) Authenticate(ctx context.Context, r *authn.Request) (*authn.Identity, error) {
	r.SetMeta(authn.MetaKeyAuthModule, login.CASAuthModule)

	if !c.cfg.CAS.Enabled {
		return nil, errCASDisabled.Errorf("cas client is disabled")
	}

	stateCookie, err := r.HTTPRequest.Cookie(casStateCookieName)
	if err != nil || stateCookie.Value == "" {
		return nil, errCASMissingState.Errorf("missing state cookie")
	}
	if !verifyCASState(stateCookie.Value, c.cfg.SecretKey, c.cfg.CAS.AppID) {
		return nil, errCASInvalidState.Errorf("provided state did not match stored state")
	}

	ticket := r.HTTPRequest.URL.Query().Get(casTicketQueryName)
	if ticket == "" {
		return nil, errCASTicketMissing.Errorf("missing ticket in callback request")
	}

	user, err := c.validateTicket(ctx, ticket)
	if err != nil {
		return nil, err
	}

	return &authn.Identity{
		Login:           user.Login,
		Name:            user.Name,
		Email:           user.Email,
		AuthenticatedBy: login.CASAuthModule,
		AuthID:          user.Login,
		ClientParams: authn.ClientParams{
			SyncUser:        true,
			AllowSignUp:     c.cfg.CAS.AllowSignUp,
			FetchSyncedUser: true,
			SyncPermissions: true,
			// 不按 login/email 关联既有本地账号(与 OAuth 默认一致),仅按 user_auth 的
			// (AuthModule, AuthId) 匹配,避免 CAS 用户名撞上本地账号时被静默关联
			LookUpParams: login.UserLookupParams{},
		},
	}, nil
}

// Logout 用户主动登出时跳转 4A 登出端点(cas.md:严禁非用户主动登出时调用,此处
// 仅由登出编排按 AuthenticatedBy=cas 触发,符合约束)
func (c *CAS) Logout(ctx context.Context, _ identity.Requester, _ *auth.UserToken) (*authn.Redirect, bool) {
	if !c.cfg.CAS.Enabled {
		return nil, false
	}

	if c.cfg.CAS.SignoutRedirectURL != "" {
		return &authn.Redirect{URL: c.cfg.CAS.SignoutRedirectURL}, true
	}

	q := url.Values{}
	q.Set("appid", c.cfg.CAS.AppID)
	q.Set("url", c.redirectAfterLogoutURL())
	return &authn.Redirect{URL: c.cfg.CAS.ServerURL + casLogoutPath + "?" + q.Encode()}, true
}

func (c *CAS) loginURL() string {
	q := url.Values{}
	q.Set("appid", c.cfg.CAS.AppID)
	q.Set("service", c.serviceURL())
	return c.cfg.CAS.ServerURL + casLoginPath + "?" + q.Encode()
}

// serviceURL 是 4A 登录成功后的回调地址。必须是静态地址:4A 按 appid 对 service
// 精确匹配注册值,不能携带 state 等动态参数。AppURL 已含 root_url 的子路径
// (pkg/setting readServerURLSettings),不能再拼 AppSubURL
func (c *CAS) serviceURL() string {
	return strings.TrimSuffix(c.cfg.AppURL, "/") + "/login/cas"
}

func (c *CAS) redirectAfterLogoutURL() string {
	return strings.TrimSuffix(c.cfg.AppURL, "/") + "/login"
}

type casUserInfo struct {
	Login string
	Name  string
	Email string
}

// validateTicket 调用 serviceValidate。4A 约定:成功 200+XML,失败 401+纯文本(非 XML),
// 因此必须先按状态码分流再解析
func (c *CAS) validateTicket(ctx context.Context, ticket string) (*casUserInfo, error) {
	q := url.Values{}
	q.Set("appid", c.cfg.CAS.AppID)
	q.Set("ticket", ticket)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.CAS.ServerURL+casValidatePath+"?"+q.Encode(), nil)
	if err != nil {
		return nil, errCASInternal.Errorf("failed to create CAS validation request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errCASInternal.Errorf("failed to call CAS serviceValidate: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, casResponseBodyLimit))
	if err != nil {
		return nil, errCASInternal.Errorf("failed to read CAS validation response: %w", err)
	}

	ctxLogger := c.log.FromContext(ctx)

	switch {
	case resp.StatusCode == http.StatusOK:
		parsed := &casServiceResponse{}
		if err := xml.Unmarshal(body, parsed); err != nil {
			return nil, errCASInternal.Errorf("failed to parse CAS validation response: %w", err)
		}
		if parsed.AuthenticationFailure != nil {
			ctxLogger.Warn("CAS ticket validation failed", "body", truncateForLog(string(body)))
			return nil, errCASTicketInvalid.Errorf("cas ticket validation was not successful")
		}
		if parsed.AuthenticationSuccess == nil || parsed.AuthenticationSuccess.User == "" {
			return nil, errCASTicketInvalid.Errorf("cas ticket validation was not successful")
		}
		return userInfoFromXML(parsed.AuthenticationSuccess), nil
	case resp.StatusCode == http.StatusUnauthorized:
		// 错误明细仅入服务端日志,公开消息保持通用
		ctxLogger.Warn("CAS ticket validation rejected", "body", truncateForLog(string(body)))
		return nil, errCASTicketInvalid.Errorf("cas ticket validation failed")
	default:
		ctxLogger.Error("CAS serviceValidate returned unexpected status", "status", resp.StatusCode, "body", truncateForLog(string(body)))
		return nil, errCASInternal.Errorf("cas serviceValidate returned unexpected status: %d", resp.StatusCode)
	}
}

func userInfoFromXML(success *casAuthenticationSuccess) *casUserInfo {
	info := &casUserInfo{Login: success.User}
	if attrs := success.Attributes; attrs != nil {
		// 4A 的 cn 是显示名(如"张三"),name 与登录名相同;取 cn,为空回退 name
		info.Name = attrs.CN
		if info.Name == "" {
			info.Name = attrs.Name
		}
		info.Email = attrs.Email
	}
	return info
}

func truncateForLog(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// casServiceResponse 的 xml tag 不带 namespace 前缀,encoding/xml 按 local name 匹配,
// 因此兼容 4A 的非标 namespace(http://4a.pab.com.cn/cas)、无前缀及任意其他前缀
type casServiceResponse struct {
	AuthenticationSuccess *casAuthenticationSuccess `xml:"authenticationSuccess"`
	AuthenticationFailure *struct {
		Code string `xml:"code,attr"`
	} `xml:"authenticationFailure"`
}

type casAuthenticationSuccess struct {
	User       string `xml:"user"`
	Attributes *struct {
		CN    string `xml:"cn"`
		Name  string `xml:"name"`
		Email string `xml:"email"`
	} `xml:"attributes"`
}

func genCASState(secret, seed string) (string, string, error) {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		return "", "", err
	}
	state := base64.RawURLEncoding.EncodeToString(rnd)
	return state, hex.EncodeToString(hmacCASState(state, secret, seed)), nil
}

func hmacCASState(state, secret, seed string) []byte {
	mac := hmac.New(sha256.New, []byte(secret+seed))
	mac.Write([]byte(state))
	return mac.Sum(nil)
}

func verifyCASState(value, secret, seed string) bool {
	state, mac, ok := strings.Cut(value, casStateSeparator)
	if !ok || state == "" || mac == "" {
		return false
	}
	given, err := hex.DecodeString(mac)
	if err != nil {
		return false
	}
	return hmac.Equal(given, hmacCASState(state, secret, seed))
}

func casTLSConfig(s *setting.CASSettings) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//nolint:gosec // gated by config, documented as insecure
		InsecureSkipVerify: s.TLSSkipVerify,
	}
	if s.TLSCACert != "" {
		pem, err := os.ReadFile(s.TLSCACert)
		if err != nil {
			return nil, errCASInternal.Errorf("failed to read CAS tls_client_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errCASInternal.Errorf("failed to parse CAS tls_client_ca certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}
