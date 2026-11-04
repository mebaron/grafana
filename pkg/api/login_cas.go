package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/middleware/cookies"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
)

// casStateCookieName 专用 state cookie,不复用 oauth_state,避免与 OAuth 并存时互相干扰
const casStateCookieName = "cas_state"

// state 为 base64url 编码,"." 不在其字母表内,可安全用作分隔符
const casStateSeparator = "."

var (
	errCASStateMissing = errutil.BadRequest(
		"auth.cas.state.missing",
		errutil.WithPublicMessage("Missing saved CAS state"),
	)
	errCASStateInvalid = errutil.Unauthorized(
		"auth.cas.state.invalid",
		errutil.WithPublicMessage("Provided state does not match stored state"),
	)
	errCASStateInternal = errutil.Internal(
		"auth.cas.state.internal",
		errutil.WithPublicMessage("An internal error occurred"),
	)
	errCASTicketMissing = errutil.BadRequest(
		"auth.cas.ticket.missing",
		errutil.WithPublicMessage("Missing CAS ticket"),
	)
	errCASLoginInternal = errutil.Internal(
		"auth.cas.login.internal",
		errutil.WithPublicMessage("Failed to sign in user"),
	)
)

// CASLogin 发起 CAS(4A) 登录:GET /sso/login。
// 写 HMAC 签名的 cas_state cookie(4A 协议不回传 state,回调时仅验证 cookie 系
// 本实例签发,配合一次性 ticket 防 login-CSRF);redirectTo 经校验后存 redirect_to
// cookie,回调成功后经 GetRedirectURL 跳回最初访问的页面
func (hs *HTTPServer) CASLogin(c *contextmodel.ReqContext) {
	if hs.casService == nil || !hs.Cfg.CAS.Enabled {
		c.Redirect(hs.Cfg.AppSubURL + "/login")
		return
	}

	state, mac, err := genCASState(hs.Cfg.SecretKey, hs.Cfg.CAS.AppID)
	if err != nil {
		hs.redirectWithError(c, errCASStateInternal.Errorf("failed to generate state: %w", err))
		return
	}
	cookies.WriteCookie(c.Resp, casStateCookieName, state+casStateSeparator+mac,
		hs.Cfg.OAuthCookieMaxAge, hs.CookieOptionsFromCfg)

	if redirectTo := c.Query("redirectTo"); redirectTo != "" {
		// redirectTo 可能已被去掉 AppSubURL 前缀(auto-login 转发口径),
		// 而 ValidateRedirectTo 在配置子路径时要求带前缀,先补齐再校验
		if hs.Cfg.AppSubURL != "" && !strings.HasPrefix(redirectTo, hs.Cfg.AppSubURL+"/") {
			redirectTo = hs.Cfg.AppSubURL + redirectTo
		}
		if err := hs.ValidateRedirectTo(redirectTo); err == nil {
			cookies.WriteCookie(c.Resp, "redirect_to", redirectTo, hs.Cfg.OAuthCookieMaxAge, hs.CookieOptionsFromCfg)
		}
	}

	c.Redirect(hs.casService.LoginURL())
}

// CASCallback 处理 4A 回调:GET /sso/callback?ticket=...。
// 验 state cookie → 服务端 serviceValidate(不信任浏览器携带的用户信息)→ 用户
// 落库 → 原生建会话(loginUserWithUser)→ 跳回原页。失败统一写 login_error cookie
// 回 /login,LoginView 检测到该 cookie 会跳过 auto-login,不会形成重定向循环
func (hs *HTTPServer) CASCallback(c *contextmodel.ReqContext) {
	if hs.casService == nil || !hs.Cfg.CAS.Enabled {
		c.Redirect(hs.Cfg.AppSubURL + "/login")
		return
	}

	stateCookie, err := c.Req.Cookie(casStateCookieName)
	// 无论后续成败先删 state cookie,防止重放
	cookies.DeleteCookie(c.Resp, casStateCookieName, hs.CookieOptionsFromCfg)
	if err != nil || stateCookie.Value == "" {
		hs.redirectWithError(c, errCASStateMissing.Errorf("missing state cookie"))
		return
	}
	if !verifyCASState(stateCookie.Value, hs.Cfg.SecretKey, hs.Cfg.CAS.AppID) {
		hs.redirectWithError(c, errCASStateInvalid.Errorf("provided state did not match stored state"))
		return
	}

	ticket := c.Query("ticket")
	if ticket == "" {
		hs.redirectWithError(c, errCASTicketMissing.Errorf("missing ticket in callback request"))
		return
	}

	casUser, err := hs.casService.ValidateTicket(c.Req.Context(), ticket)
	if err != nil {
		hs.redirectWithError(c, err)
		return
	}

	usr, err := hs.casService.UpsertUser(c.Req.Context(), casUser)
	if err != nil {
		hs.redirectWithError(c, err)
		return
	}

	if err := hs.loginUserWithUser(usr, c); err != nil {
		hs.redirectWithError(c, errCASLoginInternal.Errorf("failed to sign in user: %w", err))
		return
	}

	metrics.MApiLoginOAuth.Inc()
	c.Redirect(hs.GetRedirectURL(c))
}

// genCASState 生成随机 state 与其 HMAC 签名,key 为 SecretKey+AppID(实例与appId 绑定)
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
