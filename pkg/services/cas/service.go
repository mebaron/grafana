// Package cas 实现企业 4A 平台的 CAS 协议认证:登录跳转、ticket 服务端校验、
// XML 属性映射与用户落库。作为独立 handler(/sso/login + /sso/callback)的支撑服务,
// 不注册 authn client,会话创建由 pkg/api/login_cas.go 走原生 loginUserWithUser。
package cas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/quota"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// casResponseBodyLimit 限制 serviceValidate 响应体读取量,防御异常大响应
const casResponseBodyLimit = 64 << 10

var (
	errCASTicketInvalid = errutil.Unauthorized(
		"auth.cas.ticket.invalid",
		errutil.WithPublicMessage("CAS ticket validation failed"),
	)
	errCASInternal = errutil.Internal(
		"auth.cas.internal",
		errutil.WithPublicMessage("An internal error occurred in CAS authentication"),
	)
	errCASSignupDisabled = errutil.Unauthorized(
		"auth.cas.signup-disabled",
		errutil.WithPublicMessage("Sign up is disabled"),
	)
	errCASUserDisabled = errutil.Unauthorized(
		"auth.cas.user-disabled",
		errutil.WithPublicMessage("User is disabled"),
	)
	errCASQuotaReached = errutil.Forbidden(
		"auth.cas.quota-reached",
		errutil.WithPublicMessage("Users quota reached"),
	)
)

var errGettingUserQuota = errors.New("error getting user quota")

// CASUser 是 serviceValidate 成功后按配置属性名映射出的外部用户信息
type CASUser struct {
	Login string
	Name  string
	Email string
	// Role 为空串表示未映射或角色值无效,走 Grafana 默认组织角色
	Role org.RoleType
}

type Service struct {
	cfg             *setting.Cfg
	log             log.Logger
	client          *http.Client
	authInfoService login.AuthInfoService
	userService     user.Service
	orgService      org.Service
	quotaService    quota.Service
}

func ProvideService(cfg *setting.Cfg, authInfoService login.AuthInfoService,
	userService user.Service, orgService org.Service, quotaService quota.Service,
) (*Service, error) {
	tlsConfig, err := casTLSConfig(&cfg.CAS)
	if err != nil {
		return nil, err
	}
	svc := &Service{
		cfg: cfg,
		log: log.New("cas"),
		client: &http.Client{
			Timeout:   cfg.CAS.Timeout,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig},
		},
		authInfoService: authInfoService,
		userService:     userService,
		orgService:      orgService,
		quotaService:    quotaService,
	}
	if cfg.CAS.Enabled {
		svc.warnIncompleteConfig()
	}
	return svc, nil
}

// warnIncompleteConfig 启用但必填项缺失时仅告警不阻断启动(与其他 provider 容忍口径一致),
// 4A 流程会在运行时报错
func (s *Service) warnIncompleteConfig() {
	var missing []string
	if s.cfg.CAS.AppID == "" {
		missing = append(missing, "app_id")
	}
	if s.cfg.CAS.LoginURL == "" {
		missing = append(missing, "login_url")
	}
	if s.cfg.CAS.ServiceValidateURL == "" {
		missing = append(missing, "service_validate_url")
	}
	if s.cfg.CAS.Service == "" {
		missing = append(missing, "service")
	}
	if len(missing) > 0 {
		s.log.Warn("CAS is enabled but required configuration is missing", "missing", strings.Join(missing, ","))
	}
}

// LoginURL 构造 4A 登录跳转地址:固定参数 appId + 动态参数 service(回调地址)
func (s *Service) LoginURL() string {
	return appendQueryParams(s.cfg.CAS.LoginURL, url.Values{
		"appId":   {s.cfg.CAS.AppID},
		"service": {s.cfg.CAS.Service},
	})
}

// LogoutURL 构造 4A 登出地址:固定参数 appId + 回跳参数 url。
// 仅在用户主动登出时调用(4A 约束:严禁登录前调用登出)
func (s *Service) LogoutURL(redirectTarget string) string {
	return appendQueryParams(s.cfg.CAS.LogoutURL, url.Values{
		"appId": {s.cfg.CAS.AppID},
		"url":   {redirectTarget},
	})
}

// appendQueryParams 拼接 query 参数,兼容端点本身已带 query(如 version=2)的情况
func appendQueryParams(base string, q url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode()
}

// ValidateTicket 服务端调用 serviceValidate 校验 ticket,只信此返回,不信浏览器携带的信息。
// 4A 约定:成功 200+XML,失败 401+纯文本(非 XML),必须先按状态码分流再解析
func (s *Service) ValidateTicket(ctx context.Context, ticket string) (*CASUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		appendQueryParams(s.cfg.CAS.ServiceValidateURL, url.Values{
			"appId":  {s.cfg.CAS.AppID},
			"ticket": {ticket},
		}), nil)
	if err != nil {
		return nil, errCASInternal.Errorf("failed to create CAS validation request: %w", err)
	}

	resp, err := s.client.Do(req)
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

	ctxLogger := s.log.FromContext(ctx)
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
		return s.casUserFromXML(parsed.AuthenticationSuccess), nil
	case resp.StatusCode == http.StatusUnauthorized:
		// 错误明细仅入服务端日志,公开消息保持通用
		ctxLogger.Warn("CAS ticket validation rejected", "body", truncateForLog(string(body)))
		return nil, errCASTicketInvalid.Errorf("cas ticket validation failed")
	default:
		ctxLogger.Error("CAS serviceValidate returned unexpected status", "status", resp.StatusCode, "body", truncateForLog(string(body)))
		return nil, errCASInternal.Errorf("cas serviceValidate returned unexpected status: %d", resp.StatusCode)
	}
}

func (s *Service) casUserFromXML(success *casAuthenticationSuccess) *CASUser {
	info := &CASUser{Login: success.User}
	attrs := success.attrMap()
	// 属性名可配置,未配置的字段不映射
	if s.cfg.CAS.EmailAttribute != "" {
		info.Email = attrs[s.cfg.CAS.EmailAttribute]
	}
	if s.cfg.CAS.NameAttribute != "" {
		info.Name = attrs[s.cfg.CAS.NameAttribute]
	}
	if s.cfg.CAS.RoleAttribute != "" {
		info.Role = normalizeOrgRole(attrs[s.cfg.CAS.RoleAttribute])
	}
	return info
}

// UpsertUser 按 user_auth 的 (cas, login) 连接查找用户:存在则同步 email/name/角色,
// 不存在则按 allow_sign_up 决定是否创建。刻意不做本地账号关联(不按 login/email 撞名
// 接管既有账号),避免 CAS 用户名与本地账号撞名时被静默关联
func (s *Service) UpsertUser(ctx context.Context, cu *CASUser) (*user.User, error) {
	usr, userAuth, err := s.getUser(ctx, cu.Login)
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		s.log.FromContext(ctx).Error("Failed to fetch user", "error", err, "login", cu.Login)
		return nil, errCASInternal.Errorf("unable to retrieve user: %w", err)
	}

	if errors.Is(err, user.ErrUserNotFound) {
		if !s.cfg.CAS.AllowSignUp {
			s.log.FromContext(ctx).Warn("Failed to create user, signup is not allowed", "login", cu.Login)
			return nil, errCASSignupDisabled.Errorf("cas signup is not allowed")
		}

		usr, err = s.createUser(ctx, cu)
		// 并发首登可能同时到达创建路径,仅一个请求成功,其余拿到
		// ErrUserAlreadyExists 后重查一次即可(与 UserSync 处理一致)
		if errors.Is(err, user.ErrUserAlreadyExists) {
			usr, _, err = s.getUser(ctx, cu.Login)
		}
		if err != nil {
			s.log.FromContext(ctx).Error("Failed to create user", "error", err, "login", cu.Login)
			return nil, errCASInternal.Errorf("unable to create user: %w", err)
		}
		return usr, nil
	}

	if usr.IsDisabled {
		return nil, errCASUserDisabled.Errorf("user is disabled")
	}

	if err := s.updateUserAttributes(ctx, usr, cu, userAuth); err != nil {
		s.log.FromContext(ctx).Error("Failed to update user", "error", err, "login", cu.Login)
		return nil, errCASInternal.Errorf("unable to update user: %w", err)
	}
	return usr, nil
}

// getUser 按 (AuthModule=cas, AuthId=login) 查 user_auth 连接;连接存在但用户已
// 删除时清理孤儿行并按未找到处理(与 UserSync.getUser 一致)
func (s *Service) getUser(ctx context.Context, authID string) (*user.User, *login.UserAuth, error) {
	authInfo, err := s.authInfoService.GetAuthInfo(ctx, &login.GetAuthInfoQuery{
		AuthModule: login.CASAuthModule,
		AuthId:     authID,
	})
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return nil, nil, err
	}
	if errors.Is(err, user.ErrUserNotFound) {
		return nil, nil, user.ErrUserNotFound
	}

	usr, err := s.userService.GetByID(ctx, &user.GetUserByIDQuery{ID: authInfo.UserId})
	if err == nil {
		return usr, authInfo, nil
	}
	if !errors.Is(err, user.ErrUserNotFound) {
		return nil, nil, err
	}

	if err := s.authInfoService.DeleteUserAuthInfo(ctx, authInfo.UserId); err != nil {
		s.log.FromContext(ctx).Error("Failed to clean up user auth", "error", err, "login", authID)
	}
	return nil, nil, user.ErrUserNotFound
}

func (s *Service) updateUserAttributes(ctx context.Context, usr *user.User, cu *CASUser, userAuth *login.UserAuth) error {
	updateCmd := &user.UpdateUserCommand{UserID: usr.ID}
	needsUpdate := false

	// login 是身份键不做变更;仅同步 email/name(空值不覆盖)
	if cu.Email != "" && cu.Email != usr.Email {
		updateCmd.Email = cu.Email
		usr.Email = cu.Email
		// 新邮箱需重置验证状态(与 UserSync 口径一致)
		verified := false
		updateCmd.EmailVerified = &verified
		usr.EmailVerified = verified
		needsUpdate = true
	}
	if cu.Name != "" && cu.Name != usr.Name {
		updateCmd.Name = cu.Name
		usr.Name = cu.Name
		needsUpdate = true
	}

	if needsUpdate {
		if err := s.userService.Update(ctx, updateCmd); err != nil {
			return err
		}
	}

	// 角色同步:role_attribute 映射出有效角色时更新用户默认 org 的角色
	// (user.User 不携带当前角色,无条件更新,幂等)
	if cu.Role != "" {
		if err := s.orgService.UpdateOrgUser(ctx, &org.UpdateOrgUserCommand{
			OrgID:  usr.OrgID,
			UserID: usr.ID,
			Role:   cu.Role,
		}); err != nil {
			return err
		}
	}

	// 维护 user_auth 连接:存在时刷新,缺失时补建
	if userAuth == nil {
		return s.authInfoService.SetAuthInfo(ctx, &login.SetAuthInfoCommand{
			UserId:     usr.ID,
			AuthModule: login.CASAuthModule,
			AuthId:     cu.Login,
		})
	}
	return s.authInfoService.UpdateAuthInfo(ctx, &login.UpdateAuthInfoCommand{
		UserId:     usr.ID,
		AuthModule: login.CASAuthModule,
		AuthId:     cu.Login,
	})
}

func (s *Service) createUser(ctx context.Context, cu *CASUser) (*user.User, error) {
	// quota 检查覆盖 user 与 org 两个 target(与 UserSync.createUser 一致)
	for _, srv := range []string{user.QuotaTargetSrv, org.QuotaTargetSrv} {
		limitReached, errLimit := s.quotaService.CheckQuotaReached(ctx, quota.TargetSrv(srv), nil)
		if errLimit != nil {
			s.log.FromContext(ctx).Error("Failed to check quota", "error", errLimit)
			return nil, errCASInternal.Errorf("%w", errGettingUserQuota)
		}
		if limitReached {
			return nil, errCASQuotaReached.Errorf("users quota reached")
		}
	}

	usr, err := s.userService.Create(ctx, &user.CreateUserCommand{
		Login: cu.Login,
		Email: cu.Email,
		Name:  cu.Name,
		// 空串时 user 服务回退 auto_assign_org_role(默认 Viewer),即 Grafana 默认组织角色
		DefaultOrgRole: string(cu.Role),
	})
	if err != nil {
		return nil, err
	}

	if err := s.authInfoService.SetAuthInfo(ctx, &login.SetAuthInfoCommand{
		UserId:     usr.ID,
		AuthModule: login.CASAuthModule,
		AuthId:     cu.Login,
	}); err != nil {
		return nil, err
	}
	return usr, nil
}

// casServiceResponse 的 xml tag 不带 namespace 前缀,encoding/xml 按 local name 匹配,
// 因此兼容 4A 的非标 namespace(http://4a.pab.com.cn/cas)、无前缀及任意其他前缀
type casServiceResponse struct {
	AuthenticationSuccess *casAuthenticationSuccess `xml:"authenticationSuccess"`
	AuthenticationFailure *struct {
		Code string `xml:"code,attr"`
	} `xml:"authenticationFailure"`
}

// casAuthenticationSuccess 的 attributes 子元素属性名可配置,用 xml.Name 捕获
// 每个子元素的 local name 后收集为 map
type casAuthenticationSuccess struct {
	User       string      `xml:"user"`
	Attributes casXMLAttrs `xml:"attributes"`
}

type casXMLAttrs struct {
	Attrs []casXMLAttr `xml:",any"`
}

type casXMLAttr struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (s *casAuthenticationSuccess) attrMap() map[string]string {
	m := make(map[string]string, len(s.Attributes.Attrs))
	for _, a := range s.Attributes.Attrs {
		m[a.XMLName.Local] = a.Value
	}
	return m
}

// normalizeOrgRole 大小写不敏感归一化角色;无效值返回空串(走默认角色)
func normalizeOrgRole(v string) org.RoleType {
	switch {
	case strings.EqualFold(v, string(org.RoleViewer)):
		return org.RoleViewer
	case strings.EqualFold(v, string(org.RoleEditor)):
		return org.RoleEditor
	case strings.EqualFold(v, string(org.RoleAdmin)):
		return org.RoleAdmin
	}
	return ""
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

func truncateForLog(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
