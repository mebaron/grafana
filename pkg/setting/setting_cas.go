package setting

import (
	"strings"
	"time"
)

// CASSettings 配置企业 4A 平台的 CAS 协议认证。
// 独立 handler 实现(/sso/login + /sso/callback),不注册 authn client。
// 见 docs/sources/setup-grafana/configure-security/configure-authentication/cas/
type CASSettings struct {
	Enabled bool
	// AppID 是 4A 分配给 Grafana 的 appId
	AppID string

	// 三个 4A 端点均为完整 URL,读取时去除尾斜杠;构造请求时兼容端点自带 query 的情况
	LoginURL           string // 登录跳转端点,如 https://4a.example.com/4a/credentials/cas
	ServiceValidateURL string // ticket 校验端点,如 https://4a.example.com/4a/cas/serviceValidate
	LogoutURL          string // 登出端点,如 https://4a.example.com/4a/cas/logout

	// Service 是 4A 侧按 appId 注册的回调地址。4A 精确匹配注册值,
	// 因此原样上送不做 trim,必须与 4A 侧登记值完全一致
	Service string
	// URL 是 4A 登出后跳回的应用地址;留空时回退 AppURL + /login
	URL string

	// 以下为 XML attributes 中各字段的属性名(local name),留空表示不映射该字段
	EmailAttribute string
	NameAttribute  string
	// RoleAttribute 取值 Viewer/Editor/Admin(大小写不敏感);
	// 无效或未配置时走 Grafana 默认组织角色
	RoleAttribute string

	AllowSignUp bool
	// Timeout 是 serviceValidate 请求的超时
	Timeout time.Duration

	TLSSkipVerify bool
	TLSCACert     string
}

func (cfg *Cfg) readCASSettings() {
	section := cfg.Raw.Section("auth.cas")
	s := CASSettings{}
	s.Enabled = section.Key("enabled").MustBool(false)
	s.AppID = valueAsString(section, "app_id", "")
	s.LoginURL = strings.TrimRight(valueAsString(section, "login_url", ""), "/")
	s.ServiceValidateURL = strings.TrimRight(valueAsString(section, "service_validate_url", ""), "/")
	s.LogoutURL = strings.TrimRight(valueAsString(section, "logout_url", ""), "/")
	s.Service = valueAsString(section, "service", "")
	s.URL = valueAsString(section, "url", "")
	s.EmailAttribute = valueAsString(section, "email_attribute", "")
	s.NameAttribute = valueAsString(section, "name_attribute", "")
	s.RoleAttribute = valueAsString(section, "role_attribute", "")
	s.AllowSignUp = section.Key("allow_sign_up").MustBool(true)
	s.Timeout = section.Key("timeout").MustDuration(10 * time.Second)
	s.TLSSkipVerify = section.Key("tls_skip_verify_insecure").MustBool(false)
	s.TLSCACert = valueAsString(section, "tls_client_ca", "")
	cfg.CAS = s
}
