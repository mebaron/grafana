package setting

import (
	"strings"
	"time"
)

// CASSettings configures authentication against an external CAS provider
// (企业 4A 统一认证). See docs/sources/setup-grafana/configure-security/configure-authentication/cas/.
type CASSettings struct {
	Enabled     bool
	AppID       string // 4A 分配给 Grafana 的 appId
	ServerURL   string // 4A 基地址, 如 https://4a.example.com.cn (不含尾斜杠)
	AllowSignUp bool   // 4A 用户首次登录是否自动创建 Grafana 用户

	// SignoutRedirectURL 非空时覆盖默认的 4A 登出地址
	SignoutRedirectURL string

	// Timeout 是 serviceValidate 请求的超时
	Timeout time.Duration
	// HealthCheckTimeout 是 4A 可达性探测的超时;探测失败(超时/网络错/5xx)
	// 时 auto-login 降级为渲染原生登录页,见 pkg/api/login.go tryAutoLogin
	HealthCheckTimeout time.Duration

	TLSSkipVerify bool
	TLSCACert     string
}

func (cfg *Cfg) readCASSettings() {
	section := cfg.Raw.Section("auth.cas")
	s := CASSettings{}
	s.Enabled = section.Key("enabled").MustBool(false)
	s.AppID = valueAsString(section, "app_id", "")
	s.ServerURL = strings.TrimRight(valueAsString(section, "server_url", ""), "/")
	s.AllowSignUp = section.Key("allow_sign_up").MustBool(true)
	s.SignoutRedirectURL = valueAsString(section, "signout_redirect_url", "")
	s.Timeout = section.Key("timeout").MustDuration(10 * time.Second)
	s.HealthCheckTimeout = section.Key("healthcheck_timeout").MustDuration(3 * time.Second)
	s.TLSSkipVerify = section.Key("tls_skip_verify_insecure").MustBool(false)
	s.TLSCACert = valueAsString(section, "tls_client_ca", "")
	cfg.CAS = s
}
