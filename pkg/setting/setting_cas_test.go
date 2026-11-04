package setting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const casTestINI = `
[auth.cas]
enabled = true
app_id = grafana
login_url = https://4a.example.com/4a/credentials/cas/
service_validate_url = https://4a.example.com/4a/cas/serviceValidate/
logout_url = https://4a.example.com/4a/cas/logout/
service = https://grafana.example.com/sso/callback
url = https://grafana.example.com/login
email_attribute = email
name_attribute = cn
role_attribute = role
allow_sign_up = false
timeout = 30s
tls_skip_verify_insecure = true
tls_client_ca = /etc/grafana/ca.pem
`

func TestReadCASSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte("[auth.cas]\n"))
		require.NoError(t, err)

		require.False(t, cfg.CAS.Enabled)
		require.True(t, cfg.CAS.AllowSignUp)
		require.Equal(t, 10*time.Second, cfg.CAS.Timeout)
		require.False(t, cfg.CAS.TLSSkipVerify)
		require.Empty(t, cfg.CAS.AppID)
		require.Empty(t, cfg.CAS.LoginURL)
		require.Empty(t, cfg.CAS.ServiceValidateURL)
		require.Empty(t, cfg.CAS.LogoutURL)
		require.Empty(t, cfg.CAS.Service)
		require.Empty(t, cfg.CAS.URL)
		require.Empty(t, cfg.CAS.EmailAttribute)
		require.Empty(t, cfg.CAS.NameAttribute)
		require.Empty(t, cfg.CAS.RoleAttribute)
		require.Empty(t, cfg.CAS.TLSCACert)
	})

	t.Run("parses all keys and trims endpoint URLs", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte(casTestINI))
		require.NoError(t, err)

		require.True(t, cfg.CAS.Enabled)
		require.Equal(t, "grafana", cfg.CAS.AppID)
		require.Equal(t, "https://4a.example.com/4a/credentials/cas", cfg.CAS.LoginURL)
		require.Equal(t, "https://4a.example.com/4a/cas/serviceValidate", cfg.CAS.ServiceValidateURL)
		require.Equal(t, "https://4a.example.com/4a/cas/logout", cfg.CAS.LogoutURL)
		require.Equal(t, "https://grafana.example.com/sso/callback", cfg.CAS.Service)
		require.Equal(t, "https://grafana.example.com/login", cfg.CAS.URL)
		require.Equal(t, "email", cfg.CAS.EmailAttribute)
		require.Equal(t, "cn", cfg.CAS.NameAttribute)
		require.Equal(t, "role", cfg.CAS.RoleAttribute)
		require.False(t, cfg.CAS.AllowSignUp)
		require.Equal(t, 30*time.Second, cfg.CAS.Timeout)
		require.True(t, cfg.CAS.TLSSkipVerify)
		require.Equal(t, "/etc/grafana/ca.pem", cfg.CAS.TLSCACert)
	})

	t.Run("service is preserved verbatim for exact 4A matching", func(t *testing.T) {
		// 4A 按 appId 对 service 精确匹配,注册值是什么就上送什么,不做 trim
		cfg, err := NewCfgFromBytes([]byte("[auth.cas]\nservice = https://g.example.com/sso/callback/\n"))
		require.NoError(t, err)

		require.Equal(t, "https://g.example.com/sso/callback/", cfg.CAS.Service)
	})

	t.Run("environment variables override declared keys", func(t *testing.T) {
		// defaults.ini 中 [auth.cas] 的键必须显式声明,GF_AUTH_CAS_* 环境变量覆盖才会生效
		t.Setenv("GF_AUTH_CAS_APP_ID", "env-app")
		t.Setenv("GF_AUTH_CAS_ENABLED", "true")

		cfg := NewCfg()
		err := cfg.Load(CommandLineArgs{HomePath: "../../"})
		require.NoError(t, err)

		require.Equal(t, "env-app", cfg.CAS.AppID)
		require.True(t, cfg.CAS.Enabled)
	})
}
