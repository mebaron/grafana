package setting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadCASSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte(`
[auth.cas]
enabled = false
`))
		require.NoError(t, err)

		assert.False(t, cfg.CAS.Enabled)
		assert.Empty(t, cfg.CAS.AppID)
		assert.Empty(t, cfg.CAS.ServerURL)
		assert.True(t, cfg.CAS.AllowSignUp)
		assert.False(t, cfg.CAS.TLSSkipVerify)
		assert.Empty(t, cfg.CAS.TLSCACert)
		assert.Equal(t, 10*time.Second, cfg.CAS.Timeout)
		assert.Equal(t, 3*time.Second, cfg.CAS.HealthCheckTimeout)
		assert.Empty(t, cfg.CAS.SignoutRedirectURL)
	})

	t.Run("parses all keys and trims trailing slash from server_url", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte(`
[auth.cas]
enabled = true
app_id = grafana
server_url = https://4a.example.com.cn///
allow_sign_up = false
signout_redirect_url = https://4a.example.com.cn/custom-logout
timeout = 30s
healthcheck_timeout = 1s
tls_client_ca = /path/to/ca.pem
tls_skip_verify_insecure = true
`))
		require.NoError(t, err)

		assert.True(t, cfg.CAS.Enabled)
		assert.Equal(t, "grafana", cfg.CAS.AppID)
		assert.Equal(t, "https://4a.example.com.cn", cfg.CAS.ServerURL)
		assert.False(t, cfg.CAS.AllowSignUp)
		assert.Equal(t, "https://4a.example.com.cn/custom-logout", cfg.CAS.SignoutRedirectURL)
		assert.Equal(t, 30*time.Second, cfg.CAS.Timeout)
		assert.Equal(t, time.Second, cfg.CAS.HealthCheckTimeout)
		assert.Equal(t, "/path/to/ca.pem", cfg.CAS.TLSCACert)
		assert.True(t, cfg.CAS.TLSSkipVerify)
	})

	t.Run("does not touch DisableLoginForm for either mode", func(t *testing.T) {
		// 降级依赖原生登录表单可用,任何 CAS 配置态都不应隐藏表单
		cfg, err := NewCfgFromBytes([]byte(`
[auth.cas]
enabled = true
`))
		require.NoError(t, err)
		assert.False(t, cfg.DisableLoginForm)
	})
}
