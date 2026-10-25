package clients

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/setting"
)

const casTestAppID = "grafana"

// cas.md 样例:4A 使用非标 namespace(http://4a.pab.com.cn/cas)
const casValidXMLNonstandardNS = `<cas:serviceResponse xmlns:cas="http://4a.pab.com.cn/cas">
	<cas:authenticationSuccess>
    	<cas:user>test543</cas:user>
        <cas:attributes>
        	<cas:cn>张三</cas:cn>
            <cas:name>test543</cas:name>
            <cas:email>test543@pingan.com.cn</cas:email>
        </cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>`

const casValidXMLNoPrefix = `<serviceResponse>
	<authenticationSuccess>
    	<user>test543</user>
        <attributes>
        	<cn>张三</cn>
            <name>test543</name>
            <cas:email xmlns:cas="http://4a.pab.com.cn/cas">test543@pingan.com.cn</cas:email>
        </attributes>
    </authenticationSuccess>
</serviceResponse>`

const casValidXMLOtherPrefix = `<foo:serviceResponse xmlns:foo="http://www.yale.edu/tp/cas">
	<foo:authenticationSuccess>
    	<foo:user>test543</foo:user>
        <foo:attributes>
        	<foo:cn>张三</foo:cn>
            <foo:name>test543</foo:name>
            <foo:email>test543@pingan.com.cn</foo:email>
        </foo:attributes>
    </foo:authenticationSuccess>
</foo:serviceResponse>`

const casFailureXML = `<cas:serviceResponse xmlns:cas="http://4a.pab.com.cn/cas">
	<cas:authenticationFailure code="INVALID_TICKET">Session not found</cas:authenticationFailure>
</cas:serviceResponse>`

func newCASTestCfg(serverURL string) *setting.Cfg {
	cfg := setting.NewCfg()
	cfg.AppURL = "http://localhost:3000/"
	cfg.CAS = setting.CASSettings{
		Enabled:            true,
		AppID:              casTestAppID,
		ServerURL:          serverURL,
		AllowSignUp:        true,
		Timeout:            5 * time.Second,
		HealthCheckTimeout: time.Second,
	}
	return cfg
}

func newCASAuthRequest(t *testing.T, cfg *setting.Cfg, query url.Values) *authn.Request {
	t.Helper()
	req := &http.Request{Header: map[string][]string{}, Host: "localhost"}
	var err error
	req.URL, err = url.Parse("http://localhost:3000/login/cas?" + query.Encode())
	require.NoError(t, err)

	// 模拟 OAuthLogin 在发起分支写入的 oauth_state cookie
	state, mac, err := genCASState(cfg.SecretKey, cfg.CAS.AppID)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: casStateCookieName, Value: state + casStateSeparator + mac})
	return &authn.Request{HTTPRequest: req}
}

func TestCAS_RedirectURL(t *testing.T) {
	newClient := func(cfg *setting.Cfg) *CAS {
		c, err := ProvideCAS(cfg)
		require.NoError(t, err)
		return c
	}

	t.Run("should return error when client is disabled", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		cfg.CAS.Enabled = false
		_, err := newClient(cfg).RedirectURL(context.Background(), &authn.Request{})
		assert.ErrorIs(t, err, errCASDisabled)
	})

	t.Run("should build 4A login URL and a verifiable state cookie value", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		redirect, err := newClient(cfg).RedirectURL(context.Background(), &authn.Request{})
		require.NoError(t, err)

		u, err := url.Parse(redirect.URL)
		require.NoError(t, err)
		assert.Equal(t, "/4a/credentials/cas", u.Path)
		assert.Equal(t, casTestAppID, u.Query().Get("appid"))
		// service 是 4A 侧精确匹配的静态回调地址,AppURL 的尾斜杠需裁剪
		assert.Equal(t, "http://localhost:3000/login/cas", u.Query().Get("service"))

		cookieValue := redirect.Extra[authn.KeyOAuthState]
		state, mac, ok := strings.Cut(cookieValue, casStateSeparator)
		require.True(t, ok)
		expectedMAC := hex.EncodeToString(hmacCASState(state, cfg.SecretKey, cfg.CAS.AppID))
		assert.Equal(t, expectedMAC, mac)
		assert.True(t, verifyCASState(cookieValue, cfg.SecretKey, cfg.CAS.AppID))
	})

	t.Run("should keep subpath of root_url in service url", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		cfg.AppURL = "http://localhost:3000/grafana/"
		redirect, err := newClient(cfg).RedirectURL(context.Background(), &authn.Request{})
		require.NoError(t, err)

		u, err := url.Parse(redirect.URL)
		require.NoError(t, err)
		assert.Equal(t, "http://localhost:3000/grafana/login/cas", u.Query().Get("service"))
	})
}

func TestCAS_Authenticate(t *testing.T) {
	type testCase struct {
		desc string

		status int
		body   string

		disableClient   bool
		omitStateCookie bool
		tamperState     bool
		omitTicket      bool
		clientTimeout   time.Duration

		expectedErr      error
		expectedIdentity *authn.Identity
	}

	tests := []testCase{
		{
			desc:          "should return error when client is disabled",
			disableClient: true,
			expectedErr:   errCASDisabled,
		},
		{
			desc:            "should return error when state cookie is missing",
			omitStateCookie: true,
			expectedErr:     errCASMissingState,
		},
		{
			desc:        "should return error when state cookie mac does not verify",
			tamperState: true,
			expectedErr: errCASInvalidState,
		},
		{
			desc:        "should return error when ticket is missing",
			omitTicket:  true,
			expectedErr: errCASTicketMissing,
		},
		{
			desc: "should parse cas.md sample xml with non-standard namespace",
			body: casValidXMLNonstandardNS, status: http.StatusOK,
			expectedIdentity: &authn.Identity{
				Login: "test543", Name: "张三", Email: "test543@pingan.com.cn",
				AuthID: "test543", AuthenticatedBy: login.CASAuthModule,
			},
		},
		{
			desc: "should parse xml without namespace prefix",
			body: casValidXMLNoPrefix, status: http.StatusOK,
			expectedIdentity: &authn.Identity{
				Login: "test543", Name: "张三", Email: "test543@pingan.com.cn",
				AuthID: "test543", AuthenticatedBy: login.CASAuthModule,
			},
		},
		{
			desc: "should parse xml with an arbitrary prefix",
			body: casValidXMLOtherPrefix, status: http.StatusOK,
			expectedIdentity: &authn.Identity{
				Login: "test543", Name: "张三", Email: "test543@pingan.com.cn",
				AuthID: "test543", AuthenticatedBy: login.CASAuthModule,
			},
		},
		{
			desc: "should reject authenticationFailure xml",
			body: casFailureXML, status: http.StatusOK,
			expectedErr: errCASTicketInvalid,
		},
		{
			desc: "should reject 401 plain-text error",
			body: "Session not found, ticket：123456", status: http.StatusUnauthorized,
			expectedErr: errCASTicketInvalid,
		},
		{
			desc: "should return internal error on unexpected status",
			body: "bad gateway", status: http.StatusBadGateway,
			expectedErr: errCASInternal,
		},
		{
			desc:          "should return internal error on timeout",
			clientTimeout: 100 * time.Millisecond,
			expectedErr:   errCASInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			handlerCalled := false
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				assert.Equal(t, "/4a/cas/serviceValidate", r.URL.Path)
				assert.Equal(t, casTestAppID, r.URL.Query().Get("appid"))

				if tt.clientTimeout > 0 {
					time.Sleep(2 * tt.clientTimeout)
					return
				}
				if tt.body != "" || tt.status != 0 {
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(casValidXMLNonstandardNS))
			}))
			defer ts.Close()

			cfg := newCASTestCfg(ts.URL)
			if tt.disableClient {
				cfg.CAS.Enabled = false
			}
			if tt.clientTimeout > 0 {
				cfg.CAS.Timeout = tt.clientTimeout
			}

			c, err := ProvideCAS(cfg)
			require.NoError(t, err)

			query := url.Values{}
			if !tt.omitTicket {
				query.Set("ticket", "ST-mock-123")
			}
			req := newCASAuthRequest(t, cfg, query)
			if tt.omitStateCookie {
				req.HTTPRequest.Header.Del("Cookie")
			}
			if tt.tamperState {
				// http.Request.Cookie 返回解析副本,必须改写原始 Cookie header 才真正生效
				_, mac, ok := strings.Cut(req.HTTPRequest.Header.Get("Cookie"), casStateSeparator)
				require.True(t, ok)
				req.HTTPRequest.Header.Set("Cookie", fmt.Sprintf("%s=tampered-state%s%s", casStateCookieName, casStateSeparator, mac))
			}

			identity, err := c.Authenticate(context.Background(), req)
			assert.ErrorIs(t, err, tt.expectedErr)
			if tt.expectedErr != nil {
				assert.Nil(t, identity)
			}
			if tt.expectedIdentity != nil {
				require.NotNil(t, identity)
				assert.Equal(t, tt.expectedIdentity.Login, identity.Login)
				assert.Equal(t, tt.expectedIdentity.Name, identity.Name)
				assert.Equal(t, tt.expectedIdentity.Email, identity.Email)
				assert.Equal(t, tt.expectedIdentity.AuthID, identity.AuthID)
				assert.Equal(t, tt.expectedIdentity.AuthenticatedBy, identity.AuthenticatedBy)
				assert.True(t, identity.ClientParams.SyncUser)
				assert.True(t, identity.ClientParams.AllowSignUp)
				assert.True(t, identity.ClientParams.FetchSyncedUser)
				assert.True(t, identity.ClientParams.SyncPermissions)
			}
			if tt.desc == "should return error when ticket is missing" {
				assert.False(t, handlerCalled, "4A must not be called without a ticket")
			}
		})
	}
}

func TestCAS_Authenticate401DoesNotLeakBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Session not found, ticket：SECRET-DETAIL"))
	}))
	defer ts.Close()

	cfg := newCASTestCfg(ts.URL)
	c, err := ProvideCAS(cfg)
	require.NoError(t, err)

	_, err = c.Authenticate(context.Background(), newCASAuthRequest(t, cfg, url.Values{"ticket": {"ST-x"}}))
	require.ErrorIs(t, err, errCASTicketInvalid)
	assert.NotContains(t, err.Error(), "SECRET-DETAIL")
}

func TestCAS_Logout(t *testing.T) {
	newClient := func(cfg *setting.Cfg) *CAS {
		c, err := ProvideCAS(cfg)
		require.NoError(t, err)
		return c
	}

	t.Run("disabled client should not redirect", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		cfg.CAS.Enabled = false
		redirect, ok := newClient(cfg).Logout(context.Background(), nil, nil)
		assert.False(t, ok)
		assert.Nil(t, redirect)
	})

	t.Run("should redirect to default 4A logout url", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		redirect, ok := newClient(cfg).Logout(context.Background(), nil, nil)
		require.True(t, ok)
		require.NotNil(t, redirect)

		u, err := url.Parse(redirect.URL)
		require.NoError(t, err)
		assert.Equal(t, "/4a/cas/logout", u.Path)
		assert.Equal(t, casTestAppID, u.Query().Get("appid"))
		assert.Equal(t, "http://localhost:3000/login", u.Query().Get("url"))
	})

	t.Run("should prefer configured signout redirect url", func(t *testing.T) {
		cfg := newCASTestCfg("http://4a.example.com.cn")
		cfg.CAS.SignoutRedirectURL = "https://4a.example.com.cn/custom-logout"
		redirect, ok := newClient(cfg).Logout(context.Background(), nil, nil)
		require.True(t, ok)
		assert.Equal(t, "https://4a.example.com.cn/custom-logout", redirect.URL)
	})
}

func TestCAS_Interfaces(t *testing.T) {
	c, err := ProvideCAS(newCASTestCfg("http://4a.example.com.cn"))
	require.NoError(t, err)

	var (
		_ authn.Client         = c
		_ authn.RedirectClient = c
		_ authn.LogoutClient   = c
	)
	assert.Equal(t, authn.ClientCAS, c.Name())
	assert.True(t, c.IsEnabled())
}

func TestVerifyCASState(t *testing.T) {
	state, mac, err := genCASState("secret", "seed")
	require.NoError(t, err)
	value := fmt.Sprintf("%s%s%s", state, casStateSeparator, mac)

	assert.True(t, verifyCASState(value, "secret", "seed"))
	assert.False(t, verifyCASState(value, "other-secret", "seed"), "HMAC must bind SecretKey")
	assert.False(t, verifyCASState(value, "secret", "other-seed"), "HMAC must bind AppID")
	assert.False(t, verifyCASState("no-separator", "secret", "seed"))
	assert.False(t, verifyCASState(".abcdef", "secret", "seed"))
	assert.False(t, verifyCASState("state.not-hex!", "secret", "seed"))
}
