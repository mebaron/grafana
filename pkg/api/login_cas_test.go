package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/models/usertoken"
	authtest "github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/cas"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const casSuccessXML = `<cas:serviceResponse xmlns:cas="http://4a.pab.com.cn/cas">` +
	`<cas:authenticationSuccess><cas:user>test543</cas:user>` +
	`<cas:attributes><cas:cn>张三</cas:cn><cas:email>test543@pingan.com.cn</cas:email></cas:attributes>` +
	`</cas:authenticationSuccess></cas:serviceResponse>`

func newCASHTTPCfg(enabled bool) *setting.Cfg {
	cfg := setting.NewCfg()
	cfg.SecretKey = "test-secret"
	// NewCfg 不带 ini 默认值;空 cookie 名会被 http.SetCookie 静默丢弃
	cfg.LoginCookieName = "grafana_session"
	cfg.CAS = setting.CASSettings{
		Enabled:            enabled,
		AppID:              "grafana",
		LoginURL:           "https://4a.example.com/4a/credentials/cas",
		ServiceValidateURL: "https://4a.example.com/4a/cas/serviceValidate",
		LogoutURL:          "https://4a.example.com/4a/cas/logout",
		Service:            "https://grafana.example.com/sso/callback",
		EmailAttribute:     "email",
		NameAttribute:      "cn",
		RoleAttribute:      "role",
		AllowSignUp:        true,
		Timeout:            5 * time.Second,
	}
	return cfg
}

// setupCASAPITestServer 构造挂载真实 cas.Service 的路由级测试服务,
// 4A serviceValidate 端点由 validateSrv 桩替身
func setupCASAPITestServer(t *testing.T, cfg *setting.Cfg, validateSrv *httptest.Server,
	authInfo *authinfotest.FakeService, usr *usertest.FakeUserService,
) *webtest.Server {
	t.Helper()
	if validateSrv != nil {
		cfg.CAS.ServiceValidateURL = validateSrv.URL
	}
	casSvc, err := cas.ProvideService(cfg, authInfo, usr, &orgtest.FakeOrgService{}, quotatest.New(false, nil))
	require.NoError(t, err)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.NewNopLogger()
		hs.SecretsService = fakes.NewFakeSecretsService()
		hs.AuthTokenService = authtest.NewFakeUserAuthTokenService()
		hs.casService = casSvc
	})
	setClientWithoutRedirectFollow(t, server)
	return server
}

func newCAS4AServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func newValidCASStateCookie(t *testing.T, cfg *setting.Cfg) *http.Cookie {
	t.Helper()
	state, mac, err := genCASState(cfg.SecretKey, cfg.CAS.AppID)
	require.NoError(t, err)
	return &http.Cookie{Name: casStateCookieName, Value: state + casStateSeparator + mac}
}

func cookieByName(t *testing.T, res *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// newExistingCASUserFakes 返回命中既有用户路径的 fakes(user_auth 连接存在)
func newExistingCASUserFakes() (*authinfotest.FakeService, *usertest.FakeUserService) {
	authInfo := &authinfotest.FakeService{
		ExpectedUserAuth: &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"},
	}
	usr := usertest.NewUserServiceFake()
	usr.ExpectedUser = &user.User{ID: 7, Login: "test543", Email: "test543@pingan.com.cn", Name: "张三", OrgID: 1}
	return authInfo, usr
}

func TestCASLogin_Redirect(t *testing.T) {
	t.Run("redirects to 4A with state cookie", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/login"))
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t,
			"https://4a.example.com/4a/credentials/cas?appId=grafana&service=https%3A%2F%2Fgrafana.example.com%2Fsso%2Fcallback",
			res.Header.Get("Location"))

		stateCookie := cookieByName(t, res, casStateCookieName)
		require.NotNil(t, stateCookie, "cas_state cookie should be set")
		assert.Contains(t, stateCookie.Value, casStateSeparator)
		require.NoError(t, res.Body.Close())
	})

	t.Run("persists valid redirectTo as redirect_to cookie", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/login?redirectTo=%2Fd%2Ftest"))
		require.NoError(t, err)

		redirectCookie := cookieByName(t, res, "redirect_to")
		require.NotNil(t, redirectCookie, "redirect_to cookie should be set for valid redirectTo")
		assert.Equal(t, "/d/test", redirectCookie.Value)
		require.NoError(t, res.Body.Close())
	})

	t.Run("re-prefixes AppSubURL before validating redirectTo", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		cfg.AppSubURL = "/grafana"
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/login?redirectTo=%2Fd%2Ftest"))
		require.NoError(t, err)

		redirectCookie := cookieByName(t, res, "redirect_to")
		require.NotNil(t, redirectCookie)
		assert.Equal(t, "/grafana/d/test", redirectCookie.Value)
		require.NoError(t, res.Body.Close())
	})

	t.Run("does not persist invalid redirectTo", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/login?redirectTo=%2F%2Fevil.example.com"))
		require.NoError(t, err)

		assert.Nil(t, cookieByName(t, res, "redirect_to"))
		require.NoError(t, res.Body.Close())
	})

	t.Run("redirects to /login when disabled", func(t *testing.T) {
		cfg := newCASHTTPCfg(false)
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/login"))
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.Nil(t, cookieByName(t, res, casStateCookieName))
		require.NoError(t, res.Body.Close())
	})
}

func TestCASCallback(t *testing.T) {
	t.Run("creates session and redirects to root on success", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		validateSrv := newCAS4AServer(t, http.StatusOK, casSuccessXML)
		defer validateSrv.Close()
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		req := server.NewGetRequest("/sso/callback?ticket=ticket-1")
		req.AddCookie(newValidCASStateCookie(t, cfg))
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/", res.Header.Get("Location"))

		// state cookie 始终被删除
		deleted := cookieByName(t, res, casStateCookieName)
		require.NotNil(t, deleted)
		assert.Equal(t, "", deleted.Value)
		assert.Equal(t, -1, deleted.MaxAge)

		// 原生会话 cookie
		assert.NotNil(t, cookieByName(t, res, cfg.LoginCookieName))
		assert.NotNil(t, cookieByName(t, res, "grafana_session_expiry"))
		require.NoError(t, res.Body.Close())
	})

	t.Run("honors stashed redirect_to cookie", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		validateSrv := newCAS4AServer(t, http.StatusOK, casSuccessXML)
		defer validateSrv.Close()
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		req := server.NewGetRequest("/sso/callback?ticket=ticket-1")
		req.AddCookie(newValidCASStateCookie(t, cfg))
		req.AddCookie(&http.Cookie{Name: "redirect_to", Value: "/d/test"})
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/d/test", res.Header.Get("Location"))
		require.NoError(t, res.Body.Close())
	})

	t.Run("rejects missing state cookie", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		validateSrv := newCAS4AServer(t, http.StatusOK, casSuccessXML)
		defer validateSrv.Close()
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		res, err := server.Send(server.NewGetRequest("/sso/callback?ticket=ticket-1"))
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.NotNil(t, cookieByName(t, res, loginErrorCookieName))
		assert.Nil(t, cookieByName(t, res, cfg.LoginCookieName))
		require.NoError(t, res.Body.Close())
	})

	t.Run("rejects tampered state cookie", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		validateSrv := newCAS4AServer(t, http.StatusOK, casSuccessXML)
		defer validateSrv.Close()
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		req := server.NewGetRequest("/sso/callback?ticket=ticket-1")
		req.AddCookie(&http.Cookie{Name: casStateCookieName, Value: "state.deadbeef"})
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.NotNil(t, cookieByName(t, res, loginErrorCookieName))
		require.NoError(t, res.Body.Close())
	})

	t.Run("rejects empty ticket", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, nil, authInfo, usr)

		req := server.NewGetRequest("/sso/callback")
		req.AddCookie(newValidCASStateCookie(t, cfg))
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.NotNil(t, cookieByName(t, res, loginErrorCookieName))
		require.NoError(t, res.Body.Close())
	})

	t.Run("rejects invalid ticket from 4A", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		validateSrv := newCAS4AServer(t, http.StatusUnauthorized, "Session not found, ticket: ticket-1")
		defer validateSrv.Close()
		authInfo, usr := newExistingCASUserFakes()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		req := server.NewGetRequest("/sso/callback?ticket=ticket-1")
		req.AddCookie(newValidCASStateCookie(t, cfg))
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.NotNil(t, cookieByName(t, res, loginErrorCookieName))
		require.NoError(t, res.Body.Close())
	})

	t.Run("rejects unknown user when signup is disabled", func(t *testing.T) {
		cfg := newCASHTTPCfg(true)
		cfg.CAS.AllowSignUp = false
		validateSrv := newCAS4AServer(t, http.StatusOK, casSuccessXML)
		defer validateSrv.Close()
		authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
		usr := usertest.NewUserServiceFake()
		server := setupCASAPITestServer(t, cfg, validateSrv, authInfo, usr)

		req := server.NewGetRequest("/sso/callback?ticket=ticket-1")
		req.AddCookie(newValidCASStateCookie(t, cfg))
		res, err := server.Send(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, res.StatusCode)
		assert.Equal(t, "/login", res.Header.Get("Location"))
		assert.NotNil(t, cookieByName(t, res, loginErrorCookieName))
		require.NoError(t, res.Body.Close())
	})
}

// casLogoutAuthnFake 覆写 FakeService 的 Logout(基类直接 panic)
type casLogoutAuthnFake struct {
	authntest.FakeService
}

func (f *casLogoutAuthnFake) Logout(_ context.Context, _ identity.Requester, _ *usertoken.UserToken) (*authn.Redirect, error) {
	return &authn.Redirect{URL: "/login"}, nil
}

func TestLoginViewCASAutoRedirect(t *testing.T) {
	newHandler := func(sc *scenarioContext, hs *HTTPServer) {
		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			hs.LoginView(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()
	}

	t.Run("redirects to /sso/login when CAS is enabled", func(t *testing.T) {
		fakeSetIndexViewData(t)
		sc := setupScenarioContext(t, "/login")
		sc.cfg.CAS.Enabled = true
		hs := &HTTPServer{
			authnService:     &authntest.FakeService{},
			Cfg:              sc.cfg,
			SettingsProvider: &setting.OSSImpl{Cfg: sc.cfg},
			License:          &licensing.OSSLicensingService{},
			SocialService:    &mockSocialService{},
			Features:         featuremgmt.WithFeatures(),
			log:              log.NewNopLogger(),
		}

		newHandler(sc, hs)

		require.Equal(t, http.StatusTemporaryRedirect, sc.resp.Code)
		location, ok := sc.resp.Header()["Location"]
		assert.True(t, ok)
		assert.Equal(t, "/sso/login", location[0])
	})

	t.Run("forwards redirectTo behind redirection feature flag", func(t *testing.T) {
		fakeSetIndexViewData(t)
		sc := setupScenarioContext(t, "/login")
		sc.cfg.CAS.Enabled = true
		hs := &HTTPServer{
			authnService:     &authntest.FakeService{},
			Cfg:              sc.cfg,
			SettingsProvider: &setting.OSSImpl{Cfg: sc.cfg},
			License:          &licensing.OSSLicensingService{},
			SocialService:    &mockSocialService{},
			Features:         featuremgmt.WithFeatures(featuremgmt.FlagUseSessionStorageForRedirection),
			log:              log.NewNopLogger(),
		}

		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.Req.URL.RawQuery = "redirectTo=/d/test"
			hs.LoginView(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()

		require.Equal(t, http.StatusTemporaryRedirect, sc.resp.Code)
		location, ok := sc.resp.Header()["Location"]
		assert.True(t, ok)
		assert.Equal(t, "/sso/login?redirectTo=%2Fd%2Ftest", location[0])
	})

	t.Run("renders login page when another auto-login provider is configured", func(t *testing.T) {
		fakeSetIndexViewData(t)
		fakeViewIndex(t)
		sc := setupScenarioContext(t, "/login")
		sc.cfg.CAS.Enabled = true
		hs := &HTTPServer{
			authnService:     &authntest.FakeService{},
			Cfg:              sc.cfg,
			SettingsProvider: &setting.OSSImpl{Cfg: sc.cfg},
			License:          &licensing.OSSLicensingService{},
			SocialService: &mockSocialService{
				oAuthInfos: map[string]*social.OAuthInfo{
					"github": {Name: "github", AutoLogin: true},
				},
			},
			Features: featuremgmt.WithFeatures(),
			log:      log.NewNopLogger(),
		}

		newHandler(sc, hs)

		// 多个 auto-login provider 并存时守卫生效:跳过跳转渲染原生登录页
		assert.Equal(t, http.StatusOK, sc.resp.Code)
	})

	t.Run("renders login page when CAS is disabled", func(t *testing.T) {
		fakeSetIndexViewData(t)
		fakeViewIndex(t)
		sc := setupScenarioContext(t, "/login")
		hs := &HTTPServer{
			authnService:     &authntest.FakeService{},
			Cfg:              sc.cfg,
			SettingsProvider: &setting.OSSImpl{Cfg: sc.cfg},
			License:          &licensing.OSSLicensingService{},
			SocialService:    &mockSocialService{},
			Features:         featuremgmt.WithFeatures(),
			log:              log.NewNopLogger(),
		}

		newHandler(sc, hs)

		assert.Equal(t, http.StatusOK, sc.resp.Code)
	})
}

func TestLogoutCAS(t *testing.T) {
	setup := func(t *testing.T) (*scenarioContext, *HTTPServer) {
		t.Helper()
		sc := setupScenarioContext(t, "/logout")
		sc.cfg.CAS.Enabled = true
		sc.cfg.CAS.AppID = "grafana"
		sc.cfg.CAS.LogoutURL = "https://4a.example.com/4a/cas/logout"
		sc.cfg.LoginCookieName = "grafana_session"
		casSvc, err := cas.ProvideService(sc.cfg, &authinfotest.FakeService{},
			usertest.NewUserServiceFake(), &orgtest.FakeOrgService{}, quotatest.New(false, nil))
		require.NoError(t, err)
		hs := &HTTPServer{
			authnService: &casLogoutAuthnFake{},
			Cfg:          sc.cfg,
			casService:   casSvc,
			log:          log.NewNopLogger(),
		}
		return sc, hs
	}

	t.Run("redirects cas user to 4A logout with configured url", func(t *testing.T) {
		sc, hs := setup(t)
		sc.cfg.CAS.URL = "https://grafana.example.com/portal"

		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.SignedInUser = &user.SignedInUser{UserID: 1, AuthenticatedBy: login.CASAuthModule}
			hs.Logout(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()

		require.Equal(t, http.StatusFound, sc.resp.Code)
		assert.Equal(t,
			"https://4a.example.com/4a/cas/logout?appId=grafana&url=https%3A%2F%2Fgrafana.example.com%2Fportal",
			sc.resp.Header().Get("Location"))
	})

	t.Run("falls back to AppURL/login as logout target", func(t *testing.T) {
		sc, hs := setup(t)
		sc.cfg.AppURL = "https://grafana.example.com/"

		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.SignedInUser = &user.SignedInUser{UserID: 1, AuthenticatedBy: login.CASAuthModule}
			hs.Logout(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()

		require.Equal(t, http.StatusFound, sc.resp.Code)
		assert.Equal(t,
			"https://4a.example.com/4a/cas/logout?appId=grafana&url=https%3A%2F%2Fgrafana.example.com%2Flogin",
			sc.resp.Header().Get("Location"))
	})

	t.Run("non-cas user gets normal logout redirect", func(t *testing.T) {
		sc, hs := setup(t)

		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.SignedInUser = &user.SignedInUser{UserID: 1, AuthenticatedBy: login.PasswordAuthModule}
			hs.Logout(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()

		require.Equal(t, http.StatusFound, sc.resp.Code)
		assert.Equal(t, "/login", sc.resp.Header().Get("Location"))
	})

	t.Run("cas user without logout_url gets normal redirect", func(t *testing.T) {
		sc, hs := setup(t)
		sc.cfg.CAS.LogoutURL = ""

		sc.defaultHandler = routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.SignedInUser = &user.SignedInUser{UserID: 1, AuthenticatedBy: login.CASAuthModule}
			hs.Logout(c)
			return response.Empty(http.StatusOK)
		})
		sc.m.Get(sc.url, sc.defaultHandler)
		sc.fakeReqNoAssertions("GET", sc.url).exec()

		require.Equal(t, http.StatusFound, sc.resp.Code)
		assert.Equal(t, "/login", sc.resp.Header().Get("Location"))
	})
}

func TestCASProviderEnabledAndSynced(t *testing.T) {
	hs := &HTTPServer{}

	t.Run("isProviderEnabled follows cfg.CAS.Enabled", func(t *testing.T) {
		cfg := &setting.Cfg{}
		cfg.CAS.Enabled = true
		assert.True(t, hs.isProviderEnabled(cfg, login.CASAuthModule))

		cfg.CAS.Enabled = false
		assert.False(t, hs.isProviderEnabled(cfg, login.CASAuthModule))
	})

	t.Run("isExternallySynced only when role_attribute is configured", func(t *testing.T) {
		cfg := &setting.Cfg{}
		cfg.CAS.Enabled = true
		cfg.CAS.RoleAttribute = ""
		assert.False(t, hs.isExternallySynced(cfg, login.CASAuthModule))

		cfg.CAS.RoleAttribute = "role"
		assert.True(t, hs.isExternallySynced(cfg, login.CASAuthModule))
	})
}
