package cas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

// recordingAuthInfo 在 authinfotest.FakeService 基础上记录写操作,
// 并支持按次切换 GetAuthInfo 结果(模拟并发首登的查询时序)
type recordingAuthInfo struct {
	authinfotest.FakeService
	getAuthInfoFn func(ctx context.Context, query *login.GetAuthInfoQuery) (*login.UserAuth, error)
	setCmd        *login.SetAuthInfoCommand
	updateCmd     *login.UpdateAuthInfoCommand
	deletedUserID int64
}

func (r *recordingAuthInfo) GetAuthInfo(ctx context.Context, query *login.GetAuthInfoQuery) (*login.UserAuth, error) {
	if r.getAuthInfoFn != nil {
		return r.getAuthInfoFn(ctx, query)
	}
	return r.FakeService.GetAuthInfo(ctx, query)
}

func (r *recordingAuthInfo) SetAuthInfo(_ context.Context, cmd *login.SetAuthInfoCommand) error {
	r.setCmd = cmd
	return nil
}

func (r *recordingAuthInfo) UpdateAuthInfo(_ context.Context, cmd *login.UpdateAuthInfoCommand) error {
	r.updateCmd = cmd
	return nil
}

func (r *recordingAuthInfo) DeleteUserAuthInfo(_ context.Context, userID int64) error {
	r.deletedUserID = userID
	return nil
}

// recordingOrg 记录 UpdateOrgUser 调用(FakeOrgService 无对应 Fn 钩子)
type recordingOrg struct {
	orgtest.FakeOrgService
	updateCmd *org.UpdateOrgUserCommand
}

func (r *recordingOrg) UpdateOrgUser(_ context.Context, cmd *org.UpdateOrgUserCommand) error {
	r.updateCmd = cmd
	return nil
}

func newCASCfg(validateURL string) *setting.Cfg {
	cfg := setting.NewCfg()
	cfg.CAS = setting.CASSettings{
		Enabled:            true,
		AppID:              "grafana",
		LoginURL:           "https://4a.example.com/4a/credentials/cas",
		ServiceValidateURL: validateURL,
		LogoutURL:          "https://4a.example.com/4a/cas/logout",
		Service:            "https://grafana.example.com/sso/callback",
		URL:                "https://grafana.example.com/login",
		EmailAttribute:     "email",
		NameAttribute:      "cn",
		RoleAttribute:      "role",
		AllowSignUp:        true,
		Timeout:            5 * time.Second,
	}
	return cfg
}

func newTestService(t *testing.T, cfg *setting.Cfg, authInfo login.AuthInfoService,
	usr user.Service, orgSvc org.Service,
) *Service {
	t.Helper()
	svc, err := ProvideService(cfg, authInfo, usr, orgSvc, quotatest.New(false, nil))
	require.NoError(t, err)
	return svc
}

func TestLoginURL(t *testing.T) {
	svc := newTestService(t, newCASCfg(""), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

	assert.Equal(t,
		"https://4a.example.com/4a/credentials/cas?appId=grafana&service=https%3A%2F%2Fgrafana.example.com%2Fsso%2Fcallback",
		svc.LoginURL())
}

func TestLoginURLAppendsToExistingQuery(t *testing.T) {
	cfg := newCASCfg("")
	cfg.CAS.LoginURL = "https://4a.example.com/4a/credentials/cas?version=2"
	svc := newTestService(t, cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

	assert.Equal(t,
		"https://4a.example.com/4a/credentials/cas?version=2&appId=grafana&service=https%3A%2F%2Fgrafana.example.com%2Fsso%2Fcallback",
		svc.LoginURL())
}

func TestLogoutURL(t *testing.T) {
	svc := newTestService(t, newCASCfg(""), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

	assert.Equal(t,
		"https://4a.example.com/4a/cas/logout?appId=grafana&url=https%3A%2F%2Fgrafana.example.com%2Flogin",
		svc.LogoutURL("https://grafana.example.com/login"))
}

func TestValidateTicket(t *testing.T) {
	successXML := func(user, attrs string) string {
		return "<cas:serviceResponse xmlns:cas=\"http://4a.pab.com.cn/cas\">" +
			"<cas:authenticationSuccess><cas:user>" + user + "</cas:user>" +
			"<cas:attributes>" + attrs + "</cas:attributes>" +
			"</cas:authenticationSuccess></cas:serviceResponse>"
	}
	defaultAttrs := "<cas:cn>张三</cas:cn><cas:name>test543</cas:name>" +
		"<cas:email>test543@pingan.com.cn</cas:email><cas:role>Editor</cas:role>"

	t.Run("success with configured attribute names", func(t *testing.T) {
		var gotAppID, gotTicket string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAppID = r.URL.Query().Get("appId")
			gotTicket = r.URL.Query().Get("ticket")
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(successXML("test543", defaultAttrs)))
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL+"/4a/cas/serviceValidate"),
			&authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		cu, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.NoError(t, err)

		assert.Equal(t, "grafana", gotAppID)
		assert.Equal(t, "TICKET-1", gotTicket)
		assert.Equal(t, &CASUser{
			Login: "test543",
			Name:  "张三",
			Email: "test543@pingan.com.cn",
			Role:  org.RoleEditor,
		}, cu)
	})

	t.Run("success with custom attribute names and unprefixed xml", func(t *testing.T) {
		body := "<serviceResponse><authenticationSuccess><user>test543</user>" +
			"<attributes><displayName>张三</displayName><mail>test543@pingan.com.cn</mail><grpRole>Admin</grpRole></attributes>" +
			"</authenticationSuccess></serviceResponse>"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()

		cfg := newCASCfg(srv.URL)
		cfg.CAS.EmailAttribute = "mail"
		cfg.CAS.NameAttribute = "displayName"
		cfg.CAS.RoleAttribute = "grpRole"
		svc := newTestService(t, cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		cu, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.NoError(t, err)

		assert.Equal(t, "test543", cu.Login)
		assert.Equal(t, "张三", cu.Name)
		assert.Equal(t, "test543@pingan.com.cn", cu.Email)
		assert.Equal(t, org.RoleAdmin, cu.Role)
	})

	t.Run("role value normalization", func(t *testing.T) {
		cases := []struct {
			value string
			want  org.RoleType
		}{
			{"Admin", org.RoleAdmin},
			{"editor", org.RoleEditor},
			{"VIEWER", org.RoleViewer},
			{"SuperAdmin", ""},
			{"", ""},
		}
		for _, tc := range cases {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(successXML("test543", "<cas:role>"+tc.value+"</cas:role>")))
			}))
			cfg := newCASCfg(srv.URL)
			svc := newTestService(t, cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

			cu, err := svc.ValidateTicket(context.Background(), "TICKET-1")
			require.NoError(t, err)
			assert.Equal(t, tc.want, cu.Role, "role value %q", tc.value)

			srv.Close()
		}
	})

	t.Run("empty attribute config maps nothing", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(successXML("test543", defaultAttrs)))
		}))
		defer srv.Close()

		cfg := newCASCfg(srv.URL)
		cfg.CAS.EmailAttribute = ""
		cfg.CAS.NameAttribute = ""
		cfg.CAS.RoleAttribute = ""
		svc := newTestService(t, cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		cu, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.NoError(t, err)

		assert.Equal(t, "test543", cu.Login)
		assert.Empty(t, cu.Email)
		assert.Empty(t, cu.Name)
		assert.Empty(t, cu.Role)
	})

	t.Run("authentication failure element", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<cas:serviceResponse xmlns:cas="http://4a.pab.com.cn/cas"><cas:authenticationFailure code="INVALID_TICKET">bad</cas:authenticationFailure></cas:serviceResponse>`))
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		_, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.ErrorIs(t, err, errCASTicketInvalid)
	})

	t.Run("missing user element", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(successXML("", defaultAttrs)))
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		_, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.ErrorIs(t, err, errCASTicketInvalid)
	})

	t.Run("non-xml body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not xml at all <"))
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		_, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.ErrorIs(t, err, errCASInternal)
	})

	t.Run("401 plain text does not leak body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Session not found, ticket: SECRET-DETAIL"))
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		_, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.ErrorIs(t, err, errCASTicketInvalid)
		assert.NotContains(t, err.Error(), "SECRET-DETAIL")
	})

	t.Run("unexpected status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		svc := newTestService(t, newCASCfg(srv.URL), &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{})

		_, err := svc.ValidateTicket(context.Background(), "TICKET-1")
		require.ErrorIs(t, err, errCASInternal)
	})
}

func TestUpsertUser(t *testing.T) {
	newCASUser := func(role org.RoleType) *CASUser {
		return &CASUser{Login: "test543", Name: "张三", Email: "test543@pingan.com.cn", Role: role}
	}

	t.Run("rejects new user when signup is disabled", func(t *testing.T) {
		cfg := newCASCfg("")
		cfg.CAS.AllowSignUp = false
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedError = user.ErrUserNotFound
		usrFake := usertest.NewUserServiceFake()
		usrFake.CreateFn = func(_ context.Context, _ *user.CreateUserCommand) (*user.User, error) {
			t.Fatal("Create must not be called when signup is disabled")
			return nil, nil
		}

		svc := newTestService(t, cfg, authInfo, usrFake, &orgtest.FakeOrgService{})

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.ErrorIs(t, err, errCASSignupDisabled)
	})

	t.Run("creates user with mapped role and auth connection", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedError = user.ErrUserNotFound
		usrFake := usertest.NewUserServiceFake()
		var createCmd *user.CreateUserCommand
		usrFake.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			createCmd = cmd
			return &user.User{ID: 42, Login: cmd.Login, Email: cmd.Email, Name: cmd.Name, OrgID: 1}, nil
		}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		usr, err := svc.UpsertUser(context.Background(), newCASUser(org.RoleEditor))
		require.NoError(t, err)
		require.Equal(t, int64(42), usr.ID)

		require.NotNil(t, createCmd)
		assert.Equal(t, "test543", createCmd.Login)
		assert.Equal(t, "test543@pingan.com.cn", createCmd.Email)
		assert.Equal(t, "张三", createCmd.Name)
		assert.Equal(t, string(org.RoleEditor), createCmd.DefaultOrgRole)

		require.NotNil(t, authInfo.setCmd)
		assert.Equal(t, int64(42), authInfo.setCmd.UserId)
		assert.Equal(t, login.CASAuthModule, authInfo.setCmd.AuthModule)
		assert.Equal(t, "test543", authInfo.setCmd.AuthId)
	})

	t.Run("empty role falls back to grafana default at creation", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedError = user.ErrUserNotFound
		usrFake := usertest.NewUserServiceFake()
		var createCmd *user.CreateUserCommand
		usrFake.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			createCmd = cmd
			return &user.User{ID: 42, Login: cmd.Login}, nil
		}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.NoError(t, err)
		assert.Empty(t, createCmd.DefaultOrgRole)
	})

	t.Run("rejects disabled user", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"}
		usrFake := usertest.NewUserServiceFake()
		usrFake.ExpectedUser = &user.User{ID: 7, Login: "test543", IsDisabled: true}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.ErrorIs(t, err, errCASUserDisabled)
	})

	t.Run("syncs changed email and name", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"}
		usrFake := usertest.NewUserServiceFake()
		usrFake.ExpectedUser = &user.User{ID: 7, Login: "test543", Email: "old@example.com", Name: "旧名", OrgID: 2}
		var updateCmd *user.UpdateUserCommand
		usrFake.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
			updateCmd = cmd
			return nil
		}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.NoError(t, err)

		require.NotNil(t, updateCmd)
		assert.Equal(t, "test543@pingan.com.cn", updateCmd.Email)
		require.NotNil(t, updateCmd.EmailVerified)
		assert.False(t, *updateCmd.EmailVerified)
		assert.Equal(t, "张三", updateCmd.Name)

		// 已有连接走 UpdateAuthInfo 刷新
		require.NotNil(t, authInfo.updateCmd)
		assert.Equal(t, int64(7), authInfo.updateCmd.UserId)
	})

	t.Run("no attribute update when nothing changed", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"}
		usrFake := usertest.NewUserServiceFake()
		usrFake.ExpectedUser = &user.User{ID: 7, Login: "test543", Email: "test543@pingan.com.cn", Name: "张三", OrgID: 2}
		usrFake.UpdateFn = func(_ context.Context, _ *user.UpdateUserCommand) error {
			t.Fatal("Update must not be called when nothing changed")
			return nil
		}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.NoError(t, err)
	})

	t.Run("updates default org role when mapped", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"}
		usrFake := usertest.NewUserServiceFake()
		usrFake.ExpectedUser = &user.User{ID: 7, Login: "test543", Email: "test543@pingan.com.cn", Name: "张三", OrgID: 2}
		orgFake := &recordingOrg{}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, orgFake)

		_, err := svc.UpsertUser(context.Background(), newCASUser(org.RoleAdmin))
		require.NoError(t, err)

		require.NotNil(t, orgFake.updateCmd)
		assert.Equal(t, int64(2), orgFake.updateCmd.OrgID)
		assert.Equal(t, int64(7), orgFake.updateCmd.UserID)
		assert.Equal(t, org.RoleAdmin, orgFake.updateCmd.Role)
	})

	t.Run("skips org role update when role is empty", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: 7, AuthModule: login.CASAuthModule, AuthId: "test543"}
		usrFake := usertest.NewUserServiceFake()
		usrFake.ExpectedUser = &user.User{ID: 7, Login: "test543", Email: "test543@pingan.com.cn", Name: "张三", OrgID: 2}
		orgFake := &recordingOrg{}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, orgFake)

		_, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.NoError(t, err)
		assert.Nil(t, orgFake.updateCmd)
	})

	t.Run("retries lookup after create race", func(t *testing.T) {
		authInfo := &recordingAuthInfo{}
		calls := 0
		authInfo.getAuthInfoFn = func(_ context.Context, _ *login.GetAuthInfoQuery) (*login.UserAuth, error) {
			calls++
			if calls == 1 {
				return nil, user.ErrUserNotFound
			}
			return &login.UserAuth{UserId: 42, AuthModule: login.CASAuthModule, AuthId: "test543"}, nil
		}
		usrFake := usertest.NewUserServiceFake()
		usrFake.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			return nil, user.ErrUserAlreadyExists
		}
		usrFake.ExpectedUser = &user.User{ID: 42, Login: "test543", Email: "test543@pingan.com.cn", Name: "张三", OrgID: 1}

		svc := newTestService(t, newCASCfg(""), authInfo, usrFake, &orgtest.FakeOrgService{})

		usr, err := svc.UpsertUser(context.Background(), newCASUser(""))
		require.NoError(t, err)
		assert.Equal(t, int64(42), usr.ID)
		assert.Equal(t, 2, calls)
	})
}

func TestProvideServiceTLS(t *testing.T) {
	t.Run("fails on unreadable ca file", func(t *testing.T) {
		cfg := newCASCfg("")
		cfg.CAS.TLSCACert = filepath.Join(t.TempDir(), "missing.pem")

		_, err := ProvideService(cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{}, quotatest.New(false, nil))
		require.ErrorIs(t, err, errCASInternal)
	})

	t.Run("fails on invalid pem", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(caFile, []byte("not a pem"), 0o600))

		cfg := newCASCfg("")
		cfg.CAS.TLSCACert = caFile

		_, err := ProvideService(cfg, &authinfotest.FakeService{}, usertest.NewUserServiceFake(), &orgtest.FakeOrgService{}, quotatest.New(false, nil))
		require.ErrorIs(t, err, errCASInternal)
	})
}
