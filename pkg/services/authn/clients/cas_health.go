package clients

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// casHealthCacheTTL 探测结果缓存时长:避免每次登录页渲染都探测 4A,
// 也避免 4A 故障期间对它的连续请求
const casHealthCacheTTL = 30 * time.Second

// CASHealth 探测 4A 登录端点可达性,供 auto-login 判断是否降级渲染原生登录页。
// down = 网络错误/超时/HTTP>=500;任何非 5xx 响应(含 302/4xx)视为 up。
// 误判为 down 时仅表现为多显示原生登录页(登录页仍可手动访问 /login/cas),无功能损失
type CASHealth struct {
	cfg    *setting.Cfg
	client *http.Client
	log    log.Logger

	mu         sync.Mutex
	checkedAt  time.Time
	lastResult bool
}

func NewCASHealth(cfg *setting.Cfg) (*CASHealth, error) {
	tlsConfig, err := casTLSConfig(&cfg.CAS)
	if err != nil {
		return nil, err
	}
	return &CASHealth{
		cfg: cfg,
		// 不跟随重定向:只关心 4A 端点本身是否响应
		client: &http.Client{
			Timeout: cfg.CAS.HealthCheckTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig},
		},
		log: log.New("auth.cas.health"),
	}, nil
}

// Check 返回 4A 是否可达,结果按 casHealthCacheTTL 缓存
func (h *CASHealth) Check(ctx context.Context) bool {
	h.mu.Lock()
	if time.Since(h.checkedAt) < casHealthCacheTTL {
		cached := h.lastResult
		h.mu.Unlock()
		return cached
	}
	h.mu.Unlock()

	// 探测在锁外执行,避免并发请求因一次慢探测集体阻塞
	result := h.probe(ctx)

	h.mu.Lock()
	h.checkedAt = time.Now()
	h.lastResult = result
	h.mu.Unlock()
	return result
}

func (h *CASHealth) probe(ctx context.Context) bool {
	q := url.Values{}
	q.Set("appId", h.cfg.CAS.AppID)
	q.Set("service", h.serviceURL())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.CAS.ServerURL+casLoginPath+"?"+q.Encode(), nil)
	if err != nil {
		return false
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.log.FromContext(ctx).Debug("CAS health probe failed", "error", err)
		return false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode < http.StatusInternalServerError
}

func (h *CASHealth) serviceURL() string {
	return strings.TrimSuffix(h.cfg.AppURL, "/") + "/login/cas"
}
