package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

func TestCASHealth_Check(t *testing.T) {
	newHealth := func(cfg *setting.Cfg) *CASHealth {
		h, err := NewCASHealth(cfg)
		require.NoError(t, err)
		return h
	}

	t.Run("should report up on redirect response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusFound)
		}))
		defer ts.Close()
		assert.True(t, newHealth(newCASTestCfg(ts.URL)).Check(context.Background()))
	})

	t.Run("should report up on any non-5xx response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		assert.True(t, newHealth(newCASTestCfg(ts.URL)).Check(context.Background()))
	})

	t.Run("should report down on 5xx", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer ts.Close()
		assert.False(t, newHealth(newCASTestCfg(ts.URL)).Check(context.Background()))
	})

	t.Run("should report down on connection refused", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := ts.URL
		ts.Close()
		assert.False(t, newHealth(newCASTestCfg(url)).Check(context.Background()))
	})

	t.Run("should report down on timeout", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		cfg := newCASTestCfg(ts.URL)
		cfg.CAS.HealthCheckTimeout = 100 * time.Millisecond
		assert.False(t, newHealth(cfg).Check(context.Background()))
	})

	t.Run("should cache the result within ttl", func(t *testing.T) {
		var probes atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			probes.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		h := newHealth(newCASTestCfg(ts.URL))
		assert.True(t, h.Check(context.Background()))
		assert.True(t, h.Check(context.Background()))
		assert.Equal(t, int64(1), probes.Load(), "second check must be served from cache")
	})

	t.Run("should not follow redirects", func(t *testing.T) {
		var followed atomic.Int64
		mux := http.NewServeMux()
		mux.HandleFunc("/4a/credentials/cas", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/4a/login", http.StatusFound)
		})
		mux.HandleFunc("/4a/login", func(w http.ResponseWriter, _ *http.Request) {
			followed.Add(1)
			w.WriteHeader(http.StatusOK)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		assert.True(t, newHealth(newCASTestCfg(ts.URL)).Check(context.Background()))
		assert.Equal(t, int64(0), followed.Load(), "health probe must not follow the 4A redirect")
	})
}
