package api

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipLimiter is a per-IP token bucket rate limiter.
// Tokens refill at `rate` per second up to a max of `burst`.
type ipLimiter struct {
	state sync.Map // string(IP) → *ipState
	rate  float64  // tokens added per second
	burst float64  // max tokens
	done  chan struct{}
}

type ipState struct {
	tokens   float64
	lastFill time.Time
	mu       sync.Mutex
}

func newIPLimiter(ratePerSec, burst float64) *ipLimiter {
	l := &ipLimiter{rate: ratePerSec, burst: burst, done: make(chan struct{})}
	go func() {
		tick := time.NewTicker(10 * time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				l.prune()
			case <-l.done:
				return
			}
		}
	}()
	return l
}

// stop terminates the background prune goroutine.
func (l *ipLimiter) stop() {
	close(l.done)
}

func (l *ipLimiter) allow(ip string) bool {
	raw, _ := l.state.LoadOrStore(ip, &ipState{tokens: l.burst, lastFill: time.Now()})
	s := raw.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(s.lastFill).Seconds()
	s.tokens += elapsed * l.rate
	if s.tokens > l.burst {
		s.tokens = l.burst
	}
	s.lastFill = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

func (l *ipLimiter) prune() {
	cutoff := time.Now().Add(-30 * time.Minute)
	l.state.Range(func(k, v interface{}) bool {
		s := v.(*ipState)
		s.mu.Lock()
		old := s.lastFill.Before(cutoff)
		s.mu.Unlock()
		if old {
			l.state.Delete(k)
		}
		return true
	})
}

// rateLimitLogin returns a middleware that applies the server's login rate limiter.
// Each Server gets its own limiter — 5 attempts per minute per IP.
func (s *Server) rateLimitLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.loginLimiter.allow(ip) {
			jsonError(w, "too many login attempts — try again later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// rateLimitAPI returns a middleware that applies the server's general API rate limiter.
// 120 requests per minute per IP (burst of 20).
func (s *Server) rateLimitAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.apiLimiter.allow(ip) {
			jsonError(w, "rate limit exceeded — slow down", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP extracts the real client IP, respecting X-Forwarded-For for proxied deployments.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) IP — that's the original client.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
