package reporter

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

const exceptionTTL = 60 * time.Second

// ExceptionCache fetches and caches the exception list from the central server.
// The cache is refreshed in the background every 60 seconds. While a refresh
// is in flight the last known list is served (stale-while-revalidate). If the
// server is unreachable, the stale list stays in use until the server comes back.
//
// Safe to use on a nil receiver (IsExcepted always returns false).
type ExceptionCache struct {
	serverURL string
	token     string
	client    *http.Client

	mu         sync.RWMutex
	exceptions []shield.Exception
}

// NewExceptionCache returns a started ExceptionCache. Returns nil when serverURL
// is empty — callers should handle nil gracefully (IsExcepted returns false on nil).
func NewExceptionCache(serverURL, token string) *ExceptionCache {
	if serverURL == "" {
		return nil
	}
	c := &ExceptionCache{
		serverURL: strings.TrimRight(serverURL, "/"),
		token:     token,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
	c.refresh() // synchronous initial fetch so the cache is warm before the proxy starts serving
	go c.loop()
	return c
}

// IsExcepted returns true if the package is on the server-managed exception list.
// Version matching rules:
//   - A stored exception with empty version matches any requested version (wildcard).
//   - A caller passing empty version (metadata/name-only check, version not yet known)
//     matches any stored exception for that package — the tarball-level check will
//     enforce version-specific exceptions once the version is known.
//   - Otherwise an exact version match is required.
func (c *ExceptionCache) IsExcepted(eco shield.Ecosystem, name, version string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.exceptions {
		if e.Ecosystem != eco || !strings.EqualFold(e.Name, name) {
			continue
		}
		if e.Version == "" || version == "" || e.Version == version {
			return true
		}
	}
	return false
}

func (c *ExceptionCache) loop() {
	ticker := time.NewTicker(exceptionTTL)
	defer ticker.Stop()
	for range ticker.C {
		c.refresh()
	}
}

func (c *ExceptionCache) refresh() {
	req, err := http.NewRequest("GET", c.serverURL+"/api/v1/proxy/exceptions", nil)
	if err != nil {
		return
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("[exceptions] refresh failed: %v — using stale cache", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[exceptions] refresh: server returned %d — using stale cache", resp.StatusCode)
		return
	}
	var result struct {
		Exceptions []shield.Exception `json:"exceptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[exceptions] refresh: decode error: %v — using stale cache", err)
		return
	}
	c.mu.Lock()
	c.exceptions = result.Exceptions
	c.mu.Unlock()
	log.Printf("[exceptions] synced %d exception(s) from server", len(result.Exceptions))
}
