package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
)

// Reporter ships scan results to a central cipher-shield server asynchronously.
type Reporter struct {
	serverURL string
	token     string
	client    *http.Client
}

// New creates a Reporter. Returns nil if serverURL is empty (disables reporting).
func New(serverURL, token string) *Reporter {
	if serverURL == "" {
		return nil
	}
	return &Reporter{
		serverURL: strings.TrimRight(serverURL, "/"),
		token:     token,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Report ships the result to the server in a background goroutine.
// Retries up to 3 times with exponential backoff on transient failures.
// Safe to call on a nil Reporter.
func (r *Reporter) Report(result *shield.ScanResult) {
	if r == nil || result == nil {
		return
	}
	go func() {
		backoff := time.Second
		for attempt := 1; attempt <= 3; attempt++ {
			err := r.send(result)
			if err == nil {
				return
			}
			if attempt == 3 {
				log.Printf("[reporter] %s@%s: giving up after 3 attempts: %v", result.Package.Name, result.Package.Version, err)
				return
			}
			log.Printf("[reporter] %s@%s: attempt %d failed, retrying in %s: %v", result.Package.Name, result.Package.Version, attempt, backoff, err)
			time.Sleep(backoff)
			backoff *= 2
		}
	}()
}

func (r *Reporter) send(result *shield.ScanResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(
		context.Background(), "POST",
		r.serverURL+"/api/v1/report",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
