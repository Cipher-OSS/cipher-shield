package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const knownBadURL = "https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/internal/analyzer/badlist/data/known_bad.json"

func runUpdate() {
	dest := envOr("SHIELD_DB_PATH", defaultDBPath())
	dest = filepath.Join(dirOf(dest), "known_bad.json")

	fmt.Printf("Fetching latest known-bad list from GitHub...\n")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(knownBadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetch failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "error: server returned %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var data struct {
		NPM  []json.RawMessage `json:"npm"`
		PyPI []json.RawMessage `json:"pypi"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read failed: %v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid JSON from server: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(dirOf(dest), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Updated: %s (%d npm, %d pypi entries)\n", dest, len(data.NPM), len(data.PyPI))
	fmt.Printf("Restart cipher-shield proxy for the new list to take effect.\n")
}
