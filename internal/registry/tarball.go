package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

const MaxTarballBytes = 50 << 20 // 50 MB

// FetchTarball downloads the package tarball from the upstream registry.
// npm:  https://registry.npmjs.org/{name}/-/{bareName}-{version}.tgz
// PyPI: resolves download URL via the JSON metadata API, prefers sdist over wheel.
func FetchTarball(ctx context.Context, pkg shield.PackageRef, userAgent string) ([]byte, error) {
	var tarURL string

	switch pkg.Ecosystem {
	case shield.EcosystemNPM:
		// Scoped packages (@scope/name) use just the bare name in the filename.
		bareName := pkg.Name
		if strings.HasPrefix(pkg.Name, "@") {
			if parts := strings.SplitN(pkg.Name[1:], "/", 2); len(parts) == 2 {
				bareName = parts[1]
			}
		}
		tarURL = fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz",
			pkg.Name, bareName, pkg.Version)

	case shield.EcosystemPyPI:
		var err error
		tarURL, err = ResolvePyPITarball(ctx, pkg.Name, pkg.Version)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", pkg.Ecosystem)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", tarURL, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", tarURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d for %s", resp.StatusCode, tarURL)
	}

	return io.ReadAll(io.LimitReader(resp.Body, MaxTarballBytes))
}

// ResolvePyPITarball queries the PyPI JSON API and returns the sdist download URL,
// falling back to the first wheel if no sdist is available.
func ResolvePyPITarball(ctx context.Context, name, ver string) (string, error) {
	apiURL := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, ver)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("pypi metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pypi metadata: HTTP %d", resp.StatusCode)
	}

	var meta struct {
		URLs []struct {
			URL         string `json:"url"`
			PackageType string `json:"packagetype"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("pypi metadata decode: %w", err)
	}

	var wheel string
	for _, u := range meta.URLs {
		switch u.PackageType {
		case "sdist":
			return u.URL, nil
		case "bdist_wheel":
			if wheel == "" {
				wheel = u.URL
			}
		}
	}
	if wheel != "" {
		return wheel, nil
	}
	return "", fmt.Errorf("no downloadable file found for %s@%s on PyPI", name, ver)
}
