package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/db"
	"github.com/cipher-oss/cipher-shield/internal/registry"
)

func runExplain(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cipher-shield explain <name[@version]>")
		os.Exit(1)
	}

	nameVersion := args[0]
	name, ver := nameVersion, ""
	if idx := strings.LastIndex(nameVersion, "@"); idx > 0 {
		name = nameVersion[:idx]
		ver = nameVersion[idx+1:]
	}

	dbPath := envOr("SHIELD_DB_PATH", defaultDBPath())
	store, err := db.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open local cache: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'cipher-shield scan package %s' to scan this package.\n", nameVersion)
		os.Exit(1)
	}
	defer store.Close()

	var result *shield.ScanResult

	if ver != "" {
		// Version specified — check cache directly for npm then pypi
		for _, eco := range []shield.Ecosystem{shield.EcosystemNPM, shield.EcosystemPyPI} {
			if r, err := store.GetCachedResult(context.Background(), eco, name, ver); err == nil && r != nil {
				result = r
				break
			}
		}
	} else {
		// No version — find the most recent history entry for this package name
		history, err := store.ListHistory(context.Background(), 200)
		if err == nil {
			for _, r := range history {
				if strings.EqualFold(r.Package.Name, name) {
					r := r
					result = &r
					break
				}
			}
		}
	}

	if result == nil {
		fmt.Printf("No cached result for %s — scanning now...\n\n", nameVersion)

		pl := buildPipelineWithStore(store)
		eco := shield.EcosystemNPM

		resolvedVer := ver
		if resolvedVer == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if v, err := resolveLatestVersion(ctx, eco, name); err == nil {
				resolvedVer = v
				fmt.Printf("Resolved %s@latest → %s\n\n", name, resolvedVer)
			} else {
				resolvedVer = "latest"
			}
			cancel()
		}

		pkg := shield.PackageRef{Ecosystem: eco, Name: name, Version: resolvedVer}

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		fmt.Printf("Fetching tarball... ")
		tarball, fetchErr := registry.FetchTarball(ctx, pkg, "cipher-shield/"+version)
		if fetchErr != nil {
			fmt.Printf("skipped (%v)\n", fetchErr)
		} else {
			fmt.Printf("%d KB\n\n", len(tarball)/1024)
		}

		r, err := pl.Analyze(ctx, pkg, tarball)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			os.Exit(1)
		}
		result = r
	}

	fmt.Printf("Package:  %s@%s (%s)\n", result.Package.Name, result.Package.Version, result.Package.Ecosystem)
	fmt.Printf("Verdict:  %s\n", verdictStr(result.Verdict))
	fmt.Printf("Scanned:  %s", result.ScannedAt.Format("2006-01-02 15:04 UTC"))
	if result.CachedAt != nil {
		fmt.Printf(" (cached)")
	}
	if result.ClaudeUsed {
		fmt.Printf(" · Claude Opus")
	}
	fmt.Printf("\n\n")

	printDetails(result)

	if result.Verdict == shield.VerdictBlock || result.Verdict == shield.VerdictWarn {
		fmt.Printf("\nIf this package is safe to use in your environment, add an exception:\n")
		fmt.Printf("  Dashboard → Exceptions → Add Exception\n")
	}
}
