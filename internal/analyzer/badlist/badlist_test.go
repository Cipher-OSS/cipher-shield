package badlist

// White-box test package — accesses unexported editDistance, typosquatTarget, mapSev.

import (
	"context"
	"testing"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// ── editDistance ──────────────────────────────────────────────────────────────

func TestEditDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"kitten", "sitting", 3},
		{"lodash", "lodashr", 1},     // one insertion
		{"reqeusts", "requests", 2},  // two substitutions (transposition)
		{"colourama", "colorama", 1}, // one insertion
		{"a", "b", 1},
	}
	for _, tc := range cases {
		got := editDistance(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── typosquatTarget ───────────────────────────────────────────────────────────

func TestTyposquatTargetNPM(t *testing.T) {
	target, dist := typosquatTarget("lodashr", "npm")
	if target != "lodash" || dist != 1 {
		t.Errorf("typosquatTarget(lodashr, npm) = (%q, %d), want (lodash, 1)", target, dist)
	}
}

func TestTyposquatTargetPyPI(t *testing.T) {
	target, dist := typosquatTarget("reqeusts", "pypi")
	if target != "requests" || dist > 2 {
		t.Errorf("typosquatTarget(reqeusts, pypi) = (%q, %d), want (requests, <=2)", target, dist)
	}
}

func TestTyposquatTargetExactMatchNotFlagged(t *testing.T) {
	target, dist := typosquatTarget("lodash", "npm")
	if target != "" || dist != 99 {
		t.Errorf("exact match should return (\"\", 99), got (%q, %d)", target, dist)
	}
}

func TestTyposquatTargetUnrelatedPackage(t *testing.T) {
	_, dist := typosquatTarget("completely-unrelated-package", "npm")
	if dist <= 2 {
		t.Errorf("unrelated package: expected dist > 2, got %d", dist)
	}
}

func TestTyposquatTargetUnknownEcosystem(t *testing.T) {
	_, dist := typosquatTarget("lodash", "rubygems")
	if dist != 99 {
		t.Errorf("unknown ecosystem should return dist=99, got %d", dist)
	}
}

// ── Known-bad list ────────────────────────────────────────────────────────────

func TestKnownBadExactVersion(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "event-stream", Version: "3.3.6",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "known-bad" {
		t.Errorf("type: want known-bad, got %s", findings[0].Type)
	}
	if findings[0].Severity != shield.SeverityCritical {
		t.Errorf("severity: want critical, got %s", findings[0].Severity)
	}
}

func TestKnownBadVersionMismatch(t *testing.T) {
	a := New()
	// event-stream is only bad at 3.3.6 — 4.0.0 should be clean
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "event-stream", Version: "4.0.0",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "known-bad" {
			t.Errorf("event-stream@4.0.0 should not match known-bad (version-specific entry)")
		}
	}
}

func TestKnownBadWildcardVersion(t *testing.T) {
	a := New()
	// crossenv has version "*" — any version should match
	for _, ver := range []string{"1.0.0", "2.0.0", "0.0.1"} {
		findings, err := a.Analyze(context.Background(), shield.PackageRef{
			Ecosystem: shield.EcosystemNPM, Name: "crossenv", Version: ver,
		}, nil)
		if err != nil {
			t.Fatalf("crossenv@%s: unexpected error: %v", ver, err)
		}
		found := false
		for _, f := range findings {
			if f.Type == "known-bad" {
				found = true
			}
		}
		if !found {
			t.Errorf("crossenv@%s: expected known-bad finding (wildcard version)", ver)
		}
	}
}

func TestKnownBadPyPI(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemPyPI, Name: "colourama", Version: "0.4.1",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("colourama should be flagged as known-bad")
	}
	if findings[0].Severity != shield.SeverityCritical {
		t.Errorf("severity: want critical, got %s", findings[0].Severity)
	}
}

func TestKnownBadCaseInsensitive(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "EVENT-STREAM", Version: "3.3.6",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "known-bad" {
			found = true
		}
	}
	if !found {
		t.Error("known-bad lookup must be case-insensitive")
	}
}

func TestCleanPackage(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("lodash@4.17.21 should be clean, got %d findings: %+v", len(findings), findings)
	}
}

// ── Typosquatting ─────────────────────────────────────────────────────────────

func TestTyposquattingNPM(t *testing.T) {
	a := New()
	// lodashr is 1 edit from lodash
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "lodashr", Version: "1.0.0",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("lodashr should be flagged as possible typosquat")
	}
	if findings[0].Type != "typosquat" {
		t.Errorf("type: want typosquat, got %s", findings[0].Type)
	}
	if findings[0].Severity != shield.SeverityHigh {
		t.Errorf("severity: want high, got %s", findings[0].Severity)
	}
}

func TestTyposquattingPyPI(t *testing.T) {
	a := New()
	// reqeusts is 2 edits from requests
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemPyPI, Name: "reqeusts", Version: "2.28.0",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("reqeusts should be flagged as possible typosquat of requests")
	}
}

func TestTyposquatSkippedForShortName(t *testing.T) {
	a := New()
	// len("px") = 2 < 5 — typosquat check must be skipped
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "px", Version: "1.0.0",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "typosquat" {
			t.Error("typosquat check should be skipped for names shorter than 5 characters")
		}
	}
}

func TestTyposquatSkippedForFourCharName(t *testing.T) {
	a := New()
	// gopd is a legitimate 4-char package; edit distance 2 from "got" is a false positive.
	// Names < 5 chars must not trigger the typosquat check.
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "gopd", Version: "1.0.1",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "typosquat" {
			t.Errorf("gopd should not be flagged as a typosquat: %s", f.Description)
		}
	}
}

func TestTyposquatSkippedWhenKnownBadFound(t *testing.T) {
	a := New()
	// crossenv is known-bad AND 1 edit from popular "cross-env"
	// The typosquat check must be skipped since known-bad already fired
	findings, err := a.Analyze(context.Background(), shield.PackageRef{
		Ecosystem: shield.EcosystemNPM, Name: "crossenv", Version: "1.0.0",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "typosquat" {
			t.Error("typosquat must not appear alongside a known-bad finding for the same package")
		}
	}
	knownBadFound := false
	for _, f := range findings {
		if f.Type == "known-bad" {
			knownBadFound = true
		}
	}
	if !knownBadFound {
		t.Error("crossenv should still produce a known-bad finding")
	}
}

// ── Severity mapping ──────────────────────────────────────────────────────────

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		in   string
		want shield.Severity
	}{
		{"critical", shield.SeverityCritical},
		{"high", shield.SeverityHigh},
		{"medium", shield.SeverityMedium},
		{"low", shield.SeverityLow},
		{"CRITICAL", shield.SeverityCritical}, // case-insensitive
		{"HIGH", shield.SeverityHigh},
		{"unknown", shield.SeverityInfo},
		{"", shield.SeverityInfo},
	}
	for _, tc := range cases {
		got := mapSev(tc.in)
		if got != tc.want {
			t.Errorf("mapSev(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
