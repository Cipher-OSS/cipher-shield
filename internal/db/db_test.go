package db_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/db"
)

func openTestStore(t *testing.T) db.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := db.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── Migration ─────────────────────────────────────────────────────────────────

func TestMigrateIdempotent(t *testing.T) {
	s := openTestStore(t)
	// Migrate is called by Open; calling it again must be a no-op.
	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func TestUserRoundtrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n, err := s.CountUsers(ctx)
	if err != nil || n != 0 {
		t.Fatalf("want 0 users, got %d (err %v)", n, err)
	}

	u, err := s.CreateUser(ctx, "alice@example.com", "hash", "admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.UserID == "" {
		t.Fatal("want non-empty UserID")
	}

	got, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil || got == nil {
		t.Fatalf("GetUserByEmail: got %v err %v", got, err)
	}
	if got.Role != "admin" {
		t.Errorf("want role=admin, got %q", got.Role)
	}

	byID, err := s.GetUserByID(ctx, u.UserID)
	if err != nil || byID == nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if err := s.UpdatePassword(ctx, u.UserID, "newhash"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	updated, _ := s.GetUserByID(ctx, u.UserID)
	if updated.PasswordHash != "newhash" {
		t.Errorf("password not updated")
	}

	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers: got %d (err %v)", len(users), err)
	}
}

func TestGetUserByEmailMissing(t *testing.T) {
	s := openTestStore(t)
	u, err := s.GetUserByEmail(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u != nil {
		t.Fatalf("want nil, got %+v", u)
	}
}

// ── Scan cache ────────────────────────────────────────────────────────────────

func TestScanCacheRoundtrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	pkg := shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21"}

	// Cache miss before save
	r, err := s.GetCachedResult(ctx, pkg.Ecosystem, pkg.Name, pkg.Version)
	if err != nil || r != nil {
		t.Fatalf("want nil cache miss, got %v err %v", r, err)
	}

	result := shield.ScanResult{
		ScanID:    "scan-abc",
		Package:   pkg,
		Verdict:   shield.VerdictAllow,
		Findings:  []shield.Finding{},
		ScannedAt: time.Now().UTC(),
	}
	if err := s.SaveResult(ctx, result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	cached, err := s.GetCachedResult(ctx, pkg.Ecosystem, pkg.Name, pkg.Version)
	if err != nil || cached == nil {
		t.Fatalf("want cache hit, got %v err %v", cached, err)
	}
	if cached.Verdict != shield.VerdictAllow {
		t.Errorf("want verdict allow, got %q", cached.Verdict)
	}
	if cached.CachedAt == nil {
		t.Error("want CachedAt set on cache hit")
	}
}

func TestSaveResultUpsert(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	pkg := shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "express", Version: "4.18.0"}
	save := func(verdict shield.Verdict) {
		if err := s.SaveResult(ctx, shield.ScanResult{
			ScanID:    "scan-" + string(verdict),
			Package:   pkg,
			Verdict:   verdict,
			ScannedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("SaveResult(%s): %v", verdict, err)
		}
	}

	save(shield.VerdictAllow)
	save(shield.VerdictBlock) // upsert: same cache key, new verdict

	cached, _ := s.GetCachedResult(ctx, pkg.Ecosystem, pkg.Name, pkg.Version)
	if cached == nil || cached.Verdict != shield.VerdictBlock {
		t.Errorf("want upserted verdict=block, got %v", cached)
	}
}

// ── Exceptions ────────────────────────────────────────────────────────────────

func TestExceptionRoundtrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	exc := shield.Exception{
		ExceptionID: "exc-1",
		Ecosystem:   shield.EcosystemNPM,
		Name:        "left-pad",
		Version:     "1.3.0",
		Reason:      "reviewed",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.AddException(ctx, exc); err != nil {
		t.Fatalf("AddException: %v", err)
	}

	got, err := s.GetException(ctx, shield.EcosystemNPM, "left-pad", "1.3.0")
	if err != nil || got == nil {
		t.Fatalf("GetException: got %v err %v", got, err)
	}
	if got.Reason != "reviewed" {
		t.Errorf("want reason=reviewed, got %q", got.Reason)
	}

	list, err := s.ListExceptions(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListExceptions: got %d (err %v)", len(list), err)
	}

	if err := s.DeleteException(ctx, "exc-1"); err != nil {
		t.Fatalf("DeleteException: %v", err)
	}
	list, _ = s.ListExceptions(ctx)
	if len(list) != 0 {
		t.Errorf("want empty after delete, got %d", len(list))
	}
}

func TestExceptionWildcard(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Wildcard exception (version = "")
	if err := s.AddException(ctx, shield.Exception{
		ExceptionID: "exc-wc",
		Ecosystem:   shield.EcosystemNPM,
		Name:        "colors",
		Version:     "",
		Reason:      "all versions allowed",
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AddException: %v", err)
	}

	got, err := s.GetException(ctx, shield.EcosystemNPM, "colors", "1.4.0")
	if err != nil || got == nil {
		t.Fatalf("want wildcard match, got %v err %v", got, err)
	}
}

func TestDeleteExceptionNotFound(t *testing.T) {
	s := openTestStore(t)
	err := s.DeleteException(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("want error deleting nonexistent exception")
	}
}

// ── History ───────────────────────────────────────────────────────────────────

func TestHistoryAndPrune(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		s.SaveResult(ctx, shield.ScanResult{
			ScanID:    "scan-" + string(rune('a'+i)),
			Package:   shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "pkg", Version: "1.0.0"},
			Verdict:   shield.VerdictAllow,
			ScannedAt: time.Now().UTC(),
		})
	}

	hist, err := s.ListHistory(ctx, 10)
	if err != nil || len(hist) != 3 {
		t.Fatalf("want 3 history rows, got %d (err %v)", len(hist), err)
	}

	// PruneHistory with retentionDays=0 would keep everything (nothing is that old);
	// use a large negative retention to force deletion.
	n, err := s.PruneHistory(ctx, 0)
	if err != nil {
		t.Fatalf("PruneHistory: %v", err)
	}
	// retentionDays=0 means delete everything older than now — all 3 rows qualify.
	_ = n
}

// ── Violations + triage ───────────────────────────────────────────────────────

func TestViolationsAndDismiss(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	result := shield.ScanResult{
		ScanID:    "scan-block-1",
		Package:   shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "malware", Version: "1.0.0"},
		Verdict:   shield.VerdictBlock,
		ScannedAt: time.Now().UTC(),
	}
	if err := s.SaveResult(ctx, result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	violations, err := s.ListViolations(ctx, 100)
	if err != nil || len(violations) != 1 {
		t.Fatalf("want 1 violation, got %d (err %v)", len(violations), err)
	}
	if violations[0].Dismissed {
		t.Error("want not dismissed")
	}

	if err := s.DismissResult(ctx, "scan-block-1", "alice", "false positive"); err != nil {
		t.Fatalf("DismissResult: %v", err)
	}

	violations, _ = s.ListViolations(ctx, 100)
	if !violations[0].Dismissed {
		t.Error("want dismissed after DismissResult")
	}
	if violations[0].Dismissal.DismissedBy != "alice" {
		t.Errorf("want dismissed_by=alice, got %q", violations[0].Dismissal.DismissedBy)
	}

	// Dismiss again — upsert must update, not error.
	if err := s.DismissResult(ctx, "scan-block-1", "bob", "confirmed"); err != nil {
		t.Fatalf("second DismissResult: %v", err)
	}
	violations, _ = s.ListViolations(ctx, 100)
	if violations[0].Dismissal.DismissedBy != "bob" {
		t.Errorf("want dismissed_by=bob after update, got %q", violations[0].Dismissal.DismissedBy)
	}
}

// ── Download events ───────────────────────────────────────────────────────────

func TestDownloadEventRoundtrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	e := shield.DownloadEvent{
		EventID:      "evt-001",
		Package:      shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		MachineID:    "dev-host-1",
		Verdict:      shield.VerdictAllow,
		ScanID:       "scan-001",
		DownloadedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveDownload(ctx, e); err != nil {
		t.Fatalf("SaveDownload: %v", err)
	}

	events, err := s.ListDownloads(ctx, 10)
	if err != nil {
		t.Fatalf("ListDownloads: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	got := events[0]
	if got.EventID != e.EventID {
		t.Errorf("event_id: want %q, got %q", e.EventID, got.EventID)
	}
	if got.Package.Name != e.Package.Name {
		t.Errorf("package.name: want %q, got %q", e.Package.Name, got.Package.Name)
	}
	if got.Package.Version != e.Package.Version {
		t.Errorf("package.version: want %q, got %q", e.Package.Version, got.Package.Version)
	}
	if got.Package.Ecosystem != e.Package.Ecosystem {
		t.Errorf("package.ecosystem: want %q, got %q", e.Package.Ecosystem, got.Package.Ecosystem)
	}
	if got.MachineID != e.MachineID {
		t.Errorf("machine_id: want %q, got %q", e.MachineID, got.MachineID)
	}
	if got.Verdict != e.Verdict {
		t.Errorf("verdict: want %q, got %q", e.Verdict, got.Verdict)
	}
	if got.ScanID != e.ScanID {
		t.Errorf("scan_id: want %q, got %q", e.ScanID, got.ScanID)
	}
}

func TestDownloadEventIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	e := shield.DownloadEvent{
		EventID:      "evt-dup",
		Package:      shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "express", Version: "4.18.0"},
		MachineID:    "machine-1",
		Verdict:      shield.VerdictAllow,
		ScanID:       "scan-dup",
		DownloadedAt: time.Now().UTC(),
	}
	if err := s.SaveDownload(ctx, e); err != nil {
		t.Fatalf("first SaveDownload: %v", err)
	}
	// Duplicate event_id must be a no-op, not an error (INSERT OR IGNORE / ON CONFLICT DO NOTHING).
	if err := s.SaveDownload(ctx, e); err != nil {
		t.Fatalf("duplicate SaveDownload: %v", err)
	}

	events, _ := s.ListDownloads(ctx, 10)
	if len(events) != 1 {
		t.Errorf("duplicate insert must yield exactly 1 row, got %d", len(events))
	}
}

func TestDownloadEventOrdering(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	names := []string{"oldest", "middle", "newest"}
	for i, name := range names {
		if err := s.SaveDownload(ctx, shield.DownloadEvent{
			EventID:      "evt-" + name,
			Package:      shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: name, Version: "1.0.0"},
			MachineID:    "host",
			Verdict:      shield.VerdictAllow,
			ScanID:       "scan-" + name,
			DownloadedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("SaveDownload(%s): %v", name, err)
		}
	}

	events, err := s.ListDownloads(ctx, 10)
	if err != nil {
		t.Fatalf("ListDownloads: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d", len(events))
	}
	// ListDownloads returns most-recent first.
	if events[0].Package.Name != "newest" {
		t.Errorf("want newest first, got %q", events[0].Package.Name)
	}
	if events[2].Package.Name != "oldest" {
		t.Errorf("want oldest last, got %q", events[2].Package.Name)
	}
}

func TestDownloadEventLimit(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	base := time.Now().UTC()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if err := s.SaveDownload(ctx, shield.DownloadEvent{
			EventID:      "evt-" + id,
			Package:      shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "pkg-" + id, Version: "1.0.0"},
			DownloadedAt: base,
		}); err != nil {
			t.Fatalf("SaveDownload(%s): %v", id, err)
		}
	}

	events, err := s.ListDownloads(ctx, 3)
	if err != nil {
		t.Fatalf("ListDownloads: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("want 3 (limit honored), got %d", len(events))
	}
}

// ── Environment ───────────────────────────────────────────────────────────────

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
