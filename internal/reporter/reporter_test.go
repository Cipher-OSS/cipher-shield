package reporter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/reporter"
)

// ── ReportDownload ────────────────────────────────────────────────────────────

func TestReportDownloadSendsPayload(t *testing.T) {
	received := make(chan shield.DownloadEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("want POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/download" {
			t.Errorf("want path /api/v1/download, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("want Authorization: Bearer test-token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("want Content-Type application/json, got %q", r.Header.Get("Content-Type"))
		}
		var e shield.DownloadEvent
		json.NewDecoder(r.Body).Decode(&e)
		received <- e
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	r := reporter.New(srv.URL, "test-token")
	e := &shield.DownloadEvent{
		EventID:      "evt-reporter-test",
		Package:      shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		MachineID:    "test-host",
		Verdict:      shield.VerdictAllow,
		ScanID:       "scan-reporter-test",
		DownloadedAt: time.Now().UTC(),
	}
	r.ReportDownload(e)

	select {
	case got := <-received:
		if got.EventID != e.EventID {
			t.Errorf("event_id: want %q, got %q", e.EventID, got.EventID)
		}
		if got.Package.Name != e.Package.Name {
			t.Errorf("package.name: want %q, got %q", e.Package.Name, got.Package.Name)
		}
		if got.Package.Version != e.Package.Version {
			t.Errorf("package.version: want %q, got %q", e.Package.Version, got.Package.Version)
		}
		if got.MachineID != e.MachineID {
			t.Errorf("machine_id: want %q, got %q", e.MachineID, got.MachineID)
		}
		if got.Verdict != e.Verdict {
			t.Errorf("verdict: want %q, got %q", e.Verdict, got.Verdict)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: ReportDownload never sent request to server")
	}
}

func TestReportDownloadNilReporter(t *testing.T) {
	var r *reporter.Reporter
	// Must not panic when reporter is nil.
	r.ReportDownload(&shield.DownloadEvent{
		Package: shield.PackageRef{Name: "test", Version: "1.0.0"},
	})
}

func TestReportDownloadNilEvent(t *testing.T) {
	unexpected := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unexpected <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := reporter.New(srv.URL, "token")
	// Nil event must be a no-op — no HTTP request sent.
	r.ReportDownload(nil)

	// Brief wait to confirm nothing was sent.
	select {
	case <-unexpected:
		t.Error("ReportDownload(nil) must not send an HTTP request")
	case <-time.After(100 * time.Millisecond):
		// Expected: nothing sent.
	}
}

func TestReportDownloadServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := reporter.New(srv.URL, "token")
	// Server error must be logged but must not panic or crash the caller.
	r.ReportDownload(&shield.DownloadEvent{
		EventID: "evt-err",
		Package: shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "pkg", Version: "1.0.0"},
	})
	// Allow the goroutine to complete.
	time.Sleep(100 * time.Millisecond)
}

func TestNewNilOnEmptyURL(t *testing.T) {
	r := reporter.New("", "token")
	if r != nil {
		t.Error("New with empty URL must return nil (disables reporting)")
	}
}

// ── Report (scan result) ──────────────────────────────────────────────────────

func TestReportSendsToCorrectEndpoint(t *testing.T) {
	received := make(chan string, 1) // receives the path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	r := reporter.New(srv.URL, "token")
	r.Report(&shield.ScanResult{
		ScanID:    "scan-001",
		Package:   shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		Verdict:   shield.VerdictAllow,
		ScannedAt: time.Now(),
	})

	select {
	case path := <-received:
		if path != "/api/v1/report" {
			t.Errorf("Report: want path /api/v1/report, got %q", path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: Report never sent request")
	}
}
