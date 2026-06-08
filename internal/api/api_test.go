package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/api"
	"golang.org/x/crypto/bcrypt"
)

// ── Test doubles ──────────────────────────────────────────────────────────────

type testStore struct {
	users      map[string]*shield.User // keyed by email
	history    []shield.ScanResult
	exceptions map[string]shield.Exception // keyed by exception_id
}

func newTestStore() *testStore {
	return &testStore{
		users:      make(map[string]*shield.User),
		exceptions: make(map[string]shield.Exception),
	}
}

func (s *testStore) CreateUser(email, passwordHash, role string) (*shield.User, error) {
	u := &shield.User{
		UserID:       fmt.Sprintf("uid-%d", len(s.users)+1),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
	}
	s.users[email] = u
	return u, nil
}

func (s *testStore) GetUserByEmail(email string) (*shield.User, error) {
	return s.users[email], nil
}

func (s *testStore) CountUsers() (int, error) { return len(s.users), nil }

func (s *testStore) ListUsers() ([]shield.User, error) {
	out := make([]shield.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	return out, nil
}

func (s *testStore) GetCachedResult(_ shield.Ecosystem, _, _ string) (*shield.ScanResult, error) {
	return nil, nil
}

func (s *testStore) SaveResult(r shield.ScanResult) error {
	s.history = append(s.history, r)
	return nil
}

func (s *testStore) GetException(eco shield.Ecosystem, name, version string) (*shield.Exception, error) {
	return nil, nil
}

func (s *testStore) ListExceptions() ([]shield.Exception, error) {
	out := make([]shield.Exception, 0, len(s.exceptions))
	for _, e := range s.exceptions {
		out = append(out, e)
	}
	return out, nil
}

func (s *testStore) AddException(e shield.Exception) error {
	s.exceptions[e.ExceptionID] = e
	return nil
}

func (s *testStore) DeleteException(id string) error {
	delete(s.exceptions, id)
	return nil
}

func (s *testStore) ListHistory(limit int) ([]shield.ScanResult, error) {
	n := limit
	if n > len(s.history) {
		n = len(s.history)
	}
	return s.history[:n], nil
}

func (s *testStore) Migrate() error { return nil }
func (s *testStore) Close() error   { return nil }

type stubScanner struct {
	result *shield.ScanResult
}

func (ss *stubScanner) Analyze(_ context.Context, pkg shield.PackageRef, _ []byte) (*shield.ScanResult, error) {
	if ss.result != nil {
		return ss.result, nil
	}
	return &shield.ScanResult{
		ScanID:    "stub-scan",
		Package:   pkg,
		Verdict:   shield.VerdictAllow,
		ScannedAt: time.Now(),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const testSecret = "test-jwt-secret-at-least-32-bytes!!"
const testProxyToken = "test-proxy-token"

func newTestServer(store *testStore) *api.Server {
	return api.New(store, &stubScanner{}, []byte(testSecret), []byte(testProxyToken), "enforce")
}

// hashPw hashes with MinCost for fast tests.
func hashPw(pw string) string {
	b, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	return string(b)
}

// seedUser creates a user directly in the store (bypassing the API).
func seedUser(store *testStore, email, password, role string) {
	store.users[email] = &shield.User{
		UserID:       fmt.Sprintf("uid-%s", role),
		Email:        email,
		PasswordHash: hashPw(password),
		Role:         role,
		CreatedAt:    time.Now(),
	}
}

// login calls POST /api/v1/auth/login and returns the JWT on success.
func login(t *testing.T, srv *api.Server, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login(%s): want 200, got %d — %s", email, w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	return resp.Token
}

func authHeader(token string) string { return "Bearer " + token }

// doJSON sends a JSON request and returns the response recorder.
func doJSON(srv *api.Server, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", authHeader(token))
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "GET", "/api/v1/health", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("want status=ok, got %q", resp["status"])
	}
}

func TestConfig(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "GET", "/api/v1/config", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Version     string `json:"version"`
		AuthEnabled bool   `json:"auth_enabled"`
		Mode        string `json:"mode"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Version != "0.1.0" {
		t.Errorf("want version=0.1.0, got %q", resp.Version)
	}
	if !resp.AuthEnabled {
		t.Error("want auth_enabled=true when jwtSecret is set")
	}
	if resp.Mode != "enforce" {
		t.Errorf("want mode=enforce, got %q", resp.Mode)
	}
}

func TestConfigNoAuth(t *testing.T) {
	store := newTestStore()
	srv := api.New(store, &stubScanner{}, nil, nil, "warn")
	w := doJSON(srv, "GET", "/api/v1/config", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		AuthEnabled bool   `json:"auth_enabled"`
		Mode        string `json:"mode"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.AuthEnabled {
		t.Error("want auth_enabled=false when jwtSecret is empty")
	}
	if resp.Mode != "warn" {
		t.Errorf("want mode=warn, got %q", resp.Mode)
	}
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func TestLoginSuccess(t *testing.T) {
	store := newTestStore()
	seedUser(store, "alice@example.com", "secret123", "analyst")
	srv := newTestServer(store)

	body, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": "secret123"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string                 `json:"token"`
		User  map[string]interface{} `json:"user"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("want non-empty token")
	}
	if resp.User["email"] != "alice@example.com" {
		t.Errorf("want user.email=alice@example.com, got %v", resp.User["email"])
	}
}

func TestLoginBadPassword(t *testing.T) {
	store := newTestStore()
	seedUser(store, "alice@example.com", "secret123", "analyst")
	srv := newTestServer(store)

	w := doJSON(srv, "POST", "/api/v1/auth/login", "", map[string]string{
		"email": "alice@example.com", "password": "wrong",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "POST", "/api/v1/auth/login", "", map[string]string{
		"email": "nobody@example.com", "password": "x",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestLoginMissingFields(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "POST", "/api/v1/auth/login", "", map[string]string{"email": "a@b.com"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestLoginNoJWTSecret(t *testing.T) {
	store := newTestStore()
	srv := api.New(store, &stubScanner{}, nil, nil, "enforce")
	w := doJSON(srv, "POST", "/api/v1/auth/login", "", map[string]string{
		"email": "a@b.com", "password": "pw",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
}

// ── /auth/me ──────────────────────────────────────────────────────────────────

func TestMe(t *testing.T) {
	store := newTestStore()
	seedUser(store, "bob@example.com", "pw123", "admin")
	srv := newTestServer(store)
	token := login(t, srv, "bob@example.com", "pw123")

	w := doJSON(srv, "GET", "/api/v1/auth/me", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["email"] != "bob@example.com" {
		t.Errorf("want email=bob@example.com, got %q", resp["email"])
	}
	if resp["role"] != "admin" {
		t.Errorf("want role=admin, got %q", resp["role"])
	}
}

func TestMeNoToken(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "GET", "/api/v1/auth/me", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestMeInvalidToken(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "GET", "/api/v1/auth/me", "garbage.token.here", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

// ── Users / bootstrap ─────────────────────────────────────────────────────────

func TestBootstrapFirstUserNoAuth(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)

	w := doJSON(srv, "POST", "/api/v1/users", "", map[string]string{
		"email": "first@example.com", "password": "initialpass",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for bootstrap, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["role"] != "admin" {
		t.Errorf("first user must be forced to admin, got %v", resp["role"])
	}
}

func TestBootstrapSecondUserRequiresAdmin(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)
	// Bootstrap first user
	doJSON(srv, "POST", "/api/v1/users", "", map[string]string{
		"email": "admin@example.com", "password": "adminpass",
	})

	// Second user without auth → must be rejected
	w := doJSON(srv, "POST", "/api/v1/users", "", map[string]string{
		"email": "analyst@example.com", "password": "pw",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for second user without auth, got %d", w.Code)
	}
}

func TestCreateUserAsAdmin(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)
	// Bootstrap
	doJSON(srv, "POST", "/api/v1/users", "", map[string]string{
		"email": "admin@example.com", "password": "adminpass",
	})
	token := login(t, srv, "admin@example.com", "adminpass")

	w := doJSON(srv, "POST", "/api/v1/users", token, map[string]string{
		"email": "analyst@example.com", "password": "pw", "role": "analyst",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["role"] != "analyst" {
		t.Errorf("want role=analyst, got %v", resp["role"])
	}
}

func TestCreateUserAsAnalystForbidden(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)
	seedUser(store, "admin@example.com", "adminpass", "admin")
	seedUser(store, "analyst@example.com", "pw", "analyst")
	token := login(t, srv, "analyst@example.com", "pw")

	w := doJSON(srv, "POST", "/api/v1/users", token, map[string]string{
		"email": "new@example.com", "password": "pw", "role": "analyst",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestListUsersRequiresAdmin(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)
	seedUser(store, "admin@example.com", "adminpass", "admin")
	seedUser(store, "analyst@example.com", "pw", "analyst")

	// Analyst — forbidden
	analystToken := login(t, srv, "analyst@example.com", "pw")
	w := doJSON(srv, "GET", "/api/v1/users", analystToken, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst: want 403, got %d", w.Code)
	}

	// Admin — allowed
	adminToken := login(t, srv, "admin@example.com", "adminpass")
	w = doJSON(srv, "GET", "/api/v1/users", adminToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin: want 200, got %d", w.Code)
	}
}

// ── Proxy report ──────────────────────────────────────────────────────────────

func TestReportValidToken(t *testing.T) {
	store := newTestStore()
	srv := newTestServer(store)

	result := shield.ScanResult{
		ScanID:    "proxy-scan-1",
		Package:   shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "express", Version: "4.18.0"},
		Verdict:   shield.VerdictAllow,
		ScannedAt: time.Now(),
	}
	body, _ := json.Marshal(result)
	req := httptest.NewRequest("POST", "/api/v1/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testProxyToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
	if len(store.history) == 0 {
		t.Error("result must be saved to store")
	}
}

func TestReportInvalidToken(t *testing.T) {
	srv := newTestServer(newTestStore())

	result := shield.ScanResult{
		ScanID:  "x",
		Package: shield.PackageRef{Name: "pkg", Version: "1.0.0"},
	}
	body, _ := json.Marshal(result)
	req := httptest.NewRequest("POST", "/api/v1/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrongtoken")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestReportMissingPackageName(t *testing.T) {
	srv := newTestServer(newTestStore())

	body := `{"scan_id":"x","package":{"name":"","version":"1.0.0"}}`
	req := httptest.NewRequest("POST", "/api/v1/report", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testProxyToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ── History ───────────────────────────────────────────────────────────────────

func TestHistoryRequiresAuth(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "GET", "/api/v1/history", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHistoryReturnsResults(t *testing.T) {
	store := newTestStore()
	store.history = []shield.ScanResult{
		{ScanID: "s1", Package: shield.PackageRef{Name: "lodash", Version: "4.17.21", Ecosystem: shield.EcosystemNPM}, Verdict: shield.VerdictAllow, ScannedAt: time.Now()},
		{ScanID: "s2", Package: shield.PackageRef{Name: "express", Version: "4.18.0", Ecosystem: shield.EcosystemNPM}, Verdict: shield.VerdictAllow, ScannedAt: time.Now()},
	}
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	w := doJSON(srv, "GET", "/api/v1/history", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Count   int                  `json:"count"`
		Results []shield.ScanResult  `json:"results"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 2 {
		t.Errorf("want count=2, got %d", resp.Count)
	}
}

// ── Exceptions ────────────────────────────────────────────────────────────────

func TestExceptionsFlow(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	// List — initially empty
	w := doJSON(srv, "GET", "/api/v1/exceptions", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var listResp struct {
		Exceptions []shield.Exception `json:"exceptions"`
	}
	json.NewDecoder(w.Body).Decode(&listResp)
	if len(listResp.Exceptions) != 0 {
		t.Errorf("want empty list, got %d", len(listResp.Exceptions))
	}

	// Add
	w = doJSON(srv, "POST", "/api/v1/exceptions", token, map[string]string{
		"ecosystem": "npm",
		"name":      "left-pad",
		"version":   "1.3.0",
		"reason":    "reviewed — safe",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("add: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var exc shield.Exception
	json.NewDecoder(w.Body).Decode(&exc)
	if exc.Name != "left-pad" {
		t.Errorf("want name=left-pad, got %q", exc.Name)
	}

	// List again
	w = doJSON(srv, "GET", "/api/v1/exceptions", token, nil)
	json.NewDecoder(w.Body).Decode(&listResp)
	if len(listResp.Exceptions) != 1 {
		t.Errorf("want 1 exception, got %d", len(listResp.Exceptions))
	}

	// Delete
	w = doJSON(srv, "DELETE", "/api/v1/exceptions/"+exc.ExceptionID, token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d", w.Code)
	}
}

func TestExceptionsRequireAuth(t *testing.T) {
	srv := newTestServer(newTestStore())
	tests := []struct{ method, path string }{
		{"GET", "/api/v1/exceptions"},
		{"POST", "/api/v1/exceptions"},
		{"DELETE", "/api/v1/exceptions/some-id"},
	}
	for _, tt := range tests {
		w := doJSON(srv, tt.method, tt.path, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: want 401, got %d", tt.method, tt.path, w.Code)
		}
	}
}

// ── Scan: package ─────────────────────────────────────────────────────────────

func TestScanPackageRequiresAuth(t *testing.T) {
	srv := newTestServer(newTestStore())
	w := doJSON(srv, "POST", "/api/v1/scan/package", "", map[string]string{
		"name": "lodash", "version": "4.17.21",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestScanPackageSuccess(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	w := doJSON(srv, "POST", "/api/v1/scan/package", token, map[string]string{
		"ecosystem": "npm",
		"name":      "lodash",
		"version":   "4.17.21",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
	var result shield.ScanResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Package.Name != "lodash" {
		t.Errorf("want package name=lodash, got %q", result.Package.Name)
	}
}

func TestScanPackageMissingFields(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	w := doJSON(srv, "POST", "/api/v1/scan/package", token, map[string]string{"name": "lodash"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ── Scan: lockfile ────────────────────────────────────────────────────────────

func TestScanLockfileRequiresAuth(t *testing.T) {
	srv := newTestServer(newTestStore())
	req := httptest.NewRequest("POST", "/api/v1/scan/lockfile?filename=requirements.txt",
		strings.NewReader("requests==2.31.0\n"))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestScanLockfileRawBody(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	lockfileContent := "requests==2.31.0\nflask==3.0.0\n"
	req := httptest.NewRequest("POST", "/api/v1/scan/lockfile?filename=requirements.txt",
		strings.NewReader(lockfileContent))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count   int `json:"count"`
		Results []interface{} `json:"results"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 2 {
		t.Errorf("want count=2, got %d", resp.Count)
	}
}

func TestScanLockfileMultipart(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "requirements.txt")
	fw.Write([]byte("requests==2.31.0\n"))
	mw.Close()

	req := httptest.NewRequest("POST", "/api/v1/scan/lockfile", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — %s", w.Code, w.Body.String())
	}
}

func TestScanLockfileUnsupportedFormat(t *testing.T) {
	store := newTestStore()
	seedUser(store, "u@example.com", "pw", "analyst")
	srv := newTestServer(store)
	token := login(t, srv, "u@example.com", "pw")

	req := httptest.NewRequest("POST", "/api/v1/scan/lockfile?filename=Makefile",
		strings.NewReader("build:\n\tgo build ./...\n"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}
