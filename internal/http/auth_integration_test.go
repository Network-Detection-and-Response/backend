package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	authsvc "github.com/Network-Detection-and-Response/backend/internal/service/auth"
)

func authTestDB(t *testing.T) (*postgres.Store, func()) {
	t.Helper()
	if _, err := exec.LookPath("goose"); err != nil {
		t.Skip("goose CLI not installed")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, url)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	migrations := filepath.Join(root, "migrations")
	cmd := exec.Command("goose", "-dir", migrations, "postgres", url, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		pool.Close()
		t.Fatalf("goose up: %v\n%s", err, out)
	}

	store := postgres.NewStore(pool)
	return store, func() { pool.Close() }
}

func authRouter(t *testing.T, store *postgres.Store, registerLimit, loginLimit int) http.Handler {
	t.Helper()
	cfg := config.Config{
		SensorAPIKey:          "k",
		MaxBodyBytes:          1 << 20,
		MaxFlowsPerBatch:      100,
		CORSAllowedOrigins:    []string{"http://127.0.0.1:5173"},
		SessionTTL:            time.Hour,
		AuthCookieSecure:      false,
		AuthCookieName:        "ndr_session",
		AuthRateLimitRegister: registerLimit,
		AuthRateLimitLogin:    loginLimit,
		AuthRateLimitWindow:   time.Minute,
	}
	return httpapi.NewRouter(httpapi.Dependencies{
		Config:       cfg,
		DB:           dbOK{},
		FlowEnqueuer: &memQueue{},
		AuthService:  authsvc.NewService(store, cfg.SessionTTL),
	})
}

func withOrigin(req *http.Request) *http.Request {
	req.Header.Set("Origin", "http://127.0.0.1:5173")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func readSetCookie(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func uniqueLogin(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

func TestAuthIntegrationRegisterLoginMeLogout(t *testing.T) {
	store, cleanup := authTestDB(t)
	defer cleanup()
	r := authRouter(t, store, 50, 50)

	login := uniqueLogin("alice")
	body := map[string]string{
		"name":     "Alice",
		"nickname": "Ali",
		"login":    login,
		"password": "password-15chars",
	}
	raw, _ := json.Marshal(body)
	req := withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(raw)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	cookie := readSetCookie(w, "ndr_session")
	if cookie == "" {
		t.Fatal("missing session cookie after register")
	}

	// Duplicate login
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(raw))))
	if w2.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d body=%s", w2.Code, w2.Body.String())
	}

	// Case-variant login
	body2 := map[string]string{
		"name": "Bob", "nickname": "Bob", "login": strings.ToUpper(login), "password": "password-15chars",
	}
	raw2, _ := json.Marshal(body2)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(raw2))))
	if w3.Code != http.StatusConflict {
		t.Fatalf("case duplicate status=%d body=%s", w3.Code, w3.Body.String())
	}

	// Me with cookie
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq.AddCookie(&http.Cookie{Name: "ndr_session", Value: cookie})
	meW := httptest.NewRecorder()
	r.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("me status=%d body=%s", meW.Code, meW.Body.String())
	}
	if strings.Contains(meW.Body.String(), "password") {
		t.Fatal("me response must not include password fields")
	}

	// Me without cookie
	noAuth := httptest.NewRecorder()
	r.ServeHTTP(noAuth, httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	if noAuth.Code != http.StatusUnauthorized {
		t.Fatalf("me unauth status=%d", noAuth.Code)
	}

	// Logout
	outReq := withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil))
	outReq.AddCookie(&http.Cookie{Name: "ndr_session", Value: cookie})
	outW := httptest.NewRecorder()
	r.ServeHTTP(outW, outReq)
	if outW.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", outW.Code, outW.Body.String())
	}

	// Revoked session
	me2 := httptest.NewRecorder()
	meReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq2.AddCookie(&http.Cookie{Name: "ndr_session", Value: cookie})
	r.ServeHTTP(me2, meReq2)
	if me2.Code != http.StatusUnauthorized {
		t.Fatalf("revoked me status=%d", me2.Code)
	}

	// Login success
	loginBody, _ := json.Marshal(map[string]string{"login": login, "password": "password-15chars"})
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))))
	if loginW.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginW.Code, loginW.Body.String())
	}
	if readSetCookie(loginW, "ndr_session") == "" {
		t.Fatal("missing cookie after login")
	}

	// Wrong password / unknown user — same message
	for _, payload := range []map[string]string{
		{"login": login, "password": "definitely-wrong-xx"},
		{"login": "no_such_user_zz", "password": "password-15chars"},
	} {
		b, _ := json.Marshal(payload)
		ww := httptest.NewRecorder()
		r.ServeHTTP(ww, withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))))
		if ww.Code != http.StatusUnauthorized {
			t.Fatalf("bad login status=%d body=%s", ww.Code, ww.Body.String())
		}
		if !strings.Contains(ww.Body.String(), "Неверный логин или пароль") {
			t.Fatalf("unexpected message: %s", ww.Body.String())
		}
	}

	// No plaintext password column
	cols, err := store.UserPasswordColumnNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		lower := strings.ToLower(c)
		if lower == "password" || lower == "plain_password" {
			t.Fatalf("forbidden column present: %s", c)
		}
	}
	hasHash := false
	for _, c := range cols {
		if c == "password_hash" {
			hasHash = true
		}
	}
	if !hasHash {
		t.Fatal("password_hash column missing")
	}
}

func TestAuthIntegrationExpiredSession(t *testing.T) {
	store, cleanup := authTestDB(t)
	defer cleanup()

	svc := authsvc.NewService(store, time.Millisecond)
	fixed := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return fixed }

	reg, _, err := svc.Register(context.Background(), "Eve", "Eve", uniqueLogin("eve"), "password-15chars")
	if err != nil {
		t.Fatal(err)
	}
	svc.Now = func() time.Time { return fixed.Add(time.Second) }
	if _, err := svc.ResolveSession(context.Background(), reg.RawToken); err == nil {
		t.Fatal("expected expired session rejection")
	}
}

func TestAuthIntegrationRateLimit(t *testing.T) {
	store, cleanup := authTestDB(t)
	defer cleanup()
	r := authRouter(t, store, 2, 2)

	var saw429 bool
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]string{
			"name": "R", "nickname": "Rr", "login": uniqueLogin("rl"), "password": "password-15chars",
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withOrigin(httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))))
		if w.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("expected HTTP 429 from register rate limit")
	}
}
