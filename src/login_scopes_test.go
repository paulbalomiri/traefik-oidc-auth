package src

// The tests of this fork's change: with AllowLoginScopes the login address takes a scope list, the session keeps
// the list it was asked with, and a token refresh asks for that list. Without the setting nothing changes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/paulbalomiri/traefik-oidc-auth/src/config"
	"github.com/paulbalomiri/traefik-oidc-auth/src/logging"
	"github.com/paulbalomiri/traefik-oidc-auth/src/oidc"
	"github.com/paulbalomiri/traefik-oidc-auth/src/session"
)

func newLoginScopesTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	toa := newPkceTestAuth(t)
	toa.Config.Scopes = []string{"openid", "profile"}
	toa.Config.LoginUri = "/login"
	toa.Config.ValidPostLoginRedirectUris = []string{"https://app.example.com/page"}
	toa.Config.AllowLoginScopes = true
	return toa
}

// A request as Traefik hands it to the plugin: a path, on https://app.example.com.
func requestTo(target string) *http.Request {
	req := httptest.NewRequest("GET", target, nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

// The scope list of the authorization request a response redirects to.
func scopeAskedFor(t *testing.T, rw *httptest.ResponseRecorder) string {
	t.Helper()
	if rw.Code != http.StatusFound {
		t.Fatalf("expected a redirect to the provider, got %d: %s", rw.Code, rw.Body.String())
	}
	location, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return location.Query().Get("scope")
}

func TestLogin_AsksForTheScopesOfTheLoginRequest(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	rw := httptest.NewRecorder()

	toa.handleLogin(rw, requestTo("/login?scope=openid+profile+admin.cluster&redirect_uri=https%3A%2F%2Fapp.example.com%2Fpage"), false, "")

	if got := scopeAskedFor(t, rw); got != "openid profile admin.cluster" {
		t.Fatalf("the login asks for %q, expected the list of the login request", got)
	}
	if state := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location")); state.RedirectUrl != "https://app.example.com/page" {
		t.Fatalf("the login returns to %q, expected the redirect_uri of the login request", state.RedirectUrl)
	}
}

func TestLogin_AlwaysAsksForOpenid(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	rw := httptest.NewRecorder()

	toa.handleLogin(rw, requestTo("/login?scope=admin.cluster"), false, "")

	if got := scopeAskedFor(t, rw); got != "openid admin.cluster" {
		t.Fatalf("the login asks for %q, expected openid before the list of the login request", got)
	}
}

func TestLogin_WithoutTheSettingAsksForTheConfiguredScopes(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	toa.Config.AllowLoginScopes = false
	rw := httptest.NewRecorder()

	toa.handleLogin(rw, requestTo("/login?scope=openid+admin.cluster"), false, "")

	if got := scopeAskedFor(t, rw); got != "openid profile" {
		t.Fatalf("the login asks for %q, expected the configured list", got)
	}
}

func TestLogin_WithoutAScopeParameterAsksForTheConfiguredScopes(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	rw := httptest.NewRecorder()

	toa.handleLogin(rw, requestTo("/login"), false, "")

	if got := scopeAskedFor(t, rw); got != "openid profile" {
		t.Fatalf("the login asks for %q, expected the configured list", got)
	}
}

// A page of the app may have a parameter named scope: it is no login request.
func TestLogin_OutsideTheLoginUriAsksForTheConfiguredScopes(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	rw := httptest.NewRecorder()

	toa.handleLogin(rw, requestTo("/page?scope=openid+admin.cluster"), false, "")

	if got := scopeAskedFor(t, rw); got != "openid profile" {
		t.Fatalf("the login asks for %q, expected the configured list", got)
	}
}

// Where the callback is on another host, the login goes there first and to the provider from there.
func TestLogin_ThroughTheCallbackKeepsItsScopes(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	callback, err := url.Parse("https://auth.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback
	first := httptest.NewRecorder()

	toa.handleLogin(first, requestTo("/login?scope=openid+admin.cluster"), false, "")

	state := decodeStateFromLocation(t, toa.Config.Secret, first.Header().Get("Location"))
	if state.Action != "RedirectThenLogin" {
		t.Fatalf("expected the login to go through the callback, got the action %q", state.Action)
	}
	second := callbackWithState(t, toa, state, "", "")
	if got := scopeAskedFor(t, second); got != "openid admin.cluster" {
		t.Fatalf("after the callback the login asks for %q, expected the list of the login request", got)
	}
}

func TestCallback_ARestartedLoginKeepsItsScopes(t *testing.T) {
	toa := newLoginScopesTestAuth(t)
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page", Scopes: "openid admin.cluster"}

	rw := callbackWithState(t, toa, state, "error=temporarily_unavailable&error_description=authentication_expired", "")

	if got := scopeAskedFor(t, rw); got != "openid admin.cluster" {
		t.Fatalf("the restarted login asks for %q, expected the list of the first one", got)
	}
}

// keepingSessionStorage keeps the one session it is given.
type keepingSessionStorage struct {
	kept *session.SessionState
}

func (s *keepingSessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *session.SessionState) (string, error) {
	s.kept = state
	return "ticket", nil
}

func (s *keepingSessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*session.SessionState, error) {
	return s.kept, nil
}

func TestCallback_TheSessionKeepsTheScopesItWasAskedWith(t *testing.T) {
	server := newTokenTestServer(t)
	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	storage := &keepingSessionStorage{}
	toa.SessionStorage = storage
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page", Scopes: "openid admin.cluster"}

	rw := callbackWithState(t, toa, state, "code=abc", "")

	if rw.Code >= 400 {
		t.Fatalf("callback status=%d body=%s", rw.Code, rw.Body.String())
	}
	if storage.kept == nil || storage.kept.Scopes != "openid admin.cluster" {
		t.Fatalf("the session keeps %+v, expected the scopes the login asked for", storage.kept)
	}
}

// A provider whose token endpoint records the scope a refresh asks for, and which finds only the new token active.
func newRefreshTestServer(t *testing.T, asked *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		*asked = r.FormValue("grant_type") + ": " + r.FormValue("scope")
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{AccessToken: "new-token", TokenType: "Bearer", ExpiresIn: 3600})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": r.FormValue("token") == "new-token", "sub": "user-1"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestRefresh_AsksForTheScopesOfTheSession(t *testing.T) {
	asked := ""
	server := newRefreshTestServer(t, &asked)
	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	toa.Config.Scopes = []string{"openid", "profile"}
	toa.SessionStorage = &keepingSessionStorage{kept: &session.SessionState{
		Id: "s1", AccessToken: "old-token", RefreshToken: "refresh-token", Scopes: "openid admin.cluster",
	}}

	if _, _, _, err := validateSessionTicket(toa, "ticket"); err != nil {
		t.Fatal(err)
	}

	if asked != "refresh_token: openid admin.cluster" {
		t.Fatalf("the refresh asked for %q, expected the scopes of the session", asked)
	}
}

func TestRefresh_OfASessionWithoutScopesAsksForTheConfiguredScopes(t *testing.T) {
	asked := ""
	server := newRefreshTestServer(t, &asked)
	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	toa.Config.Scopes = []string{"openid", "profile"}
	toa.SessionStorage = &keepingSessionStorage{kept: &session.SessionState{
		Id: "s1", AccessToken: "old-token", RefreshToken: "refresh-token",
	}}

	if _, _, _, err := validateSessionTicket(toa, "ticket"); err != nil {
		t.Fatal(err)
	}

	if asked != "refresh_token: openid profile" {
		t.Fatalf("the refresh asked for %q, expected the configured list", asked)
	}
}
