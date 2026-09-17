package gofiber_session

import (
	"errors"
	"testing"
	"time"

	fsession "github.com/fasthttp/session/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/session/v2"
	"github.com/valyala/fasthttp"
)

// failingProvider is a session backend whose Get always fails, the way the
// memcached provider does when the server is unreachable. gofiber/session v2
// discards that error in Session.Get and returns a Store with a nil core, so
// the first store.Get(key) panics — the real production failure the readers
// must survive.
type failingProvider struct{}

var _ fsession.Provider = failingProvider{}

func (failingProvider) Get([]byte) ([]byte, error)                     { return nil, errors.New("backend unreachable") }
func (failingProvider) Save([]byte, []byte, time.Duration) error       { return nil }
func (failingProvider) Destroy([]byte) error                           { return nil }
func (failingProvider) Regenerate([]byte, []byte, time.Duration) error { return nil }
func (failingProvider) Count() int                                     { return 0 }
func (failingProvider) NeedGC() bool                                   { return false }
func (failingProvider) GC() error                                      { return nil }

// failingSessionCtx returns a request that carries a session cookie (so the
// lookup is not a new-user path and the provider IS consulted) bound to a
// session whose provider fails.
func failingSessionCtx(t *testing.T) (*fiber.Ctx, *session.Session) {
	t.Helper()
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	t.Cleanup(func() { app.ReleaseCtx(c) })
	c.Request().Header.SetCookie("session_id", "existing-session")
	return c, session.New(session.Config{Provider: failingProvider{}})
}

// sessionCtx returns a request context bound to a fresh in-memory session whose
// store holds the given key/value pairs (a nil value skips the key).
func sessionCtx(t *testing.T, values map[string]interface{}) (*fiber.Ctx, *session.Session) {
	t.Helper()
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	t.Cleanup(func() { app.ReleaseCtx(c) })
	s := session.New()
	store := s.Get(c)
	for k, v := range values {
		if v != nil {
			store.Set(k, v)
		}
	}
	id := store.ID()
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	c.Request().Header.SetCookie("session_id", id)
	return c, s
}

func TestReadSessionString(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value interface{}
		want  string
		ok    bool
	}{
		{name: "missing key"},
		{name: "non-string value", value: 42},
		{name: "empty string", value: ""},
		{name: "whitespace only", value: " \t\n"},
		{name: "string preserved untrimmed", value: " value ", want: " value ", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: tc.value})
			got, ok := ReadSessionString(c, s, TRX_USER_DETAILS)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestReadSessionValue pins the round-trip rule the exported generic depends
// on: the session store is msgpack-encoded, so an integer stored as int comes
// back as int64 and must be read with that type parameter.
func TestReadSessionValue(t *testing.T) {
	c, s := sessionCtx(t, map[string]interface{}{"COUNT": 7, "NAME": "ana"})

	if got, ok := ReadSessionValue[int64](c, s, "COUNT"); got != 7 || !ok {
		t.Fatalf("[int64] got (%v, %v), want (7, true)", got, ok)
	}
	if got, ok := ReadSessionValue[int](c, s, "COUNT"); got != 0 || ok {
		t.Fatalf("[int] got (%v, %v), want (0, false): stored ints round-trip as int64", got, ok)
	}
	if got, ok := ReadSessionValue[string](c, s, "NAME"); got != "ana" || !ok {
		t.Fatalf("[string] got (%q, %v), want (ana, true)", got, ok)
	}
	if got, ok := ReadSessionValue[string](c, s, "MISSING"); got != "" || ok {
		t.Fatalf("missing key: got (%q, %v), want zero value", got, ok)
	}
}

func TestReadSessionStringDegradedSession(t *testing.T) {
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(c)
	fc, fs := failingSessionCtx(t)

	for _, tc := range []struct {
		name string
		ctx  *fiber.Ctx
		s    *session.Session
	}{
		{name: "nil ctx", ctx: nil, s: session.New()},
		{name: "nil session", ctx: c, s: nil},
		{name: "session id generator panics inside s.Get", ctx: c, s: session.New(session.Config{
			Generator: func() []byte { panic("session failure") },
		})},
		{name: "session provider fails (nil core, panic in store.Get)", ctx: fc, s: fs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := ReadSessionString(tc.ctx, tc.s, TRX_USER_DETAILS); got != "" || ok {
				t.Fatalf("got (%q, %v), want unavailable value", got, ok)
			}
		})
	}
}

// appDetails mirrors a typical webapp SessionDetails: a subset of the proxy's
// wire fields plus an app-local field never present on the wire.
type appDetails struct {
	AccountId string `json:"accountId"`
	UserId    string `json:"userId"`
	AppView   string `json:"appView"`
	IsAdmin   *bool  `json:"isAdmin"`
}

func TestReadSessionDetails(t *testing.T) {
	const wire = `{"accountId":"AM-1","userId":"U-1","firstName":"Ana","appView":"CLAIMS","applicationFunctionsAccess":[{"functionId":"F1","accessGranted":true}],"impersonator":{"userId":"U-9","name":"Root"}}`

	t.Run("decodes the fields the target declares and ignores the rest", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: wire})
		d, err := ReadSessionDetails[appDetails](c, s)
		if err != nil {
			t.Fatal(err)
		}
		if d.AccountId != "AM-1" || d.UserId != "U-1" || d.AppView != "CLAIMS" {
			t.Fatalf("unexpected decode: %+v", d)
		}
		if d.IsAdmin != nil {
			t.Fatalf("app-local field must keep its zero value, got %v", *d.IsAdmin)
		}
	})

	t.Run("missing appView takes the current VIEW", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"userId":"U-1"}`, VIEW: "RFM"})
		d, err := ReadSessionDetails[appDetails](c, s)
		if err != nil {
			t.Fatal(err)
		}
		if d.UserId != "U-1" || d.AppView != "RFM" {
			t.Fatalf("got %+v, want UserId U-1 and AppView RFM", d)
		}
	})

	t.Run("blank appView takes the current VIEW", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"appView":"  "}`, VIEW: "RFM"})
		d, err := ReadSessionDetails[appDetails](c, s)
		if err != nil || d.AppView != "RFM" {
			t.Fatalf("got (%+v, %v), want AppView RFM", d, err)
		}
	})

	t.Run("informed appView is kept over VIEW", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"appView":"CLAIMS"}`, VIEW: "RFM"})
		d, err := ReadSessionDetails[appDetails](c, s)
		if err != nil || d.AppView != "CLAIMS" {
			t.Fatalf("got (%+v, %v), want AppView CLAIMS", d, err)
		}
	})

	t.Run("no VIEW stored leaves appView blank", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"userId":"U-1"}`})
		d, err := ReadSessionDetails[appDetails](c, s)
		if err != nil || d.AppView != "" {
			t.Fatalf("got (%+v, %v), want blank AppView", d, err)
		}
	})

	t.Run("non-string appView fails the decode like any other mistyped field", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"userId":"U-1","appView":7}`, VIEW: "RFM"})
		d, err := ReadSessionDetails[appDetails](c, s)
		if !errors.Is(err, ErrInvalidUserDetails) || d != (appDetails{}) {
			t.Fatalf("got (%+v, %v), want zero value and ErrInvalidUserDetails", d, err)
		}
	})

	t.Run("target without an appView field is unaffected by the fallback", func(t *testing.T) {
		type idOnly struct {
			UserId string `json:"userId"`
		}
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"userId":"U-1"}`, VIEW: "RFM"})
		d, err := ReadSessionDetails[idOnly](c, s)
		if err != nil || d.UserId != "U-1" {
			t.Fatalf("got (%+v, %v)", d, err)
		}
	})

	t.Run("missing details", func(t *testing.T) {
		c, s := sessionCtx(t, nil)
		d, err := ReadSessionDetails[appDetails](c, s)
		if !errors.Is(err, ErrNoUserDetails) || d != (appDetails{}) {
			t.Fatalf("got (%+v, %v), want zero value and ErrNoUserDetails", d, err)
		}
	})

	t.Run("non-string details", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: 42})
		if _, err := ReadSessionDetails[appDetails](c, s); !errors.Is(err, ErrNoUserDetails) {
			t.Fatalf("err = %v, want ErrNoUserDetails", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{TRX_USER_DETAILS: `{"userId":"U-1",`})
		d, err := ReadSessionDetails[appDetails](c, s)
		if !errors.Is(err, ErrInvalidUserDetails) || errors.Unwrap(err) == nil {
			t.Fatalf("err = %v, want wrapped ErrInvalidUserDetails", err)
		}
		if d != (appDetails{}) {
			t.Fatalf("partial decode leaked: %+v", d)
		}
	})

	t.Run("degraded session does not panic", func(t *testing.T) {
		app := fiber.New()
		c := app.AcquireCtx(&fasthttp.RequestCtx{})
		defer app.ReleaseCtx(c)
		bad := session.New(session.Config{Generator: func() []byte { panic("session failure") }})
		if _, err := ReadSessionDetails[appDetails](c, bad); !errors.Is(err, ErrNoUserDetails) {
			t.Fatalf("panicking generator: err = %v, want ErrNoUserDetails", err)
		}
		fc, fs := failingSessionCtx(t)
		if _, err := ReadSessionDetails[appDetails](fc, fs); !errors.Is(err, ErrNoUserDetails) {
			t.Fatalf("failing provider: err = %v, want ErrNoUserDetails", err)
		}
	})
}

func TestReadSessionView(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		c, s := sessionCtx(t, map[string]interface{}{VIEW: "PBM_MNG"})
		if v, ok := ReadSessionView(c, s); v != "PBM_MNG" || !ok {
			t.Fatalf("got (%q, %v)", v, ok)
		}
	})
	t.Run("absent", func(t *testing.T) {
		c, s := sessionCtx(t, nil)
		if v, ok := ReadSessionView(c, s); v != "" || ok {
			t.Fatalf("got (%q, %v)", v, ok)
		}
	})
}

func TestReadSessionBool(t *testing.T) {
	const key = "IS_ADMIN"
	for _, tc := range []struct {
		name  string
		value interface{}
		want  bool
		ok    bool
	}{
		{name: "missing key"},
		{name: "stored true", value: true, want: true, ok: true},
		{name: "stored false is a value", value: false, want: false, ok: true},
		{name: "string under the key is not a bool", value: "true"},
		{name: "number under the key is not a bool", value: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := sessionCtx(t, map[string]interface{}{key: tc.value})
			got, ok := ReadSessionBool(c, s, key)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got (%v, %v), want (%v, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}

	t.Run("degraded session does not panic", func(t *testing.T) {
		app := fiber.New()
		c := app.AcquireCtx(&fasthttp.RequestCtx{})
		defer app.ReleaseCtx(c)
		bad := session.New(session.Config{Generator: func() []byte { panic("session failure") }})
		if got, ok := ReadSessionBool(c, bad, key); got || ok {
			t.Fatalf("panicking generator: got (%v, %v), want (false, false)", got, ok)
		}
		fc, fs := failingSessionCtx(t)
		if got, ok := ReadSessionBool(fc, fs, key); got || ok {
			t.Fatalf("failing provider: got (%v, %v), want (false, false)", got, ok)
		}
		if got, ok := ReadSessionBool(nil, session.New(), key); got || ok {
			t.Fatalf("nil ctx: got (%v, %v)", got, ok)
		}
	})
}

func TestHasInformedAppView(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want bool
	}{
		{name: "missing key", data: `{"userId":"U-1"}`},
		{name: "empty string", data: `{"appView":""}`},
		{name: "whitespace only", data: `{"appView":" \t\n"}`},
		{name: "JSON null", data: `{"appView":null}`},
		{name: "number is not a string", data: `{"appView":7}`},
		{name: "object is not a string", data: `{"appView":{"id":"RFM"}}`},
		{name: "malformed JSON", data: `{"appView":`},
		{name: "not an object", data: `["appView"]`},
		{name: "informed string", data: `{"appView":"RFM"}`, want: true},
		{name: "informed string with surrounding spaces", data: `{"appView":" RFM "}`, want: true},
		{name: "informed string among other fields", data: `{"userId":"U-1","appView":"RFM","applicationFunctionsAccess":[{"functionId":"F1"}]}`, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasInformedAppView([]byte(tc.data)); got != tc.want {
				t.Fatalf("hasInformedAppView(%s) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestPatchAppView(t *testing.T) {
	t.Run("sets appView and leaves every other field untouched", func(t *testing.T) {
		yes := true
		d := appDetails{AccountId: "AM-1", UserId: "U-1", AppView: "", IsAdmin: &yes}
		patchAppView(&d, "RFM")
		if d.AppView != "RFM" {
			t.Fatalf("AppView = %q, want RFM", d.AppView)
		}
		if d.AccountId != "AM-1" || d.UserId != "U-1" || d.IsAdmin == nil || !*d.IsAdmin {
			t.Fatalf("other fields changed: %+v", d)
		}
	})

	t.Run("overwrites a blank appView only because the caller decided so", func(t *testing.T) {
		d := appDetails{AppView: "CLAIMS"}
		patchAppView(&d, "RFM")
		if d.AppView != "RFM" {
			t.Fatalf("AppView = %q, want RFM (patchAppView does not check; hasInformedAppView does)", d.AppView)
		}
	})

	t.Run("target without an appView field is left as is", func(t *testing.T) {
		type idOnly struct {
			UserId string `json:"userId"`
		}
		d := idOnly{UserId: "U-1"}
		patchAppView(&d, "RFM")
		if d != (idOnly{UserId: "U-1"}) {
			t.Fatalf("got %+v", d)
		}
	})

	t.Run("view is JSON-escaped on the way in", func(t *testing.T) {
		d := appDetails{}
		patchAppView(&d, `PBM "Mng" \ <x>`)
		if d.AppView != `PBM "Mng" \ <x>` {
			t.Fatalf("AppView = %q", d.AppView)
		}
	})

	t.Run("non-pointer target is a no-op, never a panic", func(t *testing.T) {
		patchAppView(appDetails{}, "RFM")
		patchAppView(nil, "RFM")
	})
}
