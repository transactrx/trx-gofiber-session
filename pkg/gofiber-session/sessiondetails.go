package gofiber_session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/session/v2"
)

// ErrNoUserDetails is returned by ReadSessionDetails when the request carries no
// usable TRX_USER_DETAILS value: no session, no store, missing key, a
// non-string value, or a blank string. Callers typically answer 401/400.
var ErrNoUserDetails = errors.New("user details not found in session")

// ErrInvalidUserDetails is returned by ReadSessionDetails when the stored
// TRX_USER_DETAILS value is present but cannot be decoded into the target.
// The underlying json error is wrapped and available through errors.Unwrap.
var ErrInvalidUserDetails = errors.New("user details are not valid JSON for the target")

// ReadSessionValue reads the value stored under key and asserts it to T. It is
// the one place that touches the session store on the read side, and the whole
// read runs under recover: gofiber/session v2 discards the provider error in
// Session.Get and hands back a Store whose core is nil, so a failing backend
// (e.g. memcached down) surfaces as a nil dereference in store.Get(key); a
// panic raised inside s.Get(ctx) itself (e.g. by a custom session id
// generator) is covered the same way. The nil-store check is defensive only.
// Any failure, a nil ctx/session, a missing key or a value of another type
// yields (zero T, false).
//
// ReadSessionString, ReadSessionBool and ReadSessionView are the typed
// shorthands; use this one directly for any other type an application stores
// itself. T must be the type the value has AFTER the session round trip, not
// the one that was stored: the store is msgpack-encoded and integers come back
// as int64 (or uint64 for unsigned), so a value stored as int is read with
// ReadSessionValue[int64], never [int].
func ReadSessionValue[T any](ctx *fiber.Ctx, s *session.Session, key string) (val T, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ReadSessionValue: panic recovered reading %q: %v", key, r)
			var zero T
			val, ok = zero, false
		}
	}()

	if ctx == nil || s == nil {
		return val, false
	}

	store := s.Get(ctx)
	if store == nil {
		return val, false
	}

	v, isT := store.Get(key).(T)
	if !isT {
		return val, false
	}

	return v, true
}

// ReadSessionString reads a string value from the request's session store
// without letting a degraded session take the request down. A missing key, a
// non-string value, or a blank string (only whitespace) yields ("", false);
// otherwise the string is returned as stored (not trimmed) with true.
func ReadSessionString(ctx *fiber.Ctx, s *session.Session, key string) (string, bool) {
	v, ok := ReadSessionValue[string](ctx, s, key)
	if !ok || len(strings.TrimSpace(v)) == 0 {
		return "", false
	}
	return v, true
}

// ReadSessionBool reads a bool value from the request's session store without
// letting a degraded session take the request down. A missing key or a value
// of another type yields (false, false); a stored false yields (false, true).
// Meant for flags an application stores itself (e.g. an IS_ADMIN it computed).
func ReadSessionBool(ctx *fiber.Ctx, s *session.Session, key string) (bool, bool) {
	return ReadSessionValue[bool](ctx, s, key)
}

// ReadSessionView returns the current view stored under the VIEW key — the
// value AuthorizationProxyCheck refreshes, on every request that goes through
// it, from the TRX_VIEW header or the ?view= query parameter. ("", false)
// when absent.
// ReadSessionDetails uses it as the fallback when the user details carry no
// appView; applications may read it directly for their own purposes.
func ReadSessionView(ctx *fiber.Ctx, s *session.Session) (string, bool) {
	return ReadSessionString(ctx, s, VIEW)
}

// ReadSessionDetails decodes the TRX_USER_DETAILS JSON that
// AuthorizationProxyCheck stored for this request into a new T and returns it
// by value. T is the application's own user/session-details struct (the
// library does not define that struct; each application owns its own):
//
//	sd, err := gofiber_session.ReadSessionDetails[models.SessionDetails](c, s)
//
// The JSON is produced by secureappproxy, so any struct whose json tags match
// the wire names (accountId, userId, appView, applicationFunctionsAccess, ...)
// works; fields the struct does not declare are ignored, fields the JSON does
// not carry keep their zero value.
//
// View fallback: the appView carried in the JSON is the value at
// authentication time, while the current view lives under the VIEW key that
// AuthorizationProxyCheck refreshes on every request it handles. When the JSON
// has no
// appView, or a blank one, the current view is written into the decoded T
// under the wire name "appView" (see patchAppView), so a T that declares that
// tag receives it and a T that does not is unaffected. The library never
// inspects T: json.Unmarshal does the mapping, as for every other field. VIEW
// is only read when the fallback is needed.
//
// Errors: ErrNoUserDetails (nothing usable stored), ErrInvalidUserDetails (the
// stored value is not valid JSON for T; the json error is wrapped and the
// failure is logged once with the target type). On any error the zero T is
// returned, never a partially decoded value. It never panics on a degraded
// session.
func ReadSessionDetails[T any](ctx *fiber.Ctx, s *session.Session) (T, error) {
	var zero T

	raw, ok := ReadSessionString(ctx, s, TRX_USER_DETAILS)
	if !ok {
		return zero, ErrNoUserDetails
	}
	data := []byte(raw)

	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("ReadSessionDetails: cannot decode %s into %T: %v", TRX_USER_DETAILS, out, err)
		return zero, fmt.Errorf("%w: %v", ErrInvalidUserDetails, err)
	}

	if !hasInformedAppView(data) {
		if view, ok := ReadSessionView(ctx, s); ok {
			patchAppView(&out, view)
		}
	}

	return out, nil
}

// appViewKey is the wire name secureappproxy uses for the view inside the
// TRX_USER_DETAILS JSON. It is the proxy's contract, identical for every app.
const appViewKey = "appView"

// hasInformedAppView scans the payload for a usable appView: present, a JSON
// string and not blank after TrimSpace. It decodes nothing else and allocates
// no map: one scan of the payload, one retained field, cheaper than decoding
// into a map. A
// missing key, a non-string value or whitespace all mean the fallback applies;
// so does a payload that is not a JSON object (the real decode has already
// reported that case before this runs).
func hasInformedAppView(data []byte) bool {
	var probe struct {
		AppView json.RawMessage `json:"appView"`
	}
	if json.Unmarshal(data, &probe) != nil || probe.AppView == nil {
		return false
	}
	var view string
	if json.Unmarshal(probe.AppView, &view) != nil {
		return false
	}
	return strings.TrimSpace(view) != ""
}

// patchAppView writes view into out's appView field, if it has one, by
// decoding a one-key document over the already decoded value: json.Unmarshal
// only touches the fields present in the document, so every other field of
// out is left exactly as it was. out is the *T from ReadSessionDetails; a T
// without the appView tag is left as is.
func patchAppView(out any, view string) {
	patch, err := json.Marshal(map[string]string{appViewKey: view})
	if err != nil {
		return
	}
	_ = json.Unmarshal(patch, out)
}
