# Session read helpers — safe read + decode of TRX_USER_DETAILS

**Status:** proposal (local branch `feature/session-details-reader`, not published)
**Scope:** additive only — five exported functions (two of them generic), two private helpers and two sentinel errors in a new file. Nothing published in v0.0.103 changes signature or behavior.

## Motivation

`AuthorizationProxyCheck` adopts the identity that secureappproxy injects in the `TRX_USER_DETAILS` header and stores it in the webapp's own session **as a string**. Reading that string back — safely — and decoding it into a struct is left to every webapp, and each one does it itself, in a few recurring shapes (`GetSessionFromStore`, `FetchSessionDetails`, plus per-handler copies in `/getsessiondetails`, `SaveUserLogAuditAction`, `AddAccountToHeader`/`AddSessionToHeader`).

Those copies share two latent panics. First, a failing session backend: gofiber/session v2's `Session.Get` discards the provider error (`fstore, _ := s.core.Get(...)`) and returns a `Store` whose core is nil, so the next `store.Get(key)` dereferences nil — with the memcached provider the apps use, any error other than a cache miss takes this path. Second, an unchecked `.(string)` assertion on the stored value. In September 2026 the fix (a local `GetStringFromSessionStore` with `defer/recover`) had to be applied repo by repo. The library already owns the storing side of this contract; it should own the reading side too, so the next fix lands once, in one version bump.

## Constraint: additive, plain, no behavior change

- New file `pkg/gofiber-session/sessiondetails.go` (+ `_test.go`). No edits to `gofiber-session.go`, `utils.go` (`getSessionString` stays as is), `models.go` (the 8-field legacy `SessionDetails` stays, unused by these functions).
- Applications keep their own `models.SessionDetails`. The decoder targets whatever struct the caller passes; wire names come from the proxy and are identical for every app.
- No reflection, no interfaces the applications must implement, no new dependencies. `github.com/valyala/fasthttp` and `github.com/fasthttp/session/v2` are already transitive dependencies (the latter is gofiber/session's provider interface); the test file imports both directly, which only moves them from `// indirect` to direct in `go.mod` if `go mod tidy` is run.

## API

```go
// The single implementation of the read side — nil checks, recover around
// s.Get(ctx)/store.Get(key) and the typed assertion. (zero T, false) on any
// failure. Exported for types the shorthands below do not cover; T is the
// post-round-trip type (integers come back as int64/uint64, see below).
func ReadSessionValue[T any](ctx *fiber.Ctx, s *session.Session, key string) (T, bool)

// Reads a string key. Blank (whitespace-only) counts as not stored → ("", false);
// otherwise the string as stored (untrimmed).
func ReadSessionString(ctx *fiber.Ctx, s *session.Session, key string) (string, bool)

// Reads a bool key an application stored itself (e.g. a computed IS_ADMIN).
// (false, false) when missing or not a bool; a stored false is (false, true).
func ReadSessionBool(ctx *fiber.Ctx, s *session.Session, key string) (bool, bool)

// The current view kept under the VIEW key (TRX_VIEW header / ?view= query):
// ReadSessionString(ctx, s, VIEW). Also what ReadSessionDetails falls back to.
func ReadSessionView(ctx *fiber.Ctx, s *session.Session) (string, bool)

// Decodes TRX_USER_DETAILS into a new T (the app's struct, not a pointer) and
// returns it by value, then applies the view fallback on the decoded value
// (see below). Zero T on error.
func ReadSessionDetails[T any](ctx *fiber.Ctx, s *session.Session) (T, error)

// Private: the "is appView already usable?" question on the raw payload — key
// present, a JSON string, not blank after TrimSpace. One scan, no map.
func hasInformedAppView(data []byte) bool

// Private: writes view into out's appView field by decoding {"appView":view}
// over the already decoded value; json.Unmarshal only touches present fields.
func patchAppView(out any, view string)

var ErrNoUserDetails      // nothing usable stored (no session/store/key, non-string, blank)
var ErrInvalidUserDetails // stored value is not valid JSON for T (json error wrapped)
```

### Naming

`ReadSessionDetails` keeps the `ReadSession` prefix of its siblings (`ReadSessionValue` / `ReadSessionString` / `ReadSessionBool` / `ReadSessionView`): all five read from the request's session, the first four return a stored value as is and this one decodes the `TRX_USER_DETAILS` JSON. "Details" names what the proxy stores under that key, not a library type: the struct it fills belongs to each application, and the library's own legacy `SessionDetails` (used only by `AuthRequire`) is unrelated and not the target. The type parameter makes that explicit at every call site (`ReadSessionDetails[models.SessionDetails](c, s)`).

### Behavior of `ReadSessionValue[T]`, `ReadSessionString`, `ReadSessionBool`, `ReadSessionView`

1. `ctx == nil` or `s == nil` → `(zero, false)`.
2. `s.Get(ctx)` and `store.Get(key)` under one `defer/recover`: a provider error leaves the store with a nil core and `store.Get(key)` panics (see Motivation); a panic inside `s.Get(ctx)` itself is covered too. A recovered panic is logged once (`ReadSessionValue: panic recovered reading "<key>": …`). The `nil` store check is defensive only: gofiber/session never returns a nil `*Store`.
3. `store.Get(key).(T)` with `ok`; a value of another type → `(zero, false)`.
4. `ReadSessionString` adds the string rule: blank after `TrimSpace` → `("", false)`; otherwise the stored string, untrimmed. `ReadSessionBool` returns the assertion as is, so a stored `false` is `(false, true)`. `ReadSessionView` is `ReadSessionString(ctx, s, VIEW)`.

The generic keeps the recover/assertion block in one place; `ReadSessionString`, `ReadSessionBool` and `ReadSessionView` expose it without a type parameter, and `ReadSessionValue[T]` is exported for any other type an application stores itself. Its `T` is the type the value has after the session round trip, not the one that was stored: the store is msgpack-encoded (fasthttp/session `Dict`, `encoding.go`) and msgp decodes every integer inside an `interface{}` as `int64` or `uint64` whatever Go type was stored (`read_bytes.go`, `IntType`/`UintType`), so a value stored as `int` is read with `ReadSessionValue[int64]` and `ReadSessionValue[int]` yields `(0, false)`. No typed integer shorthand is offered for that reason; no application stores numbers today (only strings, and `IS_ADMIN` as bool).

### Behavior of `ReadSessionDetails[T]`

1. `ReadSessionString(ctx, s, TRX_USER_DETAILS)`; `!ok` → `(zero T, ErrNoUserDetails)`.
2. `json.Unmarshal` into a fresh `T`; error → logged once (`ReadSessionDetails: cannot decode TRX_USER_DETAILS into <type>: …`) and returned as `(zero T, fmt.Errorf("%w: %v", ErrInvalidUserDetails, err))`. A partially decoded value never escapes.
3. Fields the struct declares and the JSON carries are copied; JSON keys the struct lacks are ignored; struct fields the JSON lacks keep their zero value (app-local fields such as `IsAdmin`, `MenuAccess`, `Features` are filled by the app afterwards, as today).
4. View fallback (see next section): if `hasInformedAppView(data)` is false, `VIEW` is read once (`ReadSessionView`) and, when present, `patchAppView(&out, view)` writes it into the decoded value under the wire name `appView`.
5. Callers write the type parameter (`ReadSessionDetails[models.SessionDetails](c, s)`): Go does not infer `T` from a return value. In exchange they neither declare the variable first nor pass a pointer.

### The view fallback goes through json.Unmarshal, never through the struct

The JSON carries `appView` as it was at authentication time; the current view lives under the separate `VIEW` key that `AuthorizationProxyCheck` refreshes on every request it handles (WebSocket upgrades and open resources skip it). Every application applies the same rule in its `/getsessiondetails` handler: a blank `appView` is replaced by `VIEW`. The SPA routes on it (`app.js` picks the window from `sessionDetails.appView`).

Writing that value into a field of a struct the library does not know would need reflection, an interface every model implements, or an accessor callback passed on every call. All three were rejected. Instead the library relies on the wire name: `appView` is not an application field, it is the name secureappproxy uses, identical in every app, and the library already owns the other two names in this contract (`TRX_USER_DETAILS`, `VIEW`). Two private helpers, both built on `encoding/json` behavior alone:

1. `hasInformedAppView(data)` decodes the payload into a probe struct that declares only `appView` as `json.RawMessage`. One scan of the payload, nothing else stored, no map allocated. It returns true only when the key is present, holds a JSON string and is non-blank after `TrimSpace`. On this path, the common one, `VIEW` is **not** read and nothing else happens.
2. Otherwise `VIEW` is read once (`ReadSessionView`). Absent → the decoded value is returned as is. Present → `patchAppView(&out, view)` marshals `{"appView": view}` (a constant-size document, which is also where the Go string becomes a quoted, escaped JSON string) and decodes it **over** the already decoded `out`. `json.Unmarshal` into an existing value only touches the fields present in the document, so `appView` is set and every other field is left exactly as it was.

Cost: two scans of the payload in every case (the real decode and the probe), plus a constant-size patch when the fallback applies. The payload is never re-encoded. For this approach two scans is the minimum: the real decode is unavoidable, and knowing whether `appView` is informed requires one inspection of the payload, since `out.AppView` cannot be read for an unknown `T` without reflection.

Consequences, deliberate: the mapping into `T` is still done by `json.Unmarshal` alone, so a `T` without an `appView` tag is unaffected (the patch is ignored) and a `T` with `json:"appView,omitempty"` works as any other. An `appView` that is present but not a string fails the real decode with `ErrInvalidUserDetails`, like any other mistyped field; the fallback never runs on an invalid payload. The fallback now reaches **every** read, not only `/getsessiondetails`: the audit log and header stamping get a filled `AppView` they do not use, and in accountmanagementwebapp `HasAccessType`, which decides on `AppView` through a helper that had no fallback, becomes consistent with the SPA (to be stated in that app's PR).

## What this does NOT do (out of scope)

- Does not validate the JSON against a schema or require any field.
- Does not read the `TRX_USER_DETAILS` **header** — only the session value that `AuthorizationProxyCheck` stored. Requests that bypass the middleware get `ErrNoUserDetails`.
- Does not fill `appView` when `VIEW` is absent, and does not overwrite an informed `appView`.
- Does not unify the applications' `SessionDetails` models or the `SessionResponse` they return to their SPAs. A later step may add a canonical struct matching the proxy's wire shape; `ReadSessionDetails[T]` already accepts an app struct that embeds it.
- Does not change `getSessionString`, `AuthorizationProxyCheck`, `AuthRequire`, or the legacy `SessionDetails`.

## File layout

```
pkg/gofiber-session/
  sessiondetails.go           ReadSessionValue[T], ReadSessionString, ReadSessionBool, ReadSessionView, ReadSessionDetails[T], hasInformedAppView + patchAppView (private), errors
  sessiondetails_test.go      table tests (see Test plan)
docs/superpowers/specs/2026-09-16-session-details-reader-design.md   this document
```

## Test plan (`go test ./...`)

`ReadSessionValue[T]`: a value stored as `int` reads as `int64` and not as `int` (the msgpack round trip); a string reads as string; a missing key is `(zero, false)`.

`ReadSessionString`: missing key; non-string value (42); empty string; whitespace only; string preserved untrimmed; nil ctx; nil session; a session id generator that panics inside `s.Get` (`session.Config{Generator: panic}`); a provider whose `Get` returns an error (the real memcached-down path: nil core, panic in `store.Get`).

`ReadSessionBool`: missing key; stored true; stored false (a value, `ok == true`); string and number under the key are not a bool; degraded session (panicking generator, failing provider) and nil ctx never panic.

`ReadSessionView`: present; absent.

`ReadSessionDetails[T]`: decodes the fields the target declares (subset of the wire) and ignores `applicationFunctionsAccess`/`impersonator`; app-local field keeps its zero value; missing and blank `appView` take the stored `VIEW`; informed `appView` is kept over `VIEW`; no `VIEW` stored leaves `appView` blank; a non-string `appView` fails the decode with `ErrInvalidUserDetails`; a target without an `appView` field decodes unaffected; `ErrNoUserDetails` and zero `T` for missing and non-string values; wrapped `ErrInvalidUserDetails` and zero `T` for malformed JSON (no partial decode leaks); degraded session (panicking generator, failing provider) → `ErrNoUserDetails`, never a panic.

`hasInformedAppView` (unit, raw bytes): missing key, empty string, whitespace only, `null`, number, object, malformed JSON and a non-object are not informed; a non-blank string is, with or without surrounding spaces, alone or among other fields.

`patchAppView` (unit): sets `appView` and leaves every other field untouched (including a pointer field); overwrites whatever `appView` held, because the decision belongs to `hasInformedAppView`; a target without the tag is left as is; the view is JSON-escaped on the way in (quotes, backslashes, angle brackets survive); a non-pointer or nil target is a no-op, never a panic.


## Consumer migration (per webapp, after `v0.0.104`)

```go
// before
userDetailsStr, ok := GetStringFromSessionStore(c, s, common.TRX_USER_DETAILS)
if !ok { return fmt.Errorf("User Details Not Found"), nil }
sd := models.SessionDetails{}
if err := json.Unmarshal([]byte(userDetailsStr), &sd); err != nil { return err, nil }
if strings.TrimSpace(sd.AppView) == "" {
    if view, ok := GetStringFromSessionStore(c, s, common.VIEW); ok { sd.AppView = view }
}
return nil, &sd

// after
sd, err := gofiber_session.ReadSessionDetails[models.SessionDetails](c, s)
if err != nil { return err, nil }
return nil, &sd
```

The local `GetStringFromSessionStore` is deleted, and so are the per-app `AppView`/`VIEW` fallback blocks (the library applies the rule) and `GetBoolFromSessionStore` where it exists (incidentbomanagementwebapp, ppewebapp: `ReadSessionBool(c, srvSession, IS_ADMIN)`); handler signatures, `/getsessiondetails`, `AddSessionToHeader` and `SaveUserLogAuditAction` keep their contracts. Every read treats any error the same way (deny / skip). Deliberate behavior change: handlers that used to ignore a JSON decode error (`json.Unmarshal` without checking, answering 200 with empty details) now answer 400; the case is unreachable through the proxy, which always serializes valid JSON, and the failure is logged by the library. Verified before publishing by building a consumer against the branch with a temporary `replace github.com/transactrx/trx-gofiber-session => ../../trx-gofiber-session` (never committed).

## Backward compatibility

Purely additive. Consumers on v0.0.103 that bump without migrating compile and behave identically.

## Open questions

- Whether to also export a canonical `ProxySessionDetails` struct matching the proxy's wire shape in a later version (would let apps embed it and drop their field lists). Not needed for this change.
