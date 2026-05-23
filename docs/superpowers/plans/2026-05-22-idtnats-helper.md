# idtnats Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Commit policy:** Per user policy ([[feedback-no-commits]]) do NOT run `git commit` without explicit user approval. Stage changes when steps say so, but PAUSE before each commit and ask the user. The commit messages in the plan are exact text to use when the user approves.

**Goal:** Add a thin sub-package `pkg/gofiber-session/idtnats` to `trx-gofiber-session` exposing `BuildMsgWithIDT`, `BuildMsgWithIDTExplicit`, `PublishWithIDT`, `PublishWithIDTExplicit` so webapps can fan out HTTP-inbound requests to NATS agents without hand-wiring IDT + caller-chain headers.

**Architecture:** New sub-package isolates the `nats.go` dependency from the core `pkg/gofiber-session` (which stays transport-agnostic). The four helpers wrap the existing low-level primitives (`ReadIDT`, `ReadCallerChain`, `AppendCallerChain`, `BuildOutboundIDTHeaders`) into one ctx-driven call.

**Tech Stack:** Go 1.x, gofiber/fiber/v2 (already direct dep), nats-io/nats.go (NEW direct dep — only in `idtnats` sub-package), valyala/fasthttp (already transitive, promoted to direct for tests).

**Spec:** `docs/superpowers/specs/2026-05-22-idtnats-helper-design.md`

---

## File Structure

```
trx-gofiber-session/
├── go.mod                                                  # MODIFY (add nats.go + promote fasthttp to direct)
├── pkg/
│   └── gofiber-session/
│       ├── idt.go                                          # UNCHANGED
│       └── idtnats/
│           ├── idtnats.go                                  # CREATE (~80 LoC)
│           └── idtnats_test.go                             # CREATE (~180 LoC)
```

**Boundary:** `idtnats` depends on `pkg/gofiber-session` (for the primitives) and `nats.go`. Nothing in the core depends on `idtnats`. Other consumers (HTTP, gRPC) can ignore the sub-package entirely.

---

## Pre-Flight

- [ ] **Step 0: Verify working tree state**

```bash
cd ~/Documents/TransactRx/GitHub/trx-gofiber-session
git status
git rev-parse --abbrev-ref HEAD
```

Expected: on branch `inter-app-token-communication` (or a fresh branch off it), working tree clean. If dirty, stop and ask user.

- [ ] **Step 0a: Confirm starting commit**

```bash
git rev-parse --short HEAD
```

Expected: `ca948e5` (the existing IDT-helpers commit) or later. Record this hash for rollback if needed.

---

## Task 1: Add nats.go dependency and promote fasthttp

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1.1: Add nats.go**

```bash
cd ~/Documents/TransactRx/GitHub/trx-gofiber-session
go get github.com/nats-io/nats.go@latest
```

Expected: `go.mod` gains `require github.com/nats-io/nats.go vX.Y.Z` (latest); `go.sum` updated.

- [ ] **Step 1.2: Promote fasthttp to direct dep (needed for tests)**

```bash
go get github.com/valyala/fasthttp@latest
```

Expected: `// indirect` comment removed from the `fasthttp` line in `go.mod`.

- [ ] **Step 1.3: Tidy**

```bash
go mod tidy
```

Expected: no unrelated deltas. If `go mod tidy` removes nats.go because no source uses it yet, that's fine — Task 3 will add a source file that imports it.

- [ ] **Step 1.4: Verify**

```bash
go build ./...
```

Expected: success (nothing has changed in any .go file yet, so this just confirms the module graph still resolves).

- [ ] **Step 1.5: Stage**

```bash
git add go.mod go.sum
```

PAUSE — ask user before committing. Suggested commit message:
```
chore: add nats.go + fasthttp direct deps for idtnats sub-package
```

---

## Task 2: Create idtnats package skeleton with BuildMsgWithIDTExplicit

**Why this order:** `BuildMsgWithIDTExplicit` is the simpler primitive (no ctx) and is what `BuildMsgWithIDT` will delegate to. Build the foundation first.

**Files:**
- Create: `pkg/gofiber-session/idtnats/idtnats.go`
- Create: `pkg/gofiber-session/idtnats/idtnats_test.go`

- [ ] **Step 2.1: Write failing test for BuildMsgWithIDTExplicit**

Create `pkg/gofiber-session/idtnats/idtnats_test.go`:

```go
package idtnats

import (
	"testing"

	"github.com/nats-io/nats.go"
)

func TestBuildMsgWithIDTExplicit_AttachesIDTAndChain(t *testing.T) {
	msg := BuildMsgWithIDTExplicit("trx.app.subject", "IDT-abc.cipher", "upstream>self", nil, []byte("body"))
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if msg.Subject != "trx.app.subject" {
		t.Errorf("subject: got %q want %q", msg.Subject, "trx.app.subject")
	}
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-abc.cipher" {
		t.Errorf("X-TRX-IDT: got %q want %q", got, "IDT-abc.cipher")
	}
	if got := msg.Header.Get("X-TRX-Caller-Chain"); got != "upstream>self" {
		t.Errorf("X-TRX-Caller-Chain: got %q want %q", got, "upstream>self")
	}
	if string(msg.Data) != "body" {
		t.Errorf("data: got %q want %q", msg.Data, "body")
	}
}

func TestBuildMsgWithIDTExplicit_NoIDTOmitsBothHeaders(t *testing.T) {
	msg := BuildMsgWithIDTExplicit("subj", "", "ignored-when-no-idt", nil, nil)
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if v := msg.Header.Get("X-TRX-IDT"); v != "" {
		t.Errorf("X-TRX-IDT should be empty, got %q", v)
	}
	if v := msg.Header.Get("X-TRX-Caller-Chain"); v != "" {
		t.Errorf("X-TRX-Caller-Chain should be empty, got %q", v)
	}
}

func TestBuildMsgWithIDTExplicit_EmptySubjectReturnsNil(t *testing.T) {
	msg := BuildMsgWithIDTExplicit("", "IDT-x", "chain", nil, []byte("data"))
	if msg != nil {
		t.Errorf("expected nil msg for empty subject, got %+v", msg)
	}
}

func TestBuildMsgWithIDTExplicit_ExtraHeadersPreserved(t *testing.T) {
	extra := map[string]string{
		"x-trx-account-id": "acct123",
		"x-trx-user-id":    "user456",
	}
	msg := BuildMsgWithIDTExplicit("subj", "IDT-x", "self", extra, nil)
	if got := msg.Header.Get("x-trx-account-id"); got != "acct123" {
		t.Errorf("account header: got %q want %q", got, "acct123")
	}
	if got := msg.Header.Get("x-trx-user-id"); got != "user456" {
		t.Errorf("user header: got %q want %q", got, "user456")
	}
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-x" {
		t.Errorf("idt header lost: got %q", got)
	}
}

func TestBuildMsgWithIDTExplicit_IDTOverridesExtraHeaderConflict(t *testing.T) {
	extra := map[string]string{
		"X-TRX-IDT":          "stale-from-extra",
		"X-TRX-Caller-Chain": "stale-chain-from-extra",
	}
	msg := BuildMsgWithIDTExplicit("subj", "IDT-fresh", "fresh-chain", extra, nil)
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-fresh" {
		t.Errorf("expected IDT helper to win conflict, got %q", got)
	}
	if got := msg.Header.Get("X-TRX-Caller-Chain"); got != "fresh-chain" {
		t.Errorf("expected chain helper to win conflict, got %q", got)
	}
	// Sanity: nats.Header is a multi-value map; helper should not have left
	// the stale value behind.
	if vals := msg.Header.Values("X-TRX-IDT"); len(vals) != 1 {
		t.Errorf("expected 1 value for X-TRX-IDT after override, got %d: %v", len(vals), vals)
	}
}

func TestBuildMsgWithIDTExplicit_NilBodyOk(t *testing.T) {
	msg := BuildMsgWithIDTExplicit("subj", "IDT-x", "self", nil, nil)
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if msg.Data != nil {
		t.Errorf("expected nil data, got %v", msg.Data)
	}
}

// Reference for later: nats.Header is just net/textproto.MIMEHeader, so
// Set/Get behave as documented. No special init beyond the literal below.
var _ = nats.Header{}
```

- [ ] **Step 2.2: Run tests to verify failure (compile error)**

```bash
cd ~/Documents/TransactRx/GitHub/trx-gofiber-session
go test ./pkg/gofiber-session/idtnats/...
```

Expected: FAIL with `undefined: BuildMsgWithIDTExplicit` (or similar — the file doesn't exist yet).

- [ ] **Step 2.3: Create idtnats.go with BuildMsgWithIDTExplicit**

Create `pkg/gofiber-session/idtnats/idtnats.go`:

```go
// Package idtnats wires the IDT helpers from trx-gofiber-session into a
// NATS-based fan-out. Splitting it from the core pkg/gofiber-session keeps the
// core nats-dep-free: consumers that don't talk NATS (HTTP-only, gRPC) never
// pull github.com/nats-io/nats.go into their import graph.
package idtnats

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/nats-io/nats.go"

	gofibersession "github.com/transactrx/trx-gofiber-session/pkg/gofiber-session"
)

// ErrEmptySubject is returned by Publish helpers when called with subject == "".
var ErrEmptySubject = errors.New("idtnats: empty subject")

// BuildMsgWithIDTExplicit constructs a *nats.Msg with extraHeaders plus the
// X-TRX-IDT and X-TRX-Caller-Chain headers derived from the passed-in idt and
// chain. Use this variant when there is no *fiber.Ctx — typically an agent or
// webapp that received its inbound IDT over NATS headers and is forwarding
// downstream. Caller is responsible for AppendCallerChain on the inbound chain
// before calling.
//
// Returns nil if subject is empty. If idt is empty, neither IDT header nor
// the chain header is set (matches BuildOutboundIDTHeaders' nil-map contract)
// — that preserves the documented "IDT off" pass-through.
//
// When extraHeaders contains X-TRX-IDT or X-TRX-Caller-Chain, the IDT-derived
// values overwrite them. The IDT helper is the canonical source for those
// two headers.
func BuildMsgWithIDTExplicit(subject, idt, chain string, extraHeaders map[string]string, body []byte) *nats.Msg {
	if subject == "" {
		return nil
	}
	header := nats.Header{}
	for k, v := range extraHeaders {
		header.Set(k, v)
	}
	for k, v := range gofibersession.BuildOutboundIDTHeaders(idt, chain) {
		header.Set(k, v) // Set replaces, ensuring no stale duplicate from extraHeaders.
	}
	return &nats.Msg{
		Subject: subject,
		Header:  header,
		Data:    body,
	}
}

// Placeholder — Task 3 will add BuildMsgWithIDT.
// Placeholder — Task 4 will add PublishWithIDT and PublishWithIDTExplicit.

// _ assertion to keep fiber import live until BuildMsgWithIDT lands.
var _ = (*fiber.Ctx)(nil)
```

- [ ] **Step 2.4: Run tests to verify pass**

```bash
go test ./pkg/gofiber-session/idtnats/... -v
```

Expected: 6 tests PASS. If `nats.Header.Values` is unavailable in the pinned nats.go version, replace the assertion in `TestBuildMsgWithIDTExplicit_IDTOverridesExtraHeaderConflict` with `if len(msg.Header["X-Trx-Idt"]) != 1` (textproto.MIMEHeader canonicalizes keys).

- [ ] **Step 2.5: Stage**

```bash
git add pkg/gofiber-session/idtnats/idtnats.go pkg/gofiber-session/idtnats/idtnats_test.go go.mod go.sum
```

PAUSE — ask user before committing. Suggested commit message:
```
feat(idtnats): add BuildMsgWithIDTExplicit helper

First slice of the idtnats sub-package: explicit-args variant that lets
NATS-inbound callers attach IDT + caller-chain to an outbound nats.Msg.
The ctx-driven BuildMsgWithIDT and the Publish variants land in
subsequent commits.
```

---

## Task 3: Add BuildMsgWithIDT (ctx-driven variant)

**Files:**
- Modify: `pkg/gofiber-session/idtnats/idtnats.go`
- Modify: `pkg/gofiber-session/idtnats/idtnats_test.go`

- [ ] **Step 3.1: Add test helper and failing tests**

Append to `pkg/gofiber-session/idtnats/idtnats_test.go`:

```go
import (
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// newCtxWithHeaders builds a *fiber.Ctx whose inbound request has the given
// headers set. Standard Fiber test pattern. The fiber.App is created fresh
// per call to keep tests independent.
func newCtxWithHeaders(t *testing.T, headers map[string]string) *fiber.Ctx {
	t.Helper()
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	ctx := app.AcquireCtx(fctx)
	for k, v := range headers {
		ctx.Request().Header.Set(k, v)
	}
	t.Cleanup(func() { app.ReleaseCtx(ctx) })
	return ctx
}

func TestBuildMsgWithIDT_NoInboundChain(t *testing.T) {
	ctx := newCtxWithHeaders(t, map[string]string{
		"TRX_IDT": "IDT-abc.cipher",
	})
	msg := BuildMsgWithIDT(ctx, "subj", "webapp1", nil, []byte("body"))
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-abc.cipher" {
		t.Errorf("X-TRX-IDT: got %q", got)
	}
	if got := msg.Header.Get("X-TRX-Caller-Chain"); got != "webapp1" {
		t.Errorf("chain: got %q want %q (no inbound + self)", got, "webapp1")
	}
}

func TestBuildMsgWithIDT_WithInboundChainExtends(t *testing.T) {
	ctx := newCtxWithHeaders(t, map[string]string{
		"TRX_IDT":            "IDT-x",
		"X-TRX-Caller-Chain": "upstream",
	})
	msg := BuildMsgWithIDT(ctx, "subj", "webapp1", nil, nil)
	if got := msg.Header.Get("X-TRX-Caller-Chain"); got != "upstream>webapp1" {
		t.Errorf("chain: got %q want %q", got, "upstream>webapp1")
	}
}

func TestBuildMsgWithIDT_NoIDTOnRequestOmitsHeaders(t *testing.T) {
	ctx := newCtxWithHeaders(t, nil) // no TRX_IDT, no chain
	extra := map[string]string{"x-trx-account-id": "acct"}
	msg := BuildMsgWithIDT(ctx, "subj", "webapp1", extra, nil)
	if v := msg.Header.Get("X-TRX-IDT"); v != "" {
		t.Errorf("X-TRX-IDT should be empty when proxy did not inject, got %q", v)
	}
	if v := msg.Header.Get("X-TRX-Caller-Chain"); v != "" {
		t.Errorf("chain should be empty when no IDT (BuildOutboundIDTHeaders returns nil), got %q", v)
	}
	if v := msg.Header.Get("x-trx-account-id"); v != "acct" {
		t.Errorf("extra header lost: got %q", v)
	}
}

func TestBuildMsgWithIDT_EmptySubjectReturnsNil(t *testing.T) {
	ctx := newCtxWithHeaders(t, map[string]string{"TRX_IDT": "IDT-x"})
	if msg := BuildMsgWithIDT(ctx, "", "webapp1", nil, nil); msg != nil {
		t.Errorf("expected nil for empty subject, got %+v", msg)
	}
}

func TestBuildMsgWithIDT_NilCtxIsSafe(t *testing.T) {
	// ReadIDT and ReadCallerChain are nil-safe; helper should be too. With
	// nil ctx, no IDT is read, chain becomes just selfAppId — but with no
	// IDT, BuildOutboundIDTHeaders returns nil, so no headers set.
	msg := BuildMsgWithIDT(nil, "subj", "webapp1", nil, nil)
	if msg == nil {
		t.Fatal("expected non-nil msg even with nil ctx")
	}
	if v := msg.Header.Get("X-TRX-IDT"); v != "" {
		t.Errorf("expected no IDT header with nil ctx, got %q", v)
	}
}
```

Also remove the placeholder `var _ = (*fiber.Ctx)(nil)` line from `idtnats.go` since fiber is now used by the real function. (Update in Step 3.2.)

- [ ] **Step 3.2: Run tests to verify failure**

```bash
go test ./pkg/gofiber-session/idtnats/... -v
```

Expected: 5 new tests FAIL with `undefined: BuildMsgWithIDT`. Existing 6 tests still PASS.

- [ ] **Step 3.3: Implement BuildMsgWithIDT**

In `pkg/gofiber-session/idtnats/idtnats.go`, replace the placeholder block

```go
// Placeholder — Task 3 will add BuildMsgWithIDT.
// Placeholder — Task 4 will add PublishWithIDT and PublishWithIDTExplicit.

// _ assertion to keep fiber import live until BuildMsgWithIDT lands.
var _ = (*fiber.Ctx)(nil)
```

with:

```go
// BuildMsgWithIDT constructs a *nats.Msg for the common HTTP-inbound →
// NATS-outbound fan-out. It reads the IDT and inbound caller-chain from ctx
// (the request the proxy already authenticated), appends selfAppId, and
// attaches the resulting X-TRX-IDT + X-TRX-Caller-Chain headers alongside
// extraHeaders.
//
// Returns nil if subject is empty. Safe to call with a nil ctx (degrades to
// "no IDT available", which downstream agents may accept or deny per their
// own IDT_FAIL_OPEN policy).
//
// When extraHeaders contains X-TRX-IDT or X-TRX-Caller-Chain, the helper's
// derived values overwrite them.
func BuildMsgWithIDT(ctx *fiber.Ctx, subject, selfAppId string, extraHeaders map[string]string, body []byte) *nats.Msg {
	idt := gofibersession.ReadIDT(ctx)
	chain := gofibersession.AppendCallerChain(gofibersession.ReadCallerChain(ctx), selfAppId)
	return BuildMsgWithIDTExplicit(subject, idt, chain, extraHeaders, body)
}
```

- [ ] **Step 3.4: Run tests to verify pass**

```bash
go test ./pkg/gofiber-session/idtnats/... -v
```

Expected: all 11 tests PASS.

- [ ] **Step 3.5: Stage**

```bash
git add pkg/gofiber-session/idtnats/idtnats.go pkg/gofiber-session/idtnats/idtnats_test.go
```

PAUSE — ask user before committing. Suggested commit message:
```
feat(idtnats): add ctx-driven BuildMsgWithIDT

Reads TRX_IDT + X-TRX-Caller-Chain from inbound fiber.Ctx, appends
selfAppId to the chain, and delegates to BuildMsgWithIDTExplicit.
Closes the boilerplate gap that powered the IDT-forwarding pattern in
powerlineClaimSearchWebApp's runOneTurn.
```

---

## Task 4: Add Publish helpers

**Files:**
- Modify: `pkg/gofiber-session/idtnats/idtnats.go`
- Modify: `pkg/gofiber-session/idtnats/idtnats_test.go`

- [ ] **Step 4.1: Write failing tests for empty-subject error paths**

Append to `pkg/gofiber-session/idtnats/idtnats_test.go`:

```go
func TestPublishWithIDTExplicit_EmptySubjectReturnsError(t *testing.T) {
	// We pass nil *nats.Conn deliberately. If the empty-subject guard works,
	// the helper returns ErrEmptySubject before touching the nil conn.
	err := PublishWithIDTExplicit(nil, "", "IDT-x", "chain", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
	if !errors.Is(err, ErrEmptySubject) {
		t.Errorf("expected ErrEmptySubject, got %v", err)
	}
}

func TestPublishWithIDT_EmptySubjectReturnsError(t *testing.T) {
	ctx := newCtxWithHeaders(t, map[string]string{"TRX_IDT": "IDT-x"})
	err := PublishWithIDT(ctx, nil, "", "webapp1", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
	if !errors.Is(err, ErrEmptySubject) {
		t.Errorf("expected ErrEmptySubject, got %v", err)
	}
}
```

Add `"errors"` to the test file's import block.

- [ ] **Step 4.2: Run tests to verify failure**

```bash
go test ./pkg/gofiber-session/idtnats/... -v
```

Expected: 2 new tests FAIL with `undefined: PublishWithIDT` / `undefined: PublishWithIDTExplicit`. Existing 11 tests still PASS.

- [ ] **Step 4.3: Implement publish helpers**

Append to `pkg/gofiber-session/idtnats/idtnats.go`:

```go
// PublishWithIDT builds the message via BuildMsgWithIDT and publishes it on
// nc. Fire-and-forget — no reply, no retry, no timeout. Callers that need
// request/reply or streaming should use BuildMsgWithIDT + their own
// nc.RequestMsg/streaming wrapper.
//
// Returns ErrEmptySubject if subject is empty (before touching nc).
func PublishWithIDT(ctx *fiber.Ctx, nc *nats.Conn, subject, selfAppId string, extraHeaders map[string]string, body []byte) error {
	msg := BuildMsgWithIDT(ctx, subject, selfAppId, extraHeaders, body)
	if msg == nil {
		return ErrEmptySubject
	}
	return nc.PublishMsg(msg)
}

// PublishWithIDTExplicit is the ctx-free variant for NATS-inbound mid-chain
// publishers. See BuildMsgWithIDTExplicit for chain semantics.
func PublishWithIDTExplicit(nc *nats.Conn, subject, idt, chain string, extraHeaders map[string]string, body []byte) error {
	msg := BuildMsgWithIDTExplicit(subject, idt, chain, extraHeaders, body)
	if msg == nil {
		return ErrEmptySubject
	}
	return nc.PublishMsg(msg)
}
```

- [ ] **Step 4.4: Run tests to verify pass**

```bash
go test ./pkg/gofiber-session/idtnats/... -v
```

Expected: all 13 tests PASS.

- [ ] **Step 4.5: Stage**

```bash
git add pkg/gofiber-session/idtnats/idtnats.go pkg/gofiber-session/idtnats/idtnats_test.go
```

PAUSE — ask user before committing. Suggested commit message:
```
feat(idtnats): add PublishWithIDT and PublishWithIDTExplicit

Thin wrappers over Build* + nc.PublishMsg with an empty-subject guard.
Fire-and-forget; request/reply variants intentionally deferred until a
real consumer needs them.
```

---

## Task 5: Verification sweep

- [ ] **Step 5.1: Build everything**

```bash
cd ~/Documents/TransactRx/GitHub/trx-gofiber-session
go build ./...
```

Expected: success.

- [ ] **Step 5.2: Vet**

```bash
go vet ./...
```

Expected: clean.

- [ ] **Step 5.3: Full test run**

```bash
go test ./... -v
```

Expected: all tests PASS, including any pre-existing tests in other packages.

- [ ] **Step 5.4: Confirm core stayed nats-dep-free**

```bash
go list -deps ./pkg/gofiber-session | grep nats || echo "OK — core has no nats deps"
```

Expected: prints `OK — core has no nats deps`. If anything matches, a stray import leaked from idtnats into the core; bisect and fix before proceeding.

- [ ] **Step 5.5: Confirm idtnats imports are minimal**

```bash
go list -deps ./pkg/gofiber-session/idtnats | grep -E "nats|fiber|fasthttp|transactrx" | sort
```

Expected output includes only:
- `github.com/gofiber/fiber/v2` (and its deps)
- `github.com/nats-io/nats.go` (and its deps)
- `github.com/transactrx/trx-gofiber-session/pkg/gofiber-session`
- `github.com/valyala/fasthttp` (transitive through fiber)

No surprises. If a heavy/odd dep shows up, investigate before shipping.

- [ ] **Step 5.6: Stage** (no changes expected; this task is verify-only)

If any fix was needed in steps 5.1–5.5, stage and PAUSE for commit approval with a message describing the fix. Otherwise skip to Task 6.

---

## Task 6: README pointer (optional — only if a README exists in the package)

- [ ] **Step 6.1: Check for existing README**

```bash
ls ~/Documents/TransactRx/GitHub/trx-gofiber-session/README* 2>/dev/null
```

If no README exists: skip Task 6 entirely.

If a README exists: add one short section pointing at `idtnats` so future devs discover it. Sample text (adjust phrasing to match the repo's existing tone):

```markdown
### idtnats — NATS publish helper with IDT forwarding

`pkg/gofiber-session/idtnats` wraps `BuildOutboundIDTHeaders` into a one-call
fan-out for webapps that forward IDT to agents over NATS:

```go
import "github.com/transactrx/trx-gofiber-session/pkg/gofiber-session/idtnats"

err := idtnats.PublishWithIDT(ctx, nc, "trx.agent.workflow", "mywebapp", extraHeaders, body)
```

The sub-package isolates the `nats.go` dependency from the core
`gofiber-session` package, which stays transport-agnostic.
```

- [ ] **Step 6.2: Stage and PAUSE for commit approval**

```bash
git add README.md
```

Suggested commit message: `docs: point at idtnats sub-package in README`.

---

## Done criteria

- [ ] All 13 tests pass under `go test ./pkg/gofiber-session/idtnats/...`
- [ ] `go vet ./...` clean
- [ ] `go build ./...` clean
- [ ] Core `pkg/gofiber-session` still has zero `nats` imports (verified Step 5.4)
- [ ] User has approved each commit individually
- [ ] No file outside `pkg/gofiber-session/idtnats/`, `go.mod`, `go.sum`, `docs/superpowers/specs/...`, `docs/superpowers/plans/...` was modified

---

## Self-review notes (for the writing-plans author)

**Spec coverage check:**
- ✅ Sub-package layout (`pkg/gofiber-session/idtnats/`) — Task 2
- ✅ All 4 exported functions — Tasks 2 (Explicit), 3 (ctx), 4 (Publish×2)
- ✅ Header conflict policy — Step 2.1 test #5 covers it
- ✅ Empty-subject contract — Steps 2.1, 4.1
- ✅ nil ctx safety — Step 3.1 test
- ✅ Backward-compat: core untouched — verified Step 5.4
- ✅ Out-of-scope items (RequestWithIDT, streaming, webapp adoption) deliberately absent
- ✅ Open question #1 (sentinel vs generic error) resolved: sentinel `ErrEmptySubject` for `errors.Is` ergonomics
- ✅ Open question #2 (mock vs embedded server) resolved: BuildMsg tests cover header logic, Publish tests only verify empty-subject guard; trusts `nc.PublishMsg` as 1-line passthrough
- ✅ Open question #3 (naming) resolved: `idtnats`

**Type/signature consistency:** all four function signatures in the plan match the spec verbatim. `ErrEmptySubject` is the only new public symbol beyond the four functions.

**Placeholder scan:** no TBD/TODO/"similar to" references. Each step shows exact code.
