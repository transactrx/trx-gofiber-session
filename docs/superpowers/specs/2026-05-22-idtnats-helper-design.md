# idtnats — NATS publish helper with auto-IDT forwarding

**Date:** 2026-05-22
**Status:** Approved, ready for implementation plan
**Scope:** `trx-gofiber-session` library only
**Related:** [IDT design](../../../../identityservices/docs/superpowers/specs/2026-05-19-internal-delegation-token-design.md) (the broader Internal Delegation Token spec this helper supports)

## Motivation

The IDT primitives in `pkg/gofiber-session/idt.go` (`ReadIDT`, `ReadCallerChain`, `AppendCallerChain`, `BuildOutboundIDTHeaders`) are correct but low-level. Every webapp that forwards IDT to an agent over NATS today writes the same boilerplate:

```go
idt := gofibersession.ReadIDT(ctx)
chain := gofibersession.AppendCallerChain(gofibersession.ReadCallerChain(ctx), selfAppId())
headers := nats.Header{}
for k, v := range existingHeaders { headers.Set(k, v) }
for k, v := range gofibersession.BuildOutboundIDTHeaders(idt, chain) { headers.Set(k, v) }
nc.PublishMsg(&nats.Msg{Subject: subj, Header: headers, Data: body})
```

Forget the loop — IDT silently isn't forwarded, the agent denies (or fails open), and the bug surfaces as a production 403. There is no compile-time check, no lint rule, no test fixture for "did I remember to forward IDT".

A small typed helper that bakes the correct pattern in eliminates the class of bug at the call site.

## Constraint: keep the core nats-dep-free

`pkg/gofiber-session/idt.go:67-68` documents the design choice:

> Kept transport-agnostic on purpose so this library does not depend on nats.go. The webapp converts the returned map into nats.Header (or whatever transport) at the call site.

This is load-bearing — HTTP-only and gRPC consumers must not be forced to pull `nats.go` into their import graph. So the helper lives in a **sub-package** `pkg/gofiber-session/idtnats/` that imports both `nats.go` and the core helpers. Consumers opt in by importing the sub-package; the core stays clean.

## API

Four exported functions, single file:

```go
package idtnats

import (
    "github.com/gofiber/fiber/v2"
    "github.com/nats-io/nats.go"
    gofibersession "github.com/transactrx/trx-gofiber-session/pkg/gofiber-session"
)

// BuildMsgWithIDT builds a *nats.Msg with extraHeaders + IDT/chain
// from ctx already attached. Use when you need to inspect or mutate
// the message before publishing (e.g. for streaming subscriptions).
// Reads TRX_IDT and X-TRX-Caller-Chain from the inbound HTTP request
// on ctx, appends selfAppId to the chain, and sets the resulting
// X-TRX-IDT + X-TRX-Caller-Chain on the NATS header alongside
// extraHeaders. Returns nil if subject is empty.
func BuildMsgWithIDT(ctx *fiber.Ctx, subject string, selfAppId string, extraHeaders map[string]string, body []byte) *nats.Msg

// BuildMsgWithIDTExplicit is the ctx-free variant for the
// NATS-inbound mid-chain case: an agent or webapp that received its
// inbound IDT via NATS headers (not HTTP) and wants to forward to a
// downstream agent. Caller is responsible for AppendCallerChain on
// the inbound chain before calling.
func BuildMsgWithIDTExplicit(subject, idt, chain string, extraHeaders map[string]string, body []byte) *nats.Msg

// PublishWithIDT builds the message via BuildMsgWithIDT and publishes
// it. Wraps the common HTTP-inbound → NATS-outbound fan-out so call
// sites can't forget to forward IDT or extend the chain.
func PublishWithIDT(ctx *fiber.Ctx, nc *nats.Conn, subject, selfAppId string, extraHeaders map[string]string, body []byte) error

// PublishWithIDTExplicit is the ctx-free variant of PublishWithIDT
// for NATS-inbound mid-chain publishers.
func PublishWithIDTExplicit(nc *nats.Conn, subject, idt, chain string, extraHeaders map[string]string, body []byte) error
```

### Behavior of `BuildMsgWithIDT`

1. If `subject == ""`, return `nil`.
2. `idt := gofibersession.ReadIDT(ctx)` — empty when IDT is disabled or the proxy never minted one; that is a valid state.
3. `chain := gofibersession.AppendCallerChain(gofibersession.ReadCallerChain(ctx), selfAppId)`. Note: `ReadCallerChain` returns "" for leaf-after-proxy callers (proxy doesn't set the chain header), so `chain` becomes just `selfAppId` in that common case.
4. Construct `headers := nats.Header{}`. Copy each `(k, v)` from `extraHeaders` (if non-nil) via `headers.Set`.
5. For each `(k, v)` from `gofibersession.BuildOutboundIDTHeaders(idt, chain)`, call `headers.Set`. If `idt == ""`, that map is `nil` and no IDT/chain headers are set — preserves current "IDT off → pass through" semantics.
6. Return `&nats.Msg{Subject: subject, Header: headers, Data: body}`.

### Behavior of `BuildMsgWithIDTExplicit`

Same as `BuildMsgWithIDT` but skips steps 2-3 and uses the passed-in `idt` and `chain` directly. Useful when there is no `*fiber.Ctx` (NATS-inbound handler).

### Behavior of `PublishWithIDT` / `PublishWithIDTExplicit`

1. Build the message via the corresponding `BuildMsg…` function.
2. If the message is `nil` (empty subject), return `errors.New("idtnats: empty subject")`.
3. Return `nc.PublishMsg(msg)`.

No retry, no timeout — `nats.Conn.PublishMsg` is fire-and-forget by design. Callers that need request/reply must use `BuildMsgWithIDT` + their own `nc.RequestMsg(msg, timeout)` for now (a future `RequestWithIDT` is deliberately out of scope; see below).

### Header conflict policy

If `extraHeaders` contains `X-TRX-IDT` or `X-TRX-Caller-Chain`, the IDT-derived values **overwrite** them. The rationale: a webapp dev who manually sets these and also calls the helper is most likely mistakenly duplicating logic; the helper's auto-derived values are the canonical source. This is documented in the function comment.

## What this helper does NOT do (out of scope)

- **`RequestWithIDT` (request/reply).** Easy to add later once a real consumer needs it. No current caller does — chat uses a custom streaming wrapper (`doNatsStreamingRequest` in powerlineClaimSearchWebApp), not vanilla request/reply.
- **Streaming subscription wrappers.** Too app-specific. `BuildMsgWithIDT` is enough for streaming-style senders to build the request message; they own the subscription logic.
- **NATS-inbound automatic chain extension.** `BuildMsgWithIDTExplicit` puts the burden on the caller to extend the chain before calling. A future `BuildMsgWithIDTFromNats(*nats.Msg, ...)` could automate this, but no consumer needs it today (only opensearchAiChatApi receives inbound NATS IDTs, and it terminates the chain — it doesn't forward).
- **Adoption changes in webapps.** Refactoring `powerlineClaimSearchWebApp/runOneTurn` to use `BuildMsgWithIDT` is a separate change in a separate repo; this spec only delivers the library helper.
- **Request-scoped logging hooks / metrics.** Not in scope; layer on top if needed.

## File layout

```
trx-gofiber-session/
├── pkg/
│   └── gofiber-session/
│       ├── idt.go                 # unchanged (low-level primitives)
│       └── idtnats/
│           ├── idtnats.go         # NEW — ~70 lines, the 4 functions above
│           └── idtnats_test.go    # NEW — ~140 lines, table tests
└── go.mod                          # NEW dep: github.com/nats-io/nats.go
```

The core `pkg/gofiber-session/idt.go` does not change. Its imports stay `strings` + `fiber/v2`. Only `pkg/gofiber-session/idtnats/` imports `nats.go`.

## Test plan

Single `idtnats_test.go`, no network required. Tests use Fiber's `app.AcquireCtx` with a fake request to populate headers, and assert on the returned `*nats.Msg`:

| # | Case | Expected |
|---|------|----------|
| 1 | ctx has `TRX_IDT=abc`, no inbound chain, selfAppId="webapp1" | msg.Header has `X-TRX-IDT=abc`, `X-TRX-Caller-Chain=webapp1` |
| 2 | ctx has `TRX_IDT=abc`, inbound chain="upstream", selfAppId="webapp1" | msg.Header has `X-TRX-Caller-Chain=upstream>webapp1` |
| 3 | ctx has no `TRX_IDT` | msg.Header has no `X-TRX-IDT` and no `X-TRX-Caller-Chain`; extraHeaders preserved |
| 4 | extraHeaders include unrelated keys | preserved alongside IDT headers |
| 5 | extraHeaders include `X-TRX-IDT` | overwritten by IDT-derived value (per documented conflict policy) |
| 6 | Empty subject | `BuildMsgWithIDT` returns `nil`; `PublishWithIDT` returns the empty-subject error |
| 7 | Explicit variant: pass `idt="x"`, `chain="a>b"` | msg.Header has `X-TRX-IDT=x`, `X-TRX-Caller-Chain=a>b`, regardless of any ctx |
| 8 | Body `nil` | msg.Data is `nil`; no panic |
| 9 | Body non-nil | msg.Data matches input bytes verbatim |

`PublishWithIDT` itself uses a `*nats.Conn` against an embedded `nats-server` test instance OR a small mock — implementation detail to decide during writing-plans. Goal: confirm message reaches the broker with the expected headers. If the test setup is heavy, an alternative is to assert only on `BuildMsgWithIDT`'s output and trust that `nc.PublishMsg` is a trivial pass-through; this is the recommended default.

## Backward compatibility

Fully additive. Existing code paths (`ReadIDT`, `BuildOutboundIDTHeaders`, etc.) are untouched. Webapps that don't import `idtnats` are unaffected — no transitive `nats.go` dep, no API change. Compatible with `feedback-backward-compat`.

## Open questions

- Should the empty-subject failure mode be a sentinel error (`ErrEmptySubject`) or a generic `errors.New`? Lean: generic; tiny surface.
- Test-server vs. mock-conn for `PublishWithIDT` integration check? Lean: mock; embedded NATS adds a heavy test dep for one assertion.
- Naming: `idtnats` vs `natsidt` vs `nats`? Lean: `idtnats` — reads as "IDT over NATS" and avoids shadowing `nats.go`.
