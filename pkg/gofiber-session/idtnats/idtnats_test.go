package idtnats

import (
	"errors"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
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
