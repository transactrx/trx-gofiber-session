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
// publishers. Like PublishWithIDT it is fire-and-forget — no reply, no retry,
// no timeout — and returns ErrEmptySubject before touching nc when subject
// is empty. For request/reply or streaming, use BuildMsgWithIDTExplicit and
// drive the publish yourself. See BuildMsgWithIDTExplicit for chain semantics
// (caller owns AppendCallerChain on the inbound chain).
func PublishWithIDTExplicit(nc *nats.Conn, subject, idt, chain string, extraHeaders map[string]string, body []byte) error {
	msg := BuildMsgWithIDTExplicit(subject, idt, chain, extraHeaders, body)
	if msg == nil {
		return ErrEmptySubject
	}
	return nc.PublishMsg(msg)
}
