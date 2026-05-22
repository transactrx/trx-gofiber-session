package gofiber_session

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Inbound HTTP header set by secureappproxy when an IDT is available for the
// current request. Empty when IDT is disabled or never minted.
const TRX_IDT = "TRX_IDT"

// Outbound NATS header names per the IDT spec. Webapps add these when invoking
// agents over NATS so Identity (called by the agent for validate) can identify
// the token and reconstruct the caller chain for audit.
const (
	NATS_HEADER_TRX_IDT          = "X-TRX-IDT"
	NATS_HEADER_TRX_CALLER_CHAIN = "X-TRX-Caller-Chain"
)

// ReadIDT returns the IDT carried on the inbound HTTP request, or "" when
// absent (legacy proxy / IDT disabled / non-IDT request).
func ReadIDT(ctx *fiber.Ctx) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	v := ctx.Request().Header.Peek(TRX_IDT)
	return strings.TrimSpace(string(v))
}

// ReadCallerChain returns the X-TRX-Caller-Chain header from the inbound
// request, or "" when absent. The proxy itself does NOT set this — only
// upstream agents/webapps do. Use {@link AppendCallerChain} to extend it.
func ReadCallerChain(ctx *fiber.Ctx) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	v := ctx.Request().Header.Peek(NATS_HEADER_TRX_CALLER_CHAIN)
	return strings.TrimSpace(string(v))
}

// AppendCallerChain appends `selfId` to an existing chain. Empty existing
// chain becomes just `selfId`. Spec caps chain length at 256 chars — values
// beyond that are truncated to keep audit rows compact.
func AppendCallerChain(existing, selfId string) string {
	selfId = strings.TrimSpace(selfId)
	if selfId == "" {
		return strings.TrimSpace(existing)
	}
	existing = strings.TrimSpace(existing)
	var out string
	if existing == "" {
		out = selfId
	} else {
		out = existing + ">" + selfId
	}
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// BuildOutboundIDTHeaders returns the (idt, callerChain) pair as a map suitable
// for copying onto a NATS message header. Returns nil if idt is empty — callers
// that want to fail-closed on missing IDT should check before invoking.
//
// Kept transport-agnostic on purpose so this library does not depend on nats.go.
// The webapp converts the returned map into nats.Header (or whatever transport)
// at the call site.
func BuildOutboundIDTHeaders(idt, callerChain string) map[string]string {
	idt = strings.TrimSpace(idt)
	if idt == "" {
		return nil
	}
	out := make(map[string]string, 2)
	out[NATS_HEADER_TRX_IDT] = idt
	if cc := strings.TrimSpace(callerChain); cc != "" {
		out[NATS_HEADER_TRX_CALLER_CHAIN] = cc
	}
	return out
}
