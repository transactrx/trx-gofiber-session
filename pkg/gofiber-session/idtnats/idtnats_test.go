package idtnats

import (
	"errors"
	"testing"
)

func TestBuildMsg_AttachesIDT(t *testing.T) {
	msg := BuildMsg("trx.app.subject", "IDT-abc.cipher", nil, []byte("body"))
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if msg.Subject != "trx.app.subject" {
		t.Errorf("subject: got %q want %q", msg.Subject, "trx.app.subject")
	}
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-abc.cipher" {
		t.Errorf("X-TRX-IDT: got %q want %q", got, "IDT-abc.cipher")
	}
	if string(msg.Data) != "body" {
		t.Errorf("data: got %q want %q", msg.Data, "body")
	}
}

func TestBuildMsg_NoIDTOmitsHeader(t *testing.T) {
	msg := BuildMsg("subj", "", nil, nil)
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if v := msg.Header.Get("X-TRX-IDT"); v != "" {
		t.Errorf("X-TRX-IDT should be empty, got %q", v)
	}
}

func TestBuildMsg_EmptySubjectReturnsNil(t *testing.T) {
	msg := BuildMsg("", "IDT-x", nil, []byte("data"))
	if msg != nil {
		t.Errorf("expected nil msg for empty subject, got %+v", msg)
	}
}

func TestBuildMsg_ExtraHeadersPreserved(t *testing.T) {
	extra := map[string]string{
		"x-trx-account-id": "acct123",
		"x-trx-user-id":    "user456",
	}
	msg := BuildMsg("subj", "IDT-x", extra, nil)
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

func TestBuildMsg_IDTOverridesExtraHeaderConflict(t *testing.T) {
	extra := map[string]string{"X-TRX-IDT": "stale-from-extra"}
	msg := BuildMsg("subj", "IDT-fresh", extra, nil)
	if got := msg.Header.Get("X-TRX-IDT"); got != "IDT-fresh" {
		t.Errorf("expected IDT helper to win conflict, got %q", got)
	}
	if vals := msg.Header.Values("X-TRX-IDT"); len(vals) != 1 {
		t.Errorf("expected 1 value for X-TRX-IDT after override, got %d: %v", len(vals), vals)
	}
}

func TestBuildMsg_NilBodyOk(t *testing.T) {
	msg := BuildMsg("subj", "IDT-x", nil, nil)
	if msg == nil {
		t.Fatal("expected non-nil msg")
	}
	if msg.Data != nil {
		t.Errorf("expected nil data, got %v", msg.Data)
	}
}

func TestPublish_EmptySubjectReturnsError(t *testing.T) {
	err := Publish(nil, "", "IDT-x", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
	if !errors.Is(err, ErrEmptySubject) {
		t.Errorf("expected ErrEmptySubject, got %v", err)
	}
}
