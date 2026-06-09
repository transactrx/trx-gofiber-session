package gofiber_session

import "testing"

func TestIDTRegistry_CaptureAndCurrent(t *testing.T) {
	ForgetIDT("sess-1") // clean slate

	if got := CurrentIDT("sess-1"); got != "" {
		t.Fatalf("empty registry: want \"\", got %q", got)
	}

	CaptureIDT("sess-1", "IDT-aaa.cipher")
	if got := CurrentIDT("sess-1"); got != "IDT-aaa.cipher" {
		t.Fatalf("after capture: want IDT-aaa.cipher, got %q", got)
	}

	// Newer capture overwrites.
	CaptureIDT("sess-1", "IDT-bbb.cipher")
	if got := CurrentIDT("sess-1"); got != "IDT-bbb.cipher" {
		t.Fatalf("after second capture: want IDT-bbb.cipher, got %q", got)
	}

	// Empty inputs are no-ops.
	CaptureIDT("", "IDT-x")
	CaptureIDT("sess-1", "")
	if got := CurrentIDT("sess-1"); got != "IDT-bbb.cipher" {
		t.Fatalf("empty inputs must not overwrite: got %q", got)
	}

	// Forget clears it.
	ForgetIDT("sess-1")
	if got := CurrentIDT("sess-1"); got != "" {
		t.Fatalf("after forget: want \"\", got %q", got)
	}
}
