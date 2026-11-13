package sshr

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestNewRejectsNilHostKeyCallback verifies that sshr.New() refuses to start
// when no HostKeyCallback is set.
//
// Before the fix, New() silently overwrote any HostKeyCallback (including a
// caller-supplied verifying one) with ssh.InsecureIgnoreHostKey(), making
// every connection vulnerable to man-in-the-middle attacks.
func TestNewRejectsNilHostKeyCallback(t *testing.T) {
	cfg := Config{
		SSHClientConfig: &ssh.ClientConfig{
			User: "test",
			// HostKeyCallback intentionally left nil — simulates a caller that
			// forgot to set it.  Old code would silently accept this.
		},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New() must return an error when HostKeyCallback is nil, got nil")
	}
}

// TestNewAcceptsExplicitHostKeyCallback verifies that New() succeeds when the
// caller provides an explicit HostKeyCallback (even InsecureIgnoreHostKey,
// which signals a deliberate decision rather than an oversight).
func TestNewAcceptsExplicitHostKeyCallback(t *testing.T) {
	cfg := Config{
		SSHClientConfig: &ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // explicit, deliberate
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil SSHR")
	}
	// Confirm the callback was NOT overwritten.
	if s.config.SSHClientConfig.HostKeyCallback == nil {
		t.Fatal("HostKeyCallback must remain set after New()")
	}
}
