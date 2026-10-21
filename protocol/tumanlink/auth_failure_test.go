package tumanlink

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tuman-vpn/link/client"
)

// Catches a hook that drops causes, leaks between installs, or panics unset.
func TestAuthFailureHandler(t *testing.T) {
	t.Cleanup(func() { SetAuthFailureHandler(nil) })
	notifyAuthFailure("tl1", errors.New("unset"))
	var got []string
	first := func(tag string, cause error) { got = append(got, "first:"+tag+":"+cause.Error()) }
	if previous := SetAuthFailureHandler(first); previous != nil {
		t.Fatal("unexpected previous handler")
	}
	notifyAuthFailure("tl1", ErrDescriptorRefreshRequired)
	previous := SetAuthFailureHandler(func(tag string, cause error) { got = append(got, "second:"+tag) })
	if previous == nil {
		t.Fatal("lost previous handler")
	}
	previous("tl2", errors.New("chained"))
	notifyAuthFailure("tl3", errors.New("x"))
	if SetAuthFailureHandler(nil) == nil {
		t.Fatal("lost installed handler")
	}
	notifyAuthFailure("tl4", errors.New("removed"))
	want := []string{"first:tl1:" + ErrDescriptorRefreshRequired.Error(), "first:tl2:chained", "second:tl3"}
	if len(got) != len(want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %q, want %q", got, want)
		}
	}
}

// Catches a descriptor Refresh reported with an older Degraded or epoch cause
// that packetdev.Err still retains.
func TestRefreshCause(t *testing.T) {
	handshake := errors.New("handshake failed")
	epoch := fmt.Errorf("setup: %w", client.ErrCredentialEpochRequired)
	var gen generation
	for i, tc := range []struct{ current, want error }{
		{nil, ErrDescriptorRefreshRequired},
		{handshake, ErrDescriptorRefreshRequired},
		{epoch, epoch},
		{epoch, ErrDescriptorRefreshRequired},
		{handshake, ErrDescriptorRefreshRequired},
	} {
		if got := refreshCause(tc.current, &gen); got != tc.want {
			t.Fatalf("refresh %d with Err()=%v: got %v, want %v", i, tc.current, got, tc.want)
		}
	}
}
