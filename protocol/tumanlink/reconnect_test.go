//go:build with_gvisor

package tumanlink

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/tuman-vpn/link/descriptor"
)

func assertNotReady(t *testing.T, ep *Endpoint) {
	t.Helper()
	c, err := ep.DialContext(context.Background(), "tcp", M.ParseSocksaddr("198.18.0.1:8080"))
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("dial during gap: %v", err)
	}
}

func TestReconnectReloadsFiles(t *testing.T) {
	f := newFixture(t, "rtp", false, true)
	awaitLog(t, f.logs, ": Lease\n")
	descriptorPath := filepath.Join(f.dir, "gateway.tl1")
	identityPath := filepath.Join(f.dir, "credentials.json")
	saved, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	// Force the first retry to rebuild and reject the updated descriptor.
	if err = os.WriteFile(descriptorPath, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	n := f.ep.outer.(*memoryNetwork)
	n.mu.Lock()
	for _, c := range n.clients {
		c.Close()
	}
	n.mu.Unlock()
	awaitLog(t, f.logs, ": Down")
	assertNotReady(t, f.ep)
	awaitLog(t, f.logs, "reconnect: ")
	// Fix the descriptor, but make the identity invalid for another retry.
	f.desc.Version++
	if err = f.gateway.ReloadDescriptors([]descriptor.Descriptor{f.desc}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(descriptorPath, f.desc.Sign(f.root).Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var id identity
	if err = json.Unmarshal(saved, &id); err != nil {
		t.Fatal(err)
	}
	id.Epoch = 0
	if err = writeIdentity(identityPath, id); err != nil {
		t.Fatal(err)
	}
	awaitLog(t, f.logs, "invalid credential state")
	assertNotReady(t, f.ep)
	if err = os.WriteFile(identityPath, saved, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for strings.Count(f.logs.String(), ": Lease\n") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Count(f.logs.String(), ": Lease\n") != 2 {
		t.Fatalf("no replacement Lease: %s", f.logs.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := f.ep.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.1:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("reconnected")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("reconnected"))
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != "reconnected" {
		t.Fatalf("echo: %q %v", got, err)
	}
}

type authEvent struct {
	tag   string
	cause string
}

func captureAuthEvents(t *testing.T) func() []authEvent {
	t.Helper()
	var mu sync.Mutex
	var events []authEvent
	SetAuthFailureHandler(func(tag string, cause error) {
		mu.Lock()
		events = append(events, authEvent{tag, cause.Error()})
		mu.Unlock()
	})
	stop := func() []authEvent {
		SetAuthFailureHandler(nil)
		mu.Lock()
		defer mu.Unlock()
		return append([]authEvent(nil), events...)
	}
	t.Cleanup(func() { stop() })
	return stop
}

func TestAuthFailureRefreshAndNormalClose(t *testing.T) {
	t.Run("descriptor refresh", func(t *testing.T) {
		stop := captureAuthEvents(t)
		f := newFixture(t, "udp", true, true)
		awaitLog(t, f.logs, ": Refresh")
		f.ep.Close()
		output := stop()
		if len(output) != 1 || output[0].tag != "tl1" || !strings.Contains(output[0].cause, "descriptor refresh") {
			t.Fatalf("missing or duplicate auth notification: %+v", output)
		}
	})
	t.Run("normal close", func(t *testing.T) {
		stop := captureAuthEvents(t)
		f := newFixture(t, "udp", false, true)
		awaitLog(t, f.logs, ": Lease\n")
		if err := f.ep.Close(); err != nil && err != net.ErrClosed {
			t.Fatal(err)
		}
		if output := stop(); len(output) != 0 {
			t.Fatalf("Close notified auth failure: %+v", output)
		}
	})
}

func TestReconnectJitterBounds(t *testing.T) {
	for _, base := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second} {
		first := reconnectDelay(base)
		varied := false
		for range 100 {
			delay := reconnectDelay(base)
			if delay < base*8/10 || delay > base*12/10 {
				t.Fatalf("backoff %v outside ±20%% of %v", delay, base)
			}
			varied = varied || delay != first
		}
		if !varied {
			t.Fatalf("backoff %v has no jitter", base)
		}
	}
}

func TestCloseDuringReconnect(t *testing.T) {
	f := newFixture(t, "udp", false, true)
	awaitLog(t, f.logs, ": Lease\n")
	n := f.ep.outer.(*memoryNetwork)
	n.mu.Lock()
	for _, c := range n.clients {
		c.Close()
	}
	n.mu.Unlock()
	awaitLog(t, f.logs, ": Down")
	assertNotReady(t, f.ep)
	done := make(chan struct{})
	go func() { f.ep.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close waited for reconnect backoff")
	}
}

func TestListenPacketWithDestination(t *testing.T) {
	f := newFixture(t, "udp", false, true)
	awaitLog(t, f.logs, ": Lease\n")
	dst := M.ParseSocksaddr("198.18.0.1:53")
	pc, address, err := f.ep.ListenPacketWithDestination(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if address != dst.Addr {
		t.Fatalf("destination address: %v", address)
	}
	awaitLog(t, f.logs, "outbound packet connection to 198.18.0.1:53")
}
