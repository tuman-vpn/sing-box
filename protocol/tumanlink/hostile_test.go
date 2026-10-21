//go:build with_gvisor

package tumanlink

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/tuman-vpn/link/client"
	"github.com/tuman-vpn/link/gateway"
)

// Fake time drives the real client timers against an in-process gateway. OS sockets
// alone are replaced, so this also runs where UDP bind is forbidden.
func TestHostileGateway(t *testing.T) {
	for _, mode := range []string{"wrong static key", "replayed M2"} {
		t.Run(mode, func(t *testing.T) {

			clock := newTestClock()
			{
				var mu sync.Mutex
				var captured []byte
				replay := false
				hook := fixtureHooks{gateway: func(o *gateway.Options) {
					if mode == "wrong static key" {
						o.StaticPriv = [32]byte{99}
						return
					}
					send := o.Send
					o.Send = func(w int, to gateway.Tuple, p []byte) error {
						mu.Lock()
						if captured == nil {
							captured = bytes.Clone(p)
						}
						data := p
						if replay {
							data = bytes.Clone(captured)
						}
						mu.Unlock()
						return send(w, to, data)
					}
				}, endpoint: func(ep *Endpoint) {
					ep.clock = clock
					n := ep.outer.(*memoryNetwork)
					n.track, n.now = true, clock.Now
				}}
				f := newFixture(t, "udp", false, true, hook)
				if mode == "replayed M2" {
					awaitLog(t, f.logs, ": Lease\n")
					if err := f.ep.Close(); err != nil {
						t.Fatal(err)
					}
					mu.Lock()
					if len(captured) < 128 {
						t.Fatalf("no captured M2: %d", len(captured))
					}
					replay = true
					mu.Unlock()
					// Retain enrollment and admission.db, so the new M1 uses a fresh counter.
					a, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1-replay", f.ep.options)
					if err != nil {
						t.Fatal(err)
					}
					ep := a.(*Endpoint)
					ep.clock = clock
					ep.outer = f.ep.outer
					f.ep = ep
					t.Cleanup(func() { ep.Close() })
					n := ep.outer.(*memoryNetwork)
					n.mu.Lock()
					n.attempts = nil
					n.mu.Unlock()
					if err = ep.Start(adapter.StartStateStart); err != nil {
						t.Fatal(err)
					}
				}
				n := f.ep.outer.(*memoryNetwork)
				for range 30 {
					clock.advance(t, time.Second)
					assertNotReady(t, f.ep)
					f.ep.mu.RLock()
					device := f.ep.device
					f.ep.mu.RUnlock()
					if device == nil || device.Lease().LeaseID != 0 {
						t.Fatal("hostile gateway issued a Lease")
					}
					if err := f.ep.Err(); err != nil && (errors.Is(err, ErrDescriptorRefreshRequired) || errors.Is(err, client.ErrCredentialEpochRequired)) {
						t.Fatalf("hostile input caused Refresh: %v", err)
					}
				}
				n.mu.Lock()
				times := make([]time.Time, 0, len(n.attempts))
				for _, at := range n.attempts {
					times = append(times, at)
				}
				n.mu.Unlock()
				sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
				// Each attempt has a 7s direct budget, then 2s,4s,8s... ±50%.
				// Even minimum jitter permits at most four distinct M1s in 30s.
				if len(times) < 2 || len(times) > 4 {
					t.Fatalf("attempts over 30s: %v", times)
				}
				for i := 1; i < len(times); i++ {
					minimum := 7*time.Second + (time.Second << (i - 1))
					if elapsed := times[i].Sub(times[i-1]); elapsed < minimum {
						t.Fatalf("attempt %d bypassed backoff: %v < %v", i+1, elapsed, minimum)
					}
				}
			}
		})
	}
}

func TestCredentialEpochRecoveryAuthEvent(t *testing.T) {
	clock := newTestClock()
	stop := captureAuthEvents(t)
	f := newFixture(t, "udp", false, true, fixtureHooks{
		gateway:  func(o *gateway.Options) { o.StaticPriv = [32]byte{99} },
		endpoint: func(ep *Endpoint) { ep.clock = clock },
	})
	// The installed link asks for a new epoch after ten minutes of failed
	// setup. Wire REFRESH itself carries a descriptor version, never an epoch.
	clock.advance(t, time.Second)
	clock.advance(t, 10*time.Minute+time.Second)
	deadline := time.Now().Add(time.Second)
	for !errors.Is(f.ep.Err(), client.ErrCredentialEpochRequired) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(f.ep.Err(), client.ErrCredentialEpochRequired) {
		t.Fatalf("lost epoch recovery cause: %v", f.ep.Err())
	}
	assertNotReady(t, f.ep)
	f.ep.Close()
	output := stop()
	if len(output) != 1 || output[0].tag != "tl1" || !strings.Contains(output[0].cause, client.ErrCredentialEpochRequired.Error()) {
		t.Fatalf("epoch recovery auth event: %+v", output)
	}
}
