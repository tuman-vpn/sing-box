//go:build with_gvisor

package tumanlink

import (
	"sync"
	"testing"
	"time"

	"github.com/tuman-vpn/link/client"
)

// A manually advanced client clock avoids coupling gVisor's process-wide
// worker pools to testing/synctest bubbles. Reset acknowledges each owner tick.
type testClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*testTimer
}
type testTimer struct {
	clock  *testClock
	at     time.Time
	f      func()
	active bool
	resets uint64
}

func newTestClock() *testClock      { return &testClock{now: time.Now()} }
func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) AfterFunc(d time.Duration, f func()) client.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &testTimer{clock: c, at: c.now.Add(d), f: f, active: true}
	c.timers = append(c.timers, t)
	return t
}
func (t *testTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := t.active
	t.active = false
	return active
}
func (t *testTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := t.active
	t.active, t.at = true, t.clock.now.Add(d)
	t.resets++
	return active
}
func (c *testClock) advance(t *testing.T, d time.Duration) {
	t.Helper()
	// New's owner starts asynchronously; wait for its first periodic timer.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		active := false
		for _, timer := range c.timers {
			active = active || timer.active
		}
		c.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not schedule a timer")
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	due := make(map[*testTimer]uint64)
	for _, timer := range c.timers {
		if timer.active && !timer.at.After(c.now) {
			timer.active = false
			due[timer] = timer.resets
		}
	}
	c.mu.Unlock()
	for timer := range due {
		timer.f()
	}
	for timer, generation := range due {
		for {
			c.mu.Lock()
			reset := timer.resets > generation
			c.mu.Unlock()
			if reset {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("client owner did not finish its clock tick")
			}
			time.Sleep(time.Millisecond)
		}
	}
}
