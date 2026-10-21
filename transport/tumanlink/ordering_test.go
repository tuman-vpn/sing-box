//go:build with_gvisor

package tumanlink

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/tuman-vpn/link/handshake"
)

type serialDevice struct {
	*testDevice
	calls       atomic.Int32
	first       chan struct{}
	second      chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (d *serialDevice) WritePackets(bufs [][]byte, offset int) (int, error) {
	switch d.calls.Add(1) {
	case 1:
		close(d.first)
		<-d.release
	case 2:
		close(d.second)
	}
	return d.testDevice.WritePackets(bufs, offset)
}
func (d *serialDevice) unblock() { d.releaseOnce.Do(func() { close(d.release) }) }

func TestWorkersPreservePacketOrder(t *testing.T) {
	d := &serialDevice{testDevice: &testDevice{done: make(chan struct{}), read: make(chan int, 1), writes: make(chan []byte, 64)}, first: make(chan struct{}), second: make(chan struct{}), release: make(chan struct{})}
	s, err := NewStackDevice(context.Background(), d, 1280, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer d.unblock()
	if err = s.ApplyLease(handshake.Lease{V4: [4]byte{10, 77, 0, 2}, InnerMTU: 1280}); err != nil {
		t.Fatal(err)
	}
	dst := M.ParseSocksaddr("198.18.0.1:53")
	c, err := s.ListenPacket(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.WriteTo([]byte{0}, dst.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.first:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	for i := 1; i < 32; i++ {
		if _, err = c.WriteTo([]byte{byte(i)}, dst.UDPAddr()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-d.second:
		t.Fatal("concurrent WritePackets reordered dequeue order")
	case <-time.After(30 * time.Millisecond):
	}
	d.unblock()
	for i := 0; i < 32; i++ {
		select {
		case p := <-d.writes:
			if got := p[len(p)-1]; got != byte(i) {
				t.Fatalf("packet %d contains %d", i, got)
			}
		case <-time.After(time.Second):
			t.Fatal("writer failed to drain queued packets")
		}
	}
}
