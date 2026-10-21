//go:build with_gvisor

package tumanlink

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/tuman-vpn/link/handshake"
	"github.com/tuman-vpn/link/host/packetdev"
)

type testDevice struct {
	done   chan struct{}
	once   sync.Once
	read   chan int
	writes chan []byte
}

func (d *testDevice) BatchSize() int { return 8 }
func (d *testDevice) MTU() int       { return 1400 }
func (d *testDevice) ReadPackets(bufs [][]byte, sizes []int, offset int) (int, error) {
	valid := len(bufs) == 8 && len(sizes) == 8 && offset == 16
	for _, b := range bufs {
		valid = valid && len(b) == 16+packetdev.MaxPacketSize
	}
	if valid {
		select {
		case d.read <- len(bufs):
		default:
		}
	}
	<-d.done
	return 0, net.ErrClosed
}
func (d *testDevice) WritePackets(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		d.writes <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}
func (d *testDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }

// Catches undersized receive buffers, stale lease addresses, and live sockets after Refresh.
func TestStackLeaseMTUAndConnectionLifetime(t *testing.T) {
	d := &testDevice{done: make(chan struct{}), read: make(chan int, 1), writes: make(chan []byte, 16)}
	s, err := NewStackDevice(context.Background(), d, 1300, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-d.read:
	case <-time.After(time.Second):
		t.Fatal("incorrect packetdev batch or headroom")
	}
	first := handshake.Lease{V4: [4]byte{10, 77, 0, 2}, V4PrefixLen: 16, V6: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, V6PrefixLen: 64, InnerMTU: 1400}
	if err = s.ApplyLease(first); err != nil {
		t.Fatal(err)
	}
	s.SetMTU(1400)
	sd := s.(*stackDevice)
	if sd.link.MTU() != 1300 {
		t.Fatal("MTU cap ignored")
	}
	addresses := leaseAddresses(sd)
	if len(addresses) != 2 {
		t.Fatalf("addresses: %v", addresses)
	}
	for _, a := range addresses {
		if a.AddressWithPrefix.PrefixLen != a.AddressWithPrefix.Address.BitLen() {
			t.Fatalf("lease must install host address: %v", a)
		}
	}
	conn, err := s.ListenPacket(context.Background(), M.ParseSocksaddr("198.18.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.WriteTo([]byte("probe"), M.ParseSocksaddr("198.18.0.1:53").UDPAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-d.writes:
		if len(p) < 20 || p[0]>>4 != 4 {
			t.Fatalf("bad packet offset: %x", p)
		}
	case <-time.After(time.Second):
		t.Fatal("no outgoing packet")
	}
	s.CloseConnections()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = conn.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("socket survived CloseConnections")
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		t.Fatal("socket timed out instead of closing on CloseConnections")
	}
	second := handshake.Lease{V4: [4]byte{10, 77, 0, 3}, V4PrefixLen: 16, InnerMTU: 1280}
	if err = s.ApplyLease(second); err != nil {
		t.Fatal(err)
	}
	s.SetMTU(1280)
	addresses = leaseAddresses(sd)
	if len(addresses) != 1 || addresses[0].AddressWithPrefix.Address != tun.AddressFromAddr(M.ParseSocksaddr("10.77.0.3:0").Addr) {
		t.Fatalf("stale addresses: %v", addresses)
	}
	if sd.link.MTU() != 1280 {
		t.Fatal("MTU change ignored")
	}
	if _, err = s.ListenPacket(context.Background(), M.ParseSocksaddr("[fd00::1]:53")); err == nil {
		t.Fatal("removed IPv6 address remained usable")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

func leaseAddresses(d *stackDevice) []tcpip.ProtocolAddress {
	var result []tcpip.ProtocolAddress
	for _, address := range d.stack.AllAddresses()[tun.DefaultNIC] {
		if address.AddressWithPrefix.Address != tun.AddressFromAddr(netip.MustParseAddr("255.255.255.255")) {
			result = append(result, address)
		}
	}
	return result
}
