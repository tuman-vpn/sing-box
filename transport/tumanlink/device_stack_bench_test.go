//go:build with_gvisor

package tumanlink

import (
	"context"
	"io"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type benchmarkDevice struct {
	*testDevice
	remaining             int
	packet                []byte
	ready, start, drained chan struct{}
}

func (d *benchmarkDevice) ReadPackets(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.ready != nil {
		close(d.ready)
		d.ready = nil
		<-d.start
	}
	if d.remaining == 0 {
		close(d.drained)
		return 0, io.EOF
	}
	n := min(d.remaining, len(bufs))
	for i := 0; i < n; i++ {
		sizes[i] = copy(bufs[i][offset:], d.packet)
	}
	d.remaining -= n
	return n, nil
}

// Measures actual batched receive/injection into gVisor, including packetdev
// copies and packet-buffer ownership. Setup and teardown are excluded.
func BenchmarkStackInbound(b *testing.B) {
	packet := make([]byte, 1280)
	h := header.IPv4(packet[:20])
	h.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: 17, SrcAddr: tcpip.AddrFrom4([4]byte{10, 77, 0, 2}), DstAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1})})
	h.SetChecksum(^h.CalculateChecksum())
	header.UDP(packet[20:]).Encode(&header.UDPFields{SrcPort: 1234, DstPort: 53, Length: uint16(len(packet) - 20)})
	d := &benchmarkDevice{testDevice: &testDevice{done: make(chan struct{})}, remaining: b.N, packet: packet, ready: make(chan struct{}), start: make(chan struct{}), drained: make(chan struct{})}
	ready := d.ready
	s, err := NewStackDevice(context.Background(), d, 1280, 2)
	if err != nil {
		b.Fatal(err)
	}
	<-ready
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	close(d.start)
	<-d.drained
	b.StopTimer()
	s.Close()
}
