//go:build with_gvisor

package tumanlink

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/tuman-vpn/link/gateway"
)

// Datagram-preserving outer transport for sandbox runs. The client, packetdev,
// gateway and both TCP stacks are real; only OS UDP sockets are replaced.
type memoryDatagram struct {
	from netip.AddrPort
	data []byte
}
type memoryNetwork struct {
	ctx      context.Context
	server   netip.AddrPort
	mu       sync.Mutex
	next     uint16
	clients  map[netip.AddrPort]*memoryConn
	track    bool
	attempts map[[12]byte]time.Time
	now      func() time.Time
	outgoing chan memoryDatagram
}

func (n *memoryNetwork) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "udp" || dst.AddrPort() != n.server {
		return nil, fmt.Errorf("unexpected outer destination %s %s", network, dst)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.next++
	local := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 20000+n.next)
	c := &memoryConn{network: n, local: local, incoming: make(chan []byte, 1024), done: make(chan struct{})}
	n.clients[local] = c
	return c, nil
}
func (n *memoryNetwork) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected ListenPacket")
}
func (n *memoryNetwork) send(to gateway.Tuple, p []byte) error {
	n.mu.Lock()
	c := n.clients[to.Remote]
	n.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	select {
	case c.incoming <- bytes.Clone(p):
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-n.ctx.Done():
		return n.ctx.Err()
	}
}
func (n *memoryNetwork) receive(gw *gateway.Gateway) {
	for {
		select {
		case d := <-n.outgoing:
			gw.Ingress(d.data, gateway.Tuple{Local: n.server, Remote: d.from})
		case <-n.ctx.Done():
			return
		}
	}
}

type memoryConn struct {
	network  *memoryNetwork
	local    netip.AddrPort
	incoming chan []byte
	done     chan struct{}
	once     sync.Once
}

func (c *memoryConn) Read(b []byte) (int, error) {
	select {
	case p := <-c.incoming:
		return copy(b, p), nil
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.network.ctx.Done():
		return 0, c.network.ctx.Err()
	}
}
func (c *memoryConn) Write(p []byte) (int, error) {
	c.network.mu.Lock()
	if c.network.track && len(p) >= 128 {
		if c.network.attempts == nil {
			c.network.attempts = make(map[[12]byte]time.Time)
		}
		key := [12]byte(p[:12])
		if _, ok := c.network.attempts[key]; !ok {
			if c.network.now != nil {
				c.network.attempts[key] = c.network.now()
			} else {
				c.network.attempts[key] = time.Now()
			}
		}
	}
	c.network.mu.Unlock()
	select {
	case c.network.outgoing <- memoryDatagram{c.local, bytes.Clone(p)}:
		return len(p), nil
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.network.ctx.Done():
		return 0, c.network.ctx.Err()
	}
}
func (c *memoryConn) Close() error                     { c.once.Do(func() { close(c.done) }); return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(c.local) }
func (c *memoryConn) RemoteAddr() net.Addr             { return net.UDPAddrFromAddrPort(c.network.server) }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
