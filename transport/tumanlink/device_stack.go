//go:build with_gvisor

package tumanlink

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/tuman-vpn/link/handshake"
	"github.com/tuman-vpn/link/host/packetdev"
)

const packetOffset = 16

type stackDevice struct {
	ctx               context.Context
	cancel            context.CancelFunc
	device            PacketDevice
	stack             *stack.Stack
	link              *channel.Endpoint
	mtuCap            uint32
	mu                sync.RWMutex
	addresses         []netip.Addr
	inet4, inet6      netip.Addr
	closed            bool
	connections       context.Context
	cancelConnections context.CancelFunc
	wg                sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
}

func NewStackDevice(ctx context.Context, device PacketDevice, mtu uint32, workers int) (Device, error) {
	if ctx == nil || device == nil || device.BatchSize() < 1 || workers < 0 || workers > 256 || mtu != 0 && (mtu < 1280 || mtu > 1400) {
		return nil, fmt.Errorf("invalid tuman-link stack options")
	}
	ctx, cancel := context.WithCancel(ctx)
	d := &stackDevice{ctx: ctx, cancel: cancel, device: device, mtuCap: mtu}
	d.connections, d.cancelConnections = context.WithCancel(ctx)
	d.link = channel.New(256, uint32(device.MTU()), "")
	d.SetMTU(device.MTU())
	var err error
	d.stack, err = tun.NewGVisorStackWithOptions(d.link, stack.NICOptions{}, true)
	if err != nil {
		cancel()
		d.link.Close()
		return nil, err
	}
	// Outbound-only endpoint: accept packets solely for the current lease.
	d.stack.SetSpoofing(tun.DefaultNIC, false)
	d.stack.SetPromiscuousMode(tun.DefaultNIC, false)
	// A single reader drains packetdev batches. A single writer preserves
	// channel dequeue order through WritePackets, including when workers > 1.
	d.wg.Add(2)
	go d.readPackets()
	go d.writePackets()
	return d, nil
}

func (d *stackDevice) ApplyLease(lease handshake.Lease) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	// Remove the entire old lease, including IPv6 when the new lease omits it.
	for _, address := range d.addresses {
		if err := d.stack.RemoveAddress(tun.DefaultNIC, tun.AddressFromAddr(address)); err != nil {
			return fmt.Errorf("remove lease address: %s", err)
		}
	}
	d.addresses = nil
	d.inet4 = netip.Addr{}
	d.inet6 = netip.Addr{}
	addresses := []netip.Addr{netip.AddrFrom4(lease.V4)}
	if lease.V6PrefixLen != 0 {
		addresses = append(addresses, netip.AddrFrom16(lease.V6))
	}
	for _, address := range addresses {
		protocol := header.IPv4ProtocolNumber
		if address.Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tun.AddressFromAddr(address), PrefixLen: address.BitLen()}}
		if err := d.stack.AddProtocolAddress(tun.DefaultNIC, pa, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("install lease address: %s", err)
		}
		d.addresses = append(d.addresses, address)
		if address.Is4() {
			d.inet4 = address
		} else {
			d.inet6 = address
		}
	}
	return nil
}
func (d *stackDevice) SetMTU(mtu int) {
	if d.mtuCap != 0 && mtu > int(d.mtuCap) {
		mtu = int(d.mtuCap)
	}
	d.link.SetMTU(uint32(mtu))
}

func (d *stackDevice) bind(destination M.Socksaddr) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, context.Context, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return tcpip.FullAddress{}, 0, nil, net.ErrClosed
	}
	address, protocol := d.inet4, header.IPv4ProtocolNumber
	if destination.IsIPv6() {
		address, protocol = d.inet6, header.IPv6ProtocolNumber
	}
	if !destination.IsIP() || !address.IsValid() {
		return tcpip.FullAddress{}, 0, nil, fmt.Errorf("missing local address for %s", destination)
	}
	return tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(address)}, protocol, d.connections, nil
}
func (d *stackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	bind, protocol, lifetime, err := d.bind(destination)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(lifetime, cancel)
	defer stop()
	remote := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(destination.Addr), Port: destination.Port}
	var conn net.Conn
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		conn, err = wireguard.DialTCPWithBind(ctx, d.stack, bind, remote, protocol)
	case N.NetworkUDP:
		conn, err = gonet.DialUDP(d.stack, &bind, &remote, protocol)
	default:
		return nil, fmt.Errorf("%w: %s", N.ErrUnknownNetwork, network)
	}
	if err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if lifetime.Err() != nil {
		conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}
func (d *stackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bind, protocol, lifetime, err := d.bind(destination)
	if err != nil {
		return nil, err
	}
	conn, err := gonet.DialUDP(d.stack, &bind, nil, protocol)
	if err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if lifetime.Err() != nil {
		conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}
func (d *stackDevice) CloseConnections() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancelConnections()
	for _, ep := range d.stack.RegisteredEndpoints() {
		ep.Abort()
	}
	for _, ep := range d.stack.CleanupEndpoints() {
		ep.Abort()
	}
	d.connections, d.cancelConnections = context.WithCancel(d.ctx)
}
func (d *stackDevice) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		d.cancel()
		d.CloseConnections()
		d.closeErr = d.device.Close()
		d.wg.Wait()
		d.link.Close()
		d.stack.Close()
		for _, ep := range d.stack.CleanupEndpoints() {
			ep.Abort()
		}
		d.stack.Wait()
	})
	return d.closeErr
}
func packetBuffers(count int) [][]byte {
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, packetOffset+packetdev.MaxPacketSize)
	}
	return bufs
}
func (d *stackDevice) readPackets() {
	defer d.wg.Done()
	bufs := packetBuffers(d.device.BatchSize())
	sizes := make([]int, len(bufs))
	for {
		n, err := d.device.ReadPackets(bufs, sizes, packetOffset)
		for i := 0; i < n; i++ {
			p := bufs[i][packetOffset : packetOffset+sizes[i]]
			if len(p) == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch header.IPVersion(p) {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
			d.link.InjectInbound(proto, pb)
			pb.DecRef()
		}
		if err != nil {
			return
		}
	}
}
func (d *stackDevice) writePackets() {
	defer d.wg.Done()
	bufs := packetBuffers(d.device.BatchSize())
	batch := make([][]byte, len(bufs))
	for {
		packet := d.link.ReadContext(d.ctx)
		if packet == nil {
			return
		}
		n := 0
		for packet != nil {
			size := packet.Size()
			if size <= packetdev.MaxPacketSize {
				position := packetOffset
				for _, part := range packet.AsSlices() {
					position += copy(bufs[n][position:], part)
				}
				batch[n] = bufs[n][:position]
				n++
			}
			packet.DecRef()
			if n == len(bufs) {
				break
			}
			packet = d.link.Read()
		}
		if n > 0 {
			if _, err := d.device.WritePackets(batch[:n], packetOffset); err != nil {
				return
			}
		}
	}
}
