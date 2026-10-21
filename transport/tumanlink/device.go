package tumanlink

import (
	"io"

	N "github.com/sagernet/sing/common/network"
	"github.com/tuman-vpn/link/handshake"
)

// PacketDevice is the packetdev boundary; the stack owns its lifetime.
type PacketDevice interface {
	ReadPackets([][]byte, []int, int) (int, error)
	WritePackets([][]byte, int) (int, error)
	BatchSize() int
	MTU() int
	io.Closer
}

type Device interface {
	N.Dialer
	ApplyLease(handshake.Lease) error
	SetMTU(int)
	CloseConnections()
	io.Closer
}
