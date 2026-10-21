//go:build !with_gvisor

package tumanlink

import (
	"context"
	"fmt"
)

func NewStackDevice(context.Context, PacketDevice, uint32, int) (Device, error) {
	return nil, fmt.Errorf("tuman-link requires gVisor, rebuild with -tags with_gvisor")
}
