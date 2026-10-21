//go:build !with_gvisor

package tumanlink

import (
	"context"
	"strings"
	"testing"
)

func TestStackRequiresGVisor(t *testing.T) {
	device, err := NewStackDevice(context.Background(), nil, 0, 0)
	if device != nil || err == nil || !strings.Contains(err.Error(), "with_gvisor") {
		t.Fatalf("missing build guidance: %v %v", device, err)
	}
}
