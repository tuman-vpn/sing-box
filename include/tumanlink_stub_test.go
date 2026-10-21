//go:build !with_gvisor

package include

import (
	"context"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

func TestTumanLinkStub(t *testing.T) {
	registry := EndpointRegistry()
	opts, _ := registry.CreateOptions(C.TypeTumanLink)
	ep, err := registry.Create(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", C.TypeTumanLink, opts)
	if ep != nil || err == nil || !strings.Contains(err.Error(), "rebuild with -tags with_gvisor") {
		t.Fatalf("missing build guidance: %v %v", ep, err)
	}
}
