package include

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestTumanLinkRegistration(t *testing.T) {
	opts, ok := EndpointRegistry().CreateOptions(C.TypeTumanLink)
	if _, typed := opts.(*option.TumanLinkEndpointOptions); !ok || !typed {
		t.Fatalf("tuman-link not registered: %T", opts)
	}
}
