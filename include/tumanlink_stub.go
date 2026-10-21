//go:build !with_gvisor

package include

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func registerTumanLinkEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TumanLinkEndpointOptions](registry, C.TypeTumanLink, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TumanLinkEndpointOptions) (adapter.Endpoint, error) {
		return nil, fmt.Errorf("tuman-link is not included in this build, rebuild with -tags with_gvisor")
	})
}
