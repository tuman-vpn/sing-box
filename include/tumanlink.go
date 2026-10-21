//go:build with_gvisor

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/tumanlink"
)

func registerTumanLinkEndpoint(registry *endpoint.Registry) {
	tumanlink.RegisterEndpoint(registry)
}
