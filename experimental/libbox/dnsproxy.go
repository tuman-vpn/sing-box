package libbox

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// SocketProtector protects sockets from being routed through the VPN TUN
// interface.  On Android, this calls VpnService.protect(fd).
// Gomobile exports this as io.nekohasekai.libbox.SocketProtector.
type SocketProtector interface {
	ProtectFd(fd int32) bool
}

// DnsProxyOptions configures the embedded dnsproxy instance.
// Gomobile exports this as io.nekohasekai.libbox.DnsProxyOptions.
type DnsProxyOptions struct {
	ListenAddr    string
	ListenPort    int
	Upstreams     string
	CacheEnabled  bool
	CacheSizeKB   int
	CacheMinTTL   int
	CacheMaxTTL   int
	IPv6Disabled  bool
	MaxGoroutines int
}

var (
	dnsProxyMu       sync.Mutex
	dnsProxyInstance  *proxy.Proxy
	dnsProxyCancel    context.CancelFunc
)

// StartDnsProxy creates and starts a dnsproxy instance with socket protection.
// The protector is called on every DNS socket to bypass the VPN TUN interface.
// Returns the actual listening port.
func StartDnsProxy(opts *DnsProxyOptions, protector SocketProtector) (int, error) {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	if dnsProxyInstance != nil {
		return 0, fmt.Errorf("dnsproxy is already running")
	}

	lines := strings.Split(strings.TrimSpace(opts.Upstreams), "\n")
	var upstreams []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			upstreams = append(upstreams, line)
		}
	}

	if len(upstreams) == 0 {
		return 0, fmt.Errorf("no upstreams configured")
	}

	upsOpts := &upstream.Options{
		Logger: slog.Default(),
	}

	// Wire socket protection via DialControl if protector is provided.
	if protector != nil {
		upsOpts.DialControl = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if !protector.ProtectFd(int32(fd)) {
					slog.Warn("failed to protect DNS socket", "fd", fd)
				}
			})
		}
	}

	upstreamConfig, err := proxy.ParseUpstreamsConfig(upstreams, upsOpts)
	if err != nil {
		return 0, fmt.Errorf("parsing upstreams: %w", err)
	}

	addrPort := netip.AddrPortFrom(
		netip.MustParseAddr(opts.ListenAddr),
		uint16(opts.ListenPort),
	)

	var handler proxy.Handler = proxy.DefaultHandler{}
	if opts.IPv6Disabled {
		handler = &ipv6BlockHandler{next: handler}
	}

	config := &proxy.Config{
		Logger:         slog.Default(),
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(addrPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(addrPort)},
		UpstreamConfig: upstreamConfig,
		CacheEnabled:   opts.CacheEnabled,
		CacheSizeBytes: opts.CacheSizeKB * 1024,
		CacheMinTTL:    uint32(opts.CacheMinTTL),
		CacheMaxTTL:    uint32(opts.CacheMaxTTL),
		MaxGoroutines:  uint(opts.MaxGoroutines),
		RequestHandler: handler,
	}

	p, err := proxy.New(config)
	if err != nil {
		return 0, fmt.Errorf("creating dnsproxy: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if err = p.Start(ctx); err != nil {
		cancel()
		return 0, fmt.Errorf("starting dnsproxy: %w", err)
	}

	addr := p.Addr(proxy.ProtoUDP)
	if addr == nil {
		cancel()
		_ = p.Shutdown(context.Background())
		return 0, fmt.Errorf("dnsproxy started but no UDP address available")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		cancel()
		_ = p.Shutdown(context.Background())
		return 0, fmt.Errorf("unexpected address type: %T", addr)
	}

	dnsProxyInstance = p
	dnsProxyCancel = cancel

	return udpAddr.Port, nil
}

// StopDnsProxy shuts down the running dnsproxy instance.
func StopDnsProxy() error {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	if dnsProxyInstance == nil {
		return nil
	}

	if dnsProxyCancel != nil {
		dnsProxyCancel()
		dnsProxyCancel = nil
	}

	err := dnsProxyInstance.Shutdown(context.Background())
	dnsProxyInstance = nil

	return err
}

// DnsProxyRunning returns whether dnsproxy is currently running.
func DnsProxyRunning() bool {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	return dnsProxyInstance != nil
}

// ipv6BlockHandler blocks AAAA queries by returning NODATA,
// delegating all other queries to the next handler.
type ipv6BlockHandler struct {
	next proxy.Handler
}

func (h *ipv6BlockHandler) ServeDNS(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) error {
	if len(d.Req.Question) > 0 && d.Req.Question[0].Qtype == dns.TypeAAAA {
		d.Res = (&dns.Msg{}).SetReply(d.Req)
		return nil
	}

	return h.next.ServeDNS(ctx, p, d)
}
