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
	"time"

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
	dnsProxyMu        sync.Mutex
	dnsProxyInstance  *proxy.Proxy
	dnsProxyCancel    context.CancelFunc
	dnsProxyProtector SocketProtector
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
				ok := protector.ProtectFd(int32(fd))
				if !ok {
					slog.Warn("failed to protect DNS socket", "fd", fd, "network", network, "address", address)
				} else {
					slog.Debug("protected DNS socket", "fd", fd, "network", network, "address", address)
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
	dnsProxyProtector = protector

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
	dnsProxyProtector = nil

	return err
}

// DnsProxyRunning returns whether dnsproxy is currently running.
func DnsProxyRunning() bool {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	return dnsProxyInstance != nil
}

// DnsProxyHealthCheck verifies dnsproxy is running and can resolve DNS.
// Sends a query for yandex.ru to dnsproxy's own listening port from within
// the Go runtime, bypassing any vendor TUN routing quirks that affect Java sockets.
//
// The health check socket is protected via VpnService.protect() using the same
// protector passed to StartDnsProxy. On stock Android, localhost traffic uses the
// loopback interface and protection is a no-op. On some OEM devices (e.g., Honor),
// the TUN can capture localhost UDP — protection ensures the socket bypasses it.
//
// Note: after the first successful check, dnsproxy's cache (TTL 60-3600s) may serve
// the response locally. This means subsequent checks verify "dnsproxy is listening
// and responding" rather than "upstream Yandex DNS is reachable". The first check
// in a session always hits upstream.
//
// Thread safety: acquires dnsProxyMu to read dnsProxyInstance and dnsProxyProtector.
// If StopDnsProxy() is called concurrently, the query may fail — this is expected
// and returns false.
func DnsProxyHealthCheck(timeoutMs int) bool {
	dnsProxyMu.Lock()
	if dnsProxyInstance == nil {
		dnsProxyMu.Unlock()
		return false
	}
	addr := dnsProxyInstance.Addr(proxy.ProtoUDP)
	protector := dnsProxyProtector
	dnsProxyMu.Unlock()

	if addr == nil {
		return false
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}

	// Build DNS query for yandex.ru A record using miekg/dns
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("yandex.ru"), dns.TypeA)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	queryBytes, err := msg.Pack()
	if err != nil {
		slog.Warn("health check: failed to pack DNS query", "error", err)
		return false
	}

	// Send to dnsproxy on localhost — socket protected to bypass TUN on OEM devices
	timeout := time.Duration(timeoutMs) * time.Millisecond
	dialer := net.Dialer{Timeout: timeout}
	if protector != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ok := protector.ProtectFd(int32(fd))
				if !ok {
					slog.Warn("health check: failed to protect socket", "fd", fd)
				}
			})
		}
	}

	conn, err := dialer.Dial("udp",
		net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", udpAddr.Port)))
	if err != nil {
		slog.Warn("health check: failed to dial dnsproxy", "port", udpAddr.Port, "error", err)
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err = conn.Write(queryBytes); err != nil {
		slog.Warn("health check: failed to send query", "error", err)
		return false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		slog.Warn("health check: failed to read response", "error", err)
		return false
	}

	return n > 12
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
