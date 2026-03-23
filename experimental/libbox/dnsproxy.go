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

var (
	// Stored for watchdog restart
	dnsProxyOpts      *DnsProxyOptions
	dnsProxyWatchdog  context.CancelFunc
	dnsProxyUnhealthy bool // true when watchdog gave up (3 restarts failed)
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

	port, err := startProxyLocked(opts, protector)
	if err != nil {
		return 0, err
	}

	// Managed here, not in startProxyLocked (watchdog restarts must not reset these)
	dnsProxyOpts = opts
	dnsProxyUnhealthy = false

	slog.Info("dnsproxy started", "port", port)

	// Start runtime watchdog for auto-recovery
	watchCtx, watchCancel := context.WithCancel(context.Background())
	dnsProxyWatchdog = watchCancel
	startWatchdog(watchCtx, 5*time.Second, 1500, 2, 3)

	return port, nil
}

// StopDnsProxy shuts down the running dnsproxy instance.
func StopDnsProxy() error {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	// Stop watchdog first
	if dnsProxyWatchdog != nil {
		dnsProxyWatchdog()
		dnsProxyWatchdog = nil
	}

	stopProxyLocked()
	dnsProxyProtector = nil
	dnsProxyOpts = nil
	dnsProxyUnhealthy = false

	return nil
}

// startProxyLocked starts dnsproxy with the given config. Caller must hold dnsProxyMu.
func startProxyLocked(opts *DnsProxyOptions, protector SocketProtector) (int, error) {
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
		Logger:  slog.Default(),
		Timeout: 5 * time.Second,
	}

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
	// Note: dnsProxyOpts and dnsProxyUnhealthy are managed by callers,
	// not here. StartDnsProxy sets them; watchdog leaves them alone.

	return udpAddr.Port, nil
}

// stopProxyLocked stops dnsproxy. Caller must hold dnsProxyMu.
// Does NOT clear dnsProxyOpts/dnsProxyProtector (needed for restart).
func stopProxyLocked() {
	if dnsProxyInstance == nil {
		return
	}
	if dnsProxyCancel != nil {
		dnsProxyCancel()
		dnsProxyCancel = nil
	}
	_ = dnsProxyInstance.Shutdown(context.Background())
	dnsProxyInstance = nil
}

// startWatchdog launches a goroutine that periodically health-checks dnsproxy
// and restarts it on persistent failure. Stops when ctx is cancelled (via StopDnsProxy).
//
// Parameters:
//   - checkInterval: time between health checks (5s recommended)
//   - checkTimeout: health check UDP timeout in ms (1500 recommended — cache-warm)
//   - maxConsecFails: consecutive failures before restart (2)
//   - maxRestarts: give up and set unhealthy flag after this many failed restarts (3)
func startWatchdog(ctx context.Context, checkInterval time.Duration, checkTimeout int, maxConsecFails int, maxRestarts int) {
	go func() {
		consecFails := 0
		failedRestarts := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(checkInterval):
			}

			if DnsProxyHealthCheck(checkTimeout) {
				consecFails = 0
				continue
			}

			consecFails++
			slog.Warn("dnsproxy watchdog: health check failed",
				"consecutive_failures", consecFails,
				"failed_restarts_so_far", failedRestarts)

			if consecFails < maxConsecFails {
				continue
			}

			// Persistent failure — restart
			if failedRestarts >= maxRestarts {
				slog.Error("dnsproxy watchdog: max failed restarts reached, marking unhealthy",
					"max_restarts", maxRestarts)
				dnsProxyMu.Lock()
				dnsProxyUnhealthy = true
				dnsProxyMu.Unlock()
				return
			}

			slog.Warn("dnsproxy watchdog: restarting proxy", "attempt", failedRestarts+1)
			dnsProxyMu.Lock()
			// Guard: StopDnsProxy may have run between health check and here.
			// Check context AND module state to avoid restarting a stopped proxy.
			if ctx.Err() != nil {
				dnsProxyMu.Unlock()
				return
			}
			opts := dnsProxyOpts
			protector := dnsProxyProtector
			if opts == nil || dnsProxyInstance == nil {
				dnsProxyMu.Unlock()
				return // proxy was stopped externally
			}
			stopProxyLocked()
			_, err := startProxyLocked(opts, protector)
			dnsProxyMu.Unlock()

			if err != nil {
				slog.Error("dnsproxy watchdog: restart failed", "error", err)
				failedRestarts++
			} else {
				slog.Info("dnsproxy watchdog: restart succeeded")
				consecFails = 0
			}
		}
	}()
}

// DnsProxyHealthy returns true if dnsproxy is running AND the watchdog
// has not given up. Returns false if the watchdog exhausted its restart
// attempts, meaning dnsproxy is in a persistently broken state.
// Kotlin polls this via componentHealthChecker every 30s.
func DnsProxyHealthy() bool {
	dnsProxyMu.Lock()
	defer dnsProxyMu.Unlock()

	return dnsProxyInstance != nil && !dnsProxyUnhealthy
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
