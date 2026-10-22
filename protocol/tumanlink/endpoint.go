package tumanlink

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transport "github.com/sagernet/sing-box/transport/tumanlink"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/tuman-vpn/link/carrier/quic"
	"github.com/tuman-vpn/link/client"
	tlcrypto "github.com/tuman-vpn/link/crypto"
	"github.com/tuman-vpn/link/descriptor"
	"github.com/tuman-vpn/link/host/packetdev"
)

var ErrDescriptorRefreshRequired = errors.New("tuman-link: descriptor refresh required")

var (
	_ adapter.Endpoint                = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TumanLinkEndpointOptions](registry, C.TypeTumanLink, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx        context.Context
	cancel     context.CancelFunc
	logger     log.ContextLogger
	options    option.TumanLinkEndpointOptions
	clock      client.Clock
	outer      N.Dialer
	dns        adapter.DNSRouter
	network    adapter.NetworkManager
	changes    chan struct{}
	lifecycle  sync.Mutex
	mu         sync.RWMutex
	started    bool
	device     *packetdev.Device
	stack      transport.Device
	ready      bool
	closed     bool
	eventsDone chan struct{}
	closeErr   error
	lastErr    error
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TumanLinkEndpointOptions) (adapter.Endpoint, error) {
	if options.Descriptor == "" || options.CredentialsPath == "" {
		return nil, fmt.Errorf("tuman-link requires descriptor and credentials_dir")
	}
	var seen [2]bool
	for _, name := range options.SetupOrder {
		path := 0
		switch name {
		case "direct", "rtp", "udp", "quic":
		case "dns":
			path = 1
		default:
			return nil, fmt.Errorf("tuman-link setup_order: unknown path %q", name)
		}
		if seen[path] {
			return nil, fmt.Errorf("tuman-link setup_order: duplicate direct or dns path %q", name)
		}
		seen[path] = true
	}
	if _, err := normalizeCoverSNIs(options.CoverSNI); err != nil {
		return nil, err
	}
	if _, err := quic.ParseProfile(options.CoverProfile); err != nil {
		return nil, fmt.Errorf("tuman-link cover_profile: %w", err)
	}
	if options.CoverProfile != "" && !slices.Contains(options.SetupOrder, "quic") {
		return nil, fmt.Errorf("tuman-link cover_profile: requires quic in setup_order")
	}
	if options.CoverProbation < 0 || time.Duration(options.CoverProbation)%time.Second != 0 {
		return nil, fmt.Errorf("tuman-link cover_probation must be a non-negative whole number of seconds")
	}
	if options.MTU != 0 && (options.MTU < 1280 || options.MTU > 1400) {
		return nil, fmt.Errorf("tuman-link MTU must be 1280–1400")
	}
	if options.Workers < 0 || options.Workers > 256 {
		return nil, fmt.Errorf("invalid tuman-link workers")
	}
	if options.DirectTimeout < 0 || time.Duration(options.DirectTimeout) > 7*time.Second {
		return nil, fmt.Errorf("direct_timeout must be 0–7s")
	}
	if options.Resolver != "" {
		ap, err := netip.ParseAddrPort(options.Resolver)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsLoopback() || ap.Addr().IsMulticast() || ap.Addr().Is4In6() || ap.Addr().Zone() != "" {
			return nil, fmt.Errorf("invalid numeric resolver")
		}
	}
	if options.Detour != "" && options.BindInterface != "" {
		return nil, fmt.Errorf("bind_interface cannot be honored through a detour")
	}
	outer, err := dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options.DialerOptions})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Endpoint{cancel: cancel, Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeTumanLink, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions), ctx: ctx, logger: logger, options: options, outer: outer, dns: service.FromContext[adapter.DNSRouter](ctx), network: service.FromContext[adapter.NetworkManager](ctx), changes: make(chan struct{}, 1)}, nil
}

func normalizeCoverSNIs(pool []string) ([]string, error) {
	var names []string
	seen := make(map[string]bool)
	for _, entry := range pool {
		for _, name := range strings.Split(entry, ",") {
			if name == "" || (descriptor.Descriptor{CoverSNI: name}).Validate() != nil {
				return nil, fmt.Errorf("tuman-link cover_sni: invalid DNS hostname %q", name)
			}
			// Validate admits lowercase names only, so exact matching is enough.
			if seen[name] {
				return nil, fmt.Errorf("tuman-link cover_sni: duplicate DNS hostname %q", name)
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.RLock()
	closed, started := e.closed, e.started
	e.mu.RUnlock()
	if closed {
		return net.ErrClosed
	}
	if started {
		return nil
	}
	device, s, err := e.buildDevice()
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.device, e.stack = device, s
	e.started = true
	done := make(chan struct{})
	e.eventsDone = done
	e.mu.Unlock()
	go e.watchEvents(device, s, done)
	return nil
}

// Each generation reloads both provisioning files. The old stack is retired
// before publishing a replacement, and only its Lease makes dialing ready.
func (e *Endpoint) buildDevice() (*packetdev.Device, transport.Device, error) {
	cfg, erase, err := e.clientConfig()
	if err != nil {
		return nil, nil, err
	}
	defer erase()
	defer tlcrypto.Erase(cfg.Credentials.StaticPriv[:])
	defer tlcrypto.Erase(cfg.Credentials.AdmissionKey[:])
	device, err := packetdev.New(e.ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	s, err := transport.NewStackDevice(e.ctx, device, e.options.MTU, e.options.Workers)
	if err != nil {
		device.Close()
		return nil, nil, err
	}
	device.SetNetworkChangeSource(e.changes)
	return device, s, nil
}

func reconnectDelay(base time.Duration) time.Duration {
	return time.Duration(float64(base) * (0.8 + rand.Float64()*0.4))
}

func (e *Endpoint) watchEvents(device *packetdev.Device, s transport.Device, done chan struct{}) {
	defer close(done)
	backoff := time.Second
	for {
		var gen generation
		for event := range device.Events() {
			if event == packetdev.Lease {
				backoff = time.Second
			}
			e.handleEvent(device, s, event, &gen)
		}
		e.mu.Lock()
		e.ready = false
		e.device, e.stack = nil, nil
		e.mu.Unlock()

		closeErr := s.Close()
		if e.ctx.Err() != nil {
			e.mu.Lock()
			e.closeErr = closeErr
			e.mu.Unlock()
			return
		}
		if closeErr != nil {
			e.logger.Debug("close device: ", closeErr)
		}
		for {
			timer := time.NewTimer(reconnectDelay(backoff))
			select {
			case <-e.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, 30*time.Second)
			var err error
			device, s, err = e.buildDevice()
			if err != nil {
				if e.ctx.Err() != nil {
					return
				}
				e.mu.Lock()
				e.lastErr = err
				e.mu.Unlock()
				e.logger.Error("reconnect: ", err)
				continue
			}
			e.mu.Lock()
			if e.closed || e.ctx.Err() != nil {
				e.mu.Unlock()
				s.Close()
				return
			}
			e.device, e.stack = device, s
			e.mu.Unlock()
			break
		}
	}
}

// generation is the per-device event state.
type generation struct {
	notified  error // last cause passed to the auth-failure handler
	epochSeen bool  // an epoch Refresh was already classified
}

// refreshCause classifies a Refresh. Link v0.1.0 emits Refresh either with
// client.ErrCredentialEpochRequired or with no cause (descriptor refresh), and
// packetdev.Err keeps the last non-nil cause of any event, so it cannot be
// read as the Refresh's own cause: after a Degraded(err) or an earlier epoch
// Refresh it would still report that older cause.
func refreshCause(current error, gen *generation) error {
	if !gen.epochSeen && errors.Is(current, client.ErrCredentialEpochRequired) {
		gen.epochSeen = true
		return current
	}
	return ErrDescriptorRefreshRequired
}

func (e *Endpoint) handleEvent(device *packetdev.Device, s transport.Device, event packetdev.Event, gen *generation) {
	switch event {
	case packetdev.Up:
		e.logger.Info("Up")
	case packetdev.Lease:
		if err := s.ApplyLease(device.Lease()); err != nil {
			e.logger.Error("Lease: ", err)
			e.mu.Lock()
			e.ready = false
			e.mu.Unlock()
			s.CloseConnections()
			return
		}
		s.SetMTU(device.MTU())
		e.mu.Lock()
		e.ready = !e.closed && e.ctx.Err() == nil
		e.mu.Unlock()
		e.logger.Info("Lease")
	case packetdev.MTUChanged:
		s.SetMTU(device.MTU())
	case packetdev.Down, packetdev.Refresh:
		e.mu.Lock()
		e.ready = false
		closed := e.closed || e.ctx.Err() != nil
		e.mu.Unlock()
		s.CloseConnections()
		name := "Down"
		if event == packetdev.Refresh {
			name = "Refresh"
		}
		cause := device.Err()
		if event == packetdev.Refresh {
			cause = refreshCause(cause, gen)
		}
		if cause != nil {
			e.mu.Lock()
			e.lastErr = cause
			e.mu.Unlock()
			e.logger.Error(name, ": ", cause)
			if !closed && !errors.Is(cause, gen.notified) && (errors.Is(cause, client.ErrCredentialEpochRequired) || event == packetdev.Refresh) {
				notifyAuthFailure(e.Tag(), cause)
				gen.notified = cause
			}
		} else {
			e.logger.Info(name)
		}
	case packetdev.Degraded:
		e.logger.Warn("Degraded")
	case packetdev.PathChanged:
		e.logger.Debug("PathChanged")
	}
}

func (e *Endpoint) Close() error {
	e.cancel()
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return e.closeErr
	}
	e.closed, e.ready = true, false
	done := e.eventsDone
	e.mu.Unlock()
	// Cancellation closes packetdev even during a blocked outer dial. The
	// watcher owns stack teardown and never takes lifecycle, avoiding deadlock.
	if done != nil {
		<-done
	}
	return e.closeErr
}
func (e *Endpoint) InterfaceUpdated() {
	select {
	case e.changes <- struct{}{}:
	default:
	}
}
func (e *Endpoint) currentStack() (transport.Device, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, net.ErrClosed
	}
	if !e.ready {
		return nil, fmt.Errorf("tuman-link is not ready")
	}
	return e.stack, nil
}
func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	s, err := e.currentStack()
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		if e.dns == nil {
			return nil, fmt.Errorf("missing DNS router")
		}
		addresses, err := e.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, s, network, destination, addresses)
	}
	return s.DialContext(ctx, network, destination)
}
func (e *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	s, err := e.currentStack()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		if e.dns == nil {
			return nil, netip.Addr{}, fmt.Errorf("missing DNS router")
		}
		addresses, err := e.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return N.ListenSerial(ctx, s, destination, addresses)
	}
	conn, err := s.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return conn, destination.Addr, nil
}
func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, address, err := e.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if address.IsValid() && destination != M.SocksaddrFrom(address, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(address, destination.Port), destination), nil
	}
	return conn, nil
}
func (e *Endpoint) clientConfig() (client.Config, func(), error) {
	covers, err := normalizeCoverSNIs(e.options.CoverSNI)
	if err != nil {
		return client.Config{}, nil, err
	}
	cfg, erase, err := loadClientConfig(e.options)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Clock = e.clock
	cfg.BindIface = e.options.BindInterface
	cfg.SetupOrder = append([]string(nil), e.options.SetupOrder...)
	cfg.CoverSNIs = covers
	cfg.CoverProfile = e.options.CoverProfile
	cfg.NoCoverProbe = e.options.NoCoverProbe
	cfg.CoverProbationS = int(time.Duration(e.options.CoverProbation) / time.Second)
	cfg.SetupPolicy.DirectTimeout = time.Duration(e.options.DirectTimeout)
	if e.options.Resolver != "" {
		cfg.Resolver = netip.MustParseAddrPort(e.options.Resolver)
	}
	cfg.Dial = func(ctx context.Context, ap netip.AddrPort, iface string) (net.Conn, error) {
		if iface != e.options.BindInterface {
			return nil, errors.New("unexpected outer bind interface")
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(e.ctx, cancel)
		defer stop()
		return e.outer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(ap))
	}
	cfg.RouteAvailable = func(family int) bool {
		if e.network == nil {
			return true
		}
		monitor := e.network.InterfaceMonitor()
		if monitor == nil {
			return true
		}
		iface := monitor.DefaultInterface()
		if iface == nil {
			return false
		}
		if e.options.BindInterface != "" {
			for _, candidate := range e.network.NetworkInterfaces() {
				if candidate.Name == e.options.BindInterface {
					iface = &candidate.Interface
					break
				}
			}
			if iface.Name != e.options.BindInterface {
				return false
			}
		}
		for _, prefix := range iface.Addresses {
			addr := prefix.Addr()
			if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && (family == 4 && addr.Is4() || family == 6 && addr.Is6()) {
				return true
			}
		}
		return false
	}
	return cfg, erase, nil
}

// Err retains the last host or packet-device failure. Older link modules omit
// the cause on descriptor Refresh; keep an actionable fallback in that case.
func (e *Endpoint) Err() error { e.mu.RLock(); defer e.mu.RUnlock(); return e.lastErr }
