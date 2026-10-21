//go:build with_gvisor

package tumanlink

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/tuman-vpn/link/admission"
	"github.com/tuman-vpn/link/descriptor"
	"github.com/tuman-vpn/link/gateway"
)

// Catches lost JSON fields, descriptor union handling, and endpoint registration.
func TestOptionsJSONRoundTrip(t *testing.T) {
	for _, desc := range []string{`"YWJj"`, `{"base64":"YWJj"}`, `{"file":"./gateway.tl1"}`} {
		raw := `{"descriptor":` + desc + `,"credentials_dir":"/private/tl1","setup_order":["udp","dns"],"resolver":"192.0.2.53:53","direct_timeout":"3s","mtu":1280,"workers":2,"bind_interface":"en0"}`
		var opts option.TumanLinkEndpointOptions
		if err := json.Unmarshal([]byte(raw), &opts); err != nil {
			t.Fatal(err)
		}
		if opts.CredentialsPath != "/private/tl1" || opts.DirectTimeout != badoption.Duration(3*time.Second) || opts.BindInterface != "en0" || opts.Workers != 2 || opts.MTU != 1280 || opts.Resolver != "192.0.2.53:53" || strings.Join(opts.SetupOrder, ",") != "udp,dns" {
			t.Fatalf("lost options: %+v", opts)
		}
		want := "YWJj"
		if strings.Contains(desc, "file") {
			want = "./gateway.tl1"
		}
		if opts.Descriptor != want {
			t.Fatalf("descriptor = %q", opts.Descriptor)
		}
		encoded, err := json.Marshal(opts)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err = json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if len(wire["descriptor"]) == 0 || wire["descriptor"][0] != '{' {
			t.Fatalf("descriptor must marshal as documented object: %s", encoded)
		}
		var again option.TumanLinkEndpointOptions
		if err = json.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
		if again.Descriptor != want || again.DescriptorFile != strings.Contains(desc, "file") || again.CredentialsPath != opts.CredentialsPath {
			t.Fatal(string(encoded))
		}
	}
	for _, raw := range []string{`{"descriptor":{"base64":"a","file":"b"}}`, `{"descriptor":{}}`, `{"descriptor":{"unknown":"a"}}`} {
		var opts option.TumanLinkEndpointOptions
		if json.Unmarshal([]byte(raw), &opts) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	registry := endpoint.NewRegistry()
	RegisterEndpoint(registry)
	if _, ok := registry.CreateOptions(C.TypeTumanLink); !ok {
		t.Fatal("endpoint not registered")
	}
}

type logBuffer struct {
	sync.Mutex
	data bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.data.Write(p) }
func (b *logBuffer) String() string              { b.Lock(); defer b.Unlock(); return b.data.String() }

type testLeases struct{}

func (testLeases) Acquire([16]byte) (gateway.Lease, error) {
	return gateway.Lease{V4: [4]byte{10, 77, 0, 2}, V4PrefixLen: 16, InnerMTU: 1280, LeaseID: 1}, nil
}
func (testLeases) Release([16]byte, bool) {}

type fixture struct {
	gateway *gateway.Gateway
	ep      *Endpoint
	logs    *logBuffer
	desc    descriptor.Descriptor
	root    ed25519.PrivateKey
	dir     string
}

type fixtureHooks struct {
	gateway  func(*gateway.Options)
	endpoint func(*Endpoint)
}

func newFixture(t *testing.T, carrier string, stale bool, virtual bool, hooks ...fixtureHooks) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	var address netip.AddrPort
	var send func(gateway.Tuple, []byte) error
	var receive func(*gateway.Gateway)
	var outer N.Dialer
	if virtual {
		memory := &memoryNetwork{ctx: ctx, clients: make(map[netip.AddrPort]*memoryConn), outgoing: make(chan memoryDatagram, 1024)}
		address = netip.MustParseAddrPort("127.0.0.1:10002")
		memory.server = address
		send = memory.send
		receive = memory.receive
		outer = memory
	} else {
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("sandbox denies UDP socket bind: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sock.Close() })
		address = sock.LocalAddr().(*net.UDPAddr).AddrPort()
		send = func(to gateway.Tuple, p []byte) error { _, err := sock.WriteToUDPAddrPort(p, to.Remote); return err }
		receive = func(gw *gateway.Gateway) {
			var b [2048]byte
			for {
				n, from, err := sock.ReadFromUDPAddrPort(b[:])
				if err != nil {
					return
				}
				gw.Ingress(b[:n], gateway.Tuple{Local: address, Remote: from})
			}
		}
	}
	rootPub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desc := descriptor.Descriptor{Version: 1, GatewayID: [16]byte{2}, StaticPub: [32]byte(gp.PublicKey().Bytes()), UDP: []netip.AddrPort{address}, ValidUntil: uint64(time.Now().Add(time.Hour).Unix()), Limits: descriptor.Limits{MaxRecord: 1472, InnerMTU: 1280}}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	creds := map[string]any{"device_id": hex.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), "gateway_id": hex.EncodeToString(desc.GatewayID[:]), "static_private_key": hex.EncodeToString(dp.Bytes()), "k_adm": hex.EncodeToString(bytes.Repeat([]byte{3}, 32)), "root_public_key": hex.EncodeToString(rootPub), "epoch": 7, "version_floor": 0}
	raw, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "credentials.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := admission.OpenBoltStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	internet := channel.New(1024, 1280, "")
	internetStack, err := tun.NewGVisorStackWithOptions(internet, stack.NICOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		internet.Close()
		for _, ep := range internetStack.CleanupEndpoints() {
			ep.Abort()
		}
		internetStack.Close()
		internetStack.Wait()
	})
	echoIP := netip.MustParseAddr("198.18.0.1")
	if e := internetStack.AddProtocolAddress(tun.DefaultNIC, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tun.AddressFromAddr(echoIP), PrefixLen: 32}}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	listener, err := gonet.ListenTCP(internetStack, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(echoIP), Port: 8080}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	current := desc
	if stale {
		current.Version++
	}
	gwOptions := gateway.Options{StaticPriv: [32]byte(gp.Bytes()), Descriptors: []descriptor.Descriptor{current}, Devices: []gateway.DeviceRecord{{Slot: 1, ID: [16]byte{1}, PublicKey: [32]byte(dp.PublicKey().Bytes()), AdmissionKey: [32]byte(bytes.Repeat([]byte{3}, 32)), Epoch: 7}}, Store: store, Leases: testLeases{}, Send: func(_ int, to gateway.Tuple, p []byte) error { return send(to, p) }, Deliver: func(_ int, _ gateway.Lease, p []byte) {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(p))})
		defer pb.DecRef()
		proto := header.IPv4ProtocolNumber
		if header.IPVersion(p) == 6 {
			proto = header.IPv6ProtocolNumber
		}
		internet.InjectInbound(proto, pb)
	}}
	for _, hook := range hooks {
		if hook.gateway != nil {
			hook.gateway(&gwOptions)
		}
	}
	gw, err := gateway.New(gateway.Config{Carrier: carrier, Listen: desc.UDP[0], Workers: 2}, gwOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	go receive(gw)
	go func() {
		for {
			pb := internet.ReadContext(ctx)
			if pb == nil {
				return
			}
			v := pb.ToView()
			gw.RouteDownlink(v.AsSlice())
			v.Release()
			pb.DecRef()
		}
	}()
	logs := new(logBuffer)
	factory, err := log.New(log.Options{Context: ctx, Options: option.LogOptions{DisableColor: true}, DefaultWriter: logs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { factory.Close() })
	// Exercise descriptor file loading for RTP, base64 for compact UDP.
	input := base64.StdEncoding.EncodeToString(desc.Sign(root).Bytes())
	if carrier == "rtp" {
		input = filepath.Join(dir, "gateway.tl1")
		if err = os.WriteFile(input, desc.Sign(root).Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	opts := option.TumanLinkEndpointOptions{Descriptor: input, DescriptorFile: carrier == "rtp", CredentialsPath: dir, SetupOrder: []string{carrier}, Workers: 2}
	if carrier == "quic" {
		opts.CoverSNI = []string{"cover-a.example", "github.com"}
		opts.CoverProbation = badoption.Duration(30 * time.Second)
	}
	ep, err := NewEndpoint(ctx, nil, factory.NewLogger("tl1"), "tl1", opts)
	if err != nil {
		t.Fatal(err)
	}
	if outer != nil {
		ep.(*Endpoint).outer = outer
	}
	for _, hook := range hooks {
		if hook.endpoint != nil {
			hook.endpoint(ep.(*Endpoint))
		}
	}
	t.Cleanup(func() { ep.Close() })
	if err = ep.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	if err = ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	return &fixture{gateway: gw, ep: ep.(*Endpoint), logs: logs, desc: desc, root: root, dir: dir}
}
func awaitLog(t *testing.T, b *logBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing %q in %s", want, b.String())
}

// Catches broken packet offsets, admission, event consumption, and TCP downlink.
func TestEndpointLoopback(t *testing.T) { testEndpointLoopback(t, false) }
func TestEndpointInMemory(t *testing.T) { testEndpointLoopback(t, true) }
func testEndpointLoopback(t *testing.T, virtual bool) {
	for _, carrier := range []string{"udp", "rtp", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			f := newFixture(t, carrier, false, virtual)
			awaitLog(t, f.logs, "Lease")
			logs := f.logs.String()
			if i, j := strings.Index(logs, ": Up\n"), strings.Index(logs, ": Lease\n"); i < 0 || j < 0 || i >= j || strings.Count(logs, ": Up\n") != 1 || strings.Count(logs, ": Lease\n") != 1 {
				t.Fatalf("event order: %s", logs)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			conn, err := f.ep.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.1:8080"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			if err = conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 1<<20)
			if _, err = rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			writeErr := make(chan error, 1)
			go func() { _, e := io.Copy(conn, bytes.NewReader(payload)); writeErr <- e }()
			got := make([]byte, len(payload))
			if n, readErr := io.ReadFull(conn, got); readErr != nil {
				t.Fatalf("TCP echo read %d/%d bytes: %v (gateway: %+v)", n, len(got), readErr, f.gateway.Stats())
			}
			if err = <-writeErr; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("corrupt TCP echo")
			}
			// Network hints and close are safe after admission and repeated Close.
			f.ep.InterfaceUpdated()
			if err = f.ep.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.ep.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A valid but obsolete descriptor must surface packetdev.Err on Refresh.
func TestStaleDescriptorRefresh(t *testing.T)         { testStaleDescriptorRefresh(t, false) }
func TestStaleDescriptorRefreshInMemory(t *testing.T) { testStaleDescriptorRefresh(t, true) }
func testStaleDescriptorRefresh(t *testing.T, virtual bool) {
	f := newFixture(t, "udp", true, virtual)
	awaitLog(t, f.logs, "Refresh")
	if f.ep.Err() == nil {
		t.Fatal("Refresh lost cause")
	}
	if !strings.Contains(f.logs.String(), f.ep.Err().Error()) {
		t.Fatalf("cause not logged: %s", f.logs.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := f.ep.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.1:8080")); err == nil {
		c.Close()
		t.Fatal("dial after Refresh succeeded")
	}
}
