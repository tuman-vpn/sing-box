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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/tuman-vpn/link/descriptor"
)

func credentialFixture(t *testing.T) (option.TumanLinkEndpointOptions, descriptor.Descriptor, ed25519.PrivateKey) {
	t.Helper()
	pub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desc := descriptor.Descriptor{Version: 2, GatewayID: [16]byte{2}, StaticPub: [32]byte(priv.PublicKey().Bytes()), ValidUntil: uint64(time.Now().Add(time.Hour).Unix())}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := identity{DeviceID: hex.EncodeToString(bytes.Repeat([]byte{1}, 16)), GatewayID: hex.EncodeToString(desc.GatewayID[:]), StaticPrivateKey: hex.EncodeToString(priv.Bytes()), AdmissionKey: hex.EncodeToString(bytes.Repeat([]byte{3}, 32)), RootPublicKey: hex.EncodeToString(pub), Epoch: 7, VersionFloor: 1}
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return option.TumanLinkEndpointOptions{Descriptor: base64.StdEncoding.EncodeToString(desc.Sign(root).Bytes()), CredentialsPath: dir}, desc, root
}

// Catches accepting unauthenticated, expired, wrong-gateway or rolled-back descriptors.
func TestDescriptorTrustAndVersionFloor(t *testing.T) {
	opts, desc, root := credentialFixture(t)
	cfg, erase, err := loadClientConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer erase()
	if cfg.VersionFloor != 2 || cfg.Credentials.Epoch != 7 {
		t.Fatal("identity not applied")
	}
	raw, err := os.ReadFile(filepath.Join(opts.CredentialsPath, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved identity
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.VersionFloor != 2 {
		t.Fatal("descriptor floor not persisted")
	}
	if st, err := os.Stat(filepath.Join(opts.CredentialsPath, "credentials.json")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("identity permissions changed")
	}
	for _, tc := range []struct {
		name   string
		change func(*descriptor.Descriptor)
		want   error
	}{
		{"rollback", func(d *descriptor.Descriptor) { d.Version = 1 }, descriptor.ErrVersionFloor},
		{"expired", func(d *descriptor.Descriptor) { d.ValidUntil = uint64(time.Now().Add(-time.Minute).Unix()) }, descriptor.ErrExpired},
		{"wrong gateway", func(d *descriptor.Descriptor) { d.GatewayID = [16]byte{8} }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := desc
			tc.change(&d)
			input := opts
			input.Descriptor = base64.StdEncoding.EncodeToString(d.Sign(root).Bytes())
			_, _, err := loadClientConfig(input)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	signed := desc.Sign(root).Bytes()
	signed[len(signed)-1] ^= 1
	opts.Descriptor = base64.StdEncoding.EncodeToString(signed)
	if _, _, err = loadClientConfig(opts); !errors.Is(err, descriptor.ErrBadSignature) {
		t.Fatalf("accepted forged signature: %v", err)
	}
}

// Catches resetting consumed CLI enrollment or reading public/symlinked identities.
func TestCredentialsFailClosed(t *testing.T) {
	for _, kind := range []string{"public directory", "public file", "symlink", "corrupt", "missing identity", "consumed enrollment"} {
		t.Run(kind, func(t *testing.T) {
			opts, _, _ := credentialFixture(t)
			path := filepath.Join(opts.CredentialsPath, "credentials.json")
			switch kind {
			case "public directory":
				if err := os.Chmod(opts.CredentialsPath, 0755); err != nil {
					t.Fatal(err)
				}
			case "public file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing identity":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "consumed enrollment":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var id identity
				if err = json.Unmarshal(raw, &id); err != nil {
					t.Fatal(err)
				}
				id.Counter = 10
				raw, err = json.Marshal(id)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := loadClientConfig(opts); err == nil {
				t.Fatalf("accepted %s", kind)
			}
		})
	}
}

// A detour owns its socket policy; it cannot promise an explicit physical bind.
func TestExplicitBindCannotDisappearIntoDetour(t *testing.T) {
	opts, _, _ := credentialFixture(t)
	opts.BindInterface = "en0"
	opts.Detour = "outer"
	_, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
	if err == nil || !strings.Contains(err.Error(), "bind_interface") {
		t.Fatalf("explicit bind not rejected before detour resolution: %v", err)
	}
}

// Close must interrupt outer dialing even while Start holds the lifecycle lock.
func TestCloseCancelsPendingStart(t *testing.T) {
	opts, desc, root := credentialFixture(t)
	desc.UDP = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:10002")}
	opts.Descriptor = base64.StdEncoding.EncodeToString(desc.Sign(root).Bytes())
	a, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
	if err != nil {
		t.Fatal(err)
	}
	ep := a.(*Endpoint)
	blocked := &blockedDialer{entered: make(chan struct{}), release: make(chan struct{})}
	ep.outer = blocked
	started := make(chan error, 1)
	go func() { started <- ep.Start(adapter.StartStateStart) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		close(blocked.release)
		t.Fatal("Start never reached outer dial")
	}
	closed := make(chan error, 1)
	go func() { closed <- ep.Close() }()
	select {
	case err = <-closed:
		close(blocked.release)
		if err != nil {
			t.Fatal(err)
		}
		if err = <-started; !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error = %v", err)
		}
	case <-time.After(time.Second):
		close(blocked.release)
		<-started
		<-closed
		t.Fatal("Close failed to cancel pending outer dial")
	}
}

type blockedDialer struct {
	entered chan struct{}
	release chan struct{}
}

func (d *blockedDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	close(d.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, context.Canceled
	}
}
func (d *blockedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

func TestResolverValidation(t *testing.T) {
	for _, resolver := range []string{"127.0.0.1:53", "[::1]:53", "224.0.0.1:53", "[ff02::1]:53", "[::ffff:192.0.2.1]:53", "0.0.0.0:53", "[::]:53", "[fe80::1%en0]:53", "192.0.2.53:0"} {
		t.Run(resolver, func(t *testing.T) {
			opts, _, _ := credentialFixture(t)
			opts.Resolver = resolver
			ep, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
			if ep != nil {
				ep.Close()
			}
			if err == nil {
				t.Fatalf("accepted resolver %s", resolver)
			}
		})
	}
}

// Catches base64 that looks like a path being read from disk, and a missing
// descriptor file being reported as a base64 error.
func TestDescriptorFormIsExplicit(t *testing.T) {
	opts, _, _ := credentialFixture(t)
	for _, tc := range []struct {
		input   string
		isFile  bool
		corrupt bool
	}{{"/w==", false, false}, {"./missing-descriptor", false, true}, {"/etc/hosts", false, true}, {"./missing-descriptor", true, false}} {
		opts.Descriptor, opts.DescriptorFile = tc.input, tc.isFile
		_, _, err := loadClientConfig(opts)
		var pe *os.PathError
		var ce base64.CorruptInputError
		if err == nil || errors.As(err, &pe) != tc.isFile || errors.As(err, &ce) != tc.corrupt {
			t.Fatalf("%q file=%v: %v", tc.input, tc.isFile, err)
		}
	}
}
