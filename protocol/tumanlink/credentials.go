package tumanlink

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/tuman-vpn/link/client"
	tlcrypto "github.com/tuman-vpn/link/crypto"
	"github.com/tuman-vpn/link/descriptor"
)

// Same on-disk field names as linkcli. Admission counters belong exclusively to
// packetdev's admission.db; retained enrollment files are never re-imported.
type identity struct {
	DeviceID         string `json:"device_id"`
	GatewayID        string `json:"gateway_id"`
	StaticPrivateKey string `json:"static_private_key"`
	AdmissionKey     string `json:"k_adm"`
	RootPublicKey    string `json:"root_public_key"`
	Epoch            uint32 `json:"epoch"`
	VersionFloor     uint32 `json:"version_floor"`
	Counter          uint64 `json:"counter,omitempty"`
	Proven           uint64 `json:"proven,omitempty"`
	SilentAttempts   uint32 `json:"silent_attempts,omitempty"`
	M1               []byte `json:"sealed_m1,omitempty"`
}

func loadClientConfig(options option.TumanLinkEndpointOptions) (cfg client.Config, erase func(), err error) {
	erase = func() { tlcrypto.Erase(cfg.Credentials.StaticPriv[:]); tlcrypto.Erase(cfg.Credentials.AdmissionKey[:]) }
	defer func() {
		if err != nil {
			erase()
		}
	}()
	dir, err := os.Lstat(options.CredentialsPath)
	if err != nil {
		return cfg, erase, err
	}
	if !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return cfg, erase, fmt.Errorf("credentials_dir must be a private directory (0700)")
	}
	path := filepath.Join(options.CredentialsPath, "credentials.json")
	raw, err := readIdentity(path)
	if err != nil {
		return cfg, erase, err
	}
	defer tlcrypto.Erase(raw)
	var id identity
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&id); err != nil {
		return cfg, erase, fmt.Errorf("invalid credentials.json: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return cfg, erase, fmt.Errorf("trailing credentials.json data")
	}
	defer tlcrypto.Erase(id.M1)
	decode := func(s string, out []byte) error {
		if len(s) != 2*len(out) {
			return fmt.Errorf("invalid credential length")
		}
		_, err := hex.Decode(out, []byte(s))
		if err != nil {
			return fmt.Errorf("invalid credential encoding")
		}
		if bytes.Equal(out, make([]byte, len(out))) {
			return fmt.Errorf("empty credential")
		}
		return nil
	}
	var gatewayID [16]byte
	root := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for _, field := range []struct {
		value string
		out   []byte
	}{{id.DeviceID, cfg.Credentials.DeviceID[:]}, {id.GatewayID, gatewayID[:]}, {id.StaticPrivateKey, cfg.Credentials.StaticPriv[:]}, {id.AdmissionKey, cfg.Credentials.AdmissionKey[:]}, {id.RootPublicKey, root}} {
		if err = decode(field.value, field.out); err != nil {
			return cfg, erase, err
		}
	}
	if id.Epoch == 0 || id.Proven > id.Counter || len(id.M1) > 192 {
		return cfg, erase, fmt.Errorf("invalid credential state")
	}
	// A CLI file with reserved counters cannot bootstrap an empty admission DB.
	if id.Counter != 0 || id.Proven != 0 || id.SilentAttempts != 0 || len(id.M1) != 0 {
		if _, err = os.Lstat(filepath.Join(options.CredentialsPath, "admission.db")); err != nil {
			return cfg, erase, fmt.Errorf("existing admission state required: %w", err)
		}
	}
	var signedBytes []byte
	if option.TumanLinkDescriptorIsFile(options.Descriptor) {
		signedBytes, err = os.ReadFile(options.Descriptor)
	} else {
		signedBytes, err = base64.StdEncoding.DecodeString(options.Descriptor)
	}
	if err != nil {
		return cfg, erase, fmt.Errorf("read descriptor: %w", err)
	}
	cfg.Descriptor, err = descriptor.ParseSigned(signedBytes)
	if err != nil {
		return cfg, erase, err
	}
	d, err := descriptor.Verify(root, signedBytes, time.Now(), id.VersionFloor)
	if err != nil {
		return cfg, erase, err
	}
	if d.GatewayID != gatewayID {
		return cfg, erase, fmt.Errorf("descriptor gateway differs from enrolled identity")
	}
	if d.Version > id.VersionFloor {
		id.VersionFloor = d.Version
		if err = writeIdentity(path, id); err != nil {
			return cfg, erase, err
		}
	}
	cfg.RootPublicKey = root
	cfg.VersionFloor = id.VersionFloor
	cfg.Credentials.Epoch = id.Epoch
	cfg.CredentialsPath = options.CredentialsPath
	return cfg, erase, nil
}

func readIdentity(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("credentials.json must be a regular private file (0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("credentials.json changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if len(raw) > 1<<20 {
		tlcrypto.Erase(raw)
		return nil, fmt.Errorf("credentials.json too large")
	}
	return raw, err
}
func writeIdentity(path string, id identity) error {
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	defer tlcrypto.Erase(data)
	file, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
