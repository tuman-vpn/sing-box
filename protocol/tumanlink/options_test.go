package tumanlink

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Catches invalid setup paths, cover pools and fractional probation at check time.
func TestSetupAndCoverValidation(t *testing.T) {
	for _, tc := range []struct {
		name, fields, want string
	}{
		{"defaults", ``, ""},
		{"quic", `,"setup_order":["quic"]`, ""},
		{"quic dns", `,"setup_order":["quic","dns"]`, ""},
		{"chrome profile", `,"setup_order":["quic"],"cover_profile":"chrome"`, ""},
		{"chrome one packet profile", `,"setup_order":["quic"],"cover_profile":"chrome-1pkt"`, ""},
		{"apple profile", `,"setup_order":["quic"],"cover_profile":"apple"`, ""},
		{"profile with dns first", `,"setup_order":["dns","quic"],"cover_profile":"apple"`, ""},
		{"invalid profile", `,"setup_order":["quic"],"cover_profile":"firefox"`, "tuman-link cover_profile:"},
		{"profile with default order", `,"cover_profile":"apple"`, "tuman-link cover_profile: requires quic in setup_order"},
		{"profile with rtp", `,"setup_order":["rtp"],"cover_profile":"chrome"`, "tuman-link cover_profile: requires quic in setup_order"},
		{"profile with udp", `,"setup_order":["udp","dns"],"cover_profile":"chrome-1pkt"`, "tuman-link cover_profile: requires quic in setup_order"},
		{"profile with direct", `,"setup_order":["direct"],"cover_profile":"apple"`, "tuman-link cover_profile: requires quic in setup_order"},
		{"profile with dns only", `,"setup_order":["dns"],"cover_profile":"apple"`, "tuman-link cover_profile: requires quic in setup_order"},
		{"dns quic", `,"setup_order":["dns","quic"]`, ""},
		{"udp dns", `,"setup_order":["udp","dns"]`, ""},
		{"direct", `,"setup_order":["direct"]`, ""},
		{"rtp", `,"setup_order":["rtp"]`, ""},
		{"two direct paths", `,"setup_order":["quic","rtp"]`, "setup_order"},
		{"duplicate quic", `,"setup_order":["quic","quic"]`, "setup_order"},
		{"duplicate dns", `,"setup_order":["dns","dns"]`, "setup_order"},
		{"unknown path", `,"setup_order":["tcp"]`, "setup_order"},
		{"single cover", `,"cover_sni":"github.com"`, ""},
		{"cover array", `,"cover_sni":["a.example","b.example"]`, ""},
		{"comma cover", `,"cover_sni":"a.example,b.example"`, ""},
		{"comma array", `,"cover_sni":["a.example,b.example","c.example"]`, ""},
		{"empty cover", `,"cover_sni":""`, "cover_sni: invalid"},
		{"empty comma entry", `,"cover_sni":"a.example,,b.example"`, "cover_sni: invalid"},
		{"uppercase cover", `,"cover_sni":"A.example"`, "cover_sni: invalid"},
		{"trailing dot cover", `,"cover_sni":"a.example."`, "cover_sni: invalid"},
		{"repeated cover", `,"cover_sni":["a.example","a.example"]`, "cover_sni: duplicate"},
		{"duplicate across comma entries", `,"cover_sni":["a.example,b.example","a.example"]`, "cover_sni: duplicate"},
		{"space in cover", `,"cover_sni":"bad name"`, "cover_sni: invalid"},
		{"invalid cover label", `,"cover_sni":"-x.example"`, "cover_sni: invalid"},
		{"zero probation", `,"cover_probation":"0s"`, ""},
		{"probation", `,"cover_probation":"30s"`, ""},
		{"negative probation", `,"cover_probation":"-1s"`, "cover_probation"},
		{"fractional probation", `,"cover_probation":"1500ms"`, "cover_probation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts option.TumanLinkEndpointOptions
			if err := json.Unmarshal([]byte(`{"descriptor":"YWJj","credentials_dir":"/nonexistent"`+tc.fields+`}`), &opts); err != nil {
				t.Fatal(err)
			}
			ep, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
			if ep != nil {
				ep.Close()
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s error, got %v", tc.want, err)
			}
		})
	}
}

// Catches cover_profile lost between endpoint options and the link client.
func TestClientCoverProfileConfig(t *testing.T) {
	for _, profile := range []string{"", "chrome", "chrome-1pkt", "apple"} {
		t.Run(profile, func(t *testing.T) {
			opts, _, _ := credentialFixture(t)
			raw := `{"descriptor":"` + opts.Descriptor + `","credentials_dir":"` + opts.CredentialsPath + `","setup_order":["quic"],"cover_profile":"` + profile + `"}`
			if err := json.Unmarshal([]byte(raw), &opts); err != nil {
				t.Fatal(err)
			}
			a, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			cfg, erase, err := a.(*Endpoint).clientConfig()
			if err != nil {
				t.Fatal(err)
			}
			defer erase()
			if cfg.CoverProfile != profile {
				t.Fatalf("CoverProfile = %q, want %q", cfg.CoverProfile, profile)
			}
		})
	}
}

// Catches cover options lost or reordered between endpoint JSON and client.Config.
func TestClientCoverConfig(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		covers       []string
		noProbe      bool
		probation    int
		order        []string
	}{
		{"defaults", "", nil, false, 0, nil},
		{"pool", `,"cover_sni":["cover-a.example","cover-b.example"],"no_cover_probe":true,"cover_probation":"30s","setup_order":["quic"]`, []string{"cover-a.example", "cover-b.example"}, true, 30, []string{"quic"}},
		{"comma pool", `,"cover_sni":["cover-a.example,cover-b.example","cover-c.example"]`, []string{"cover-a.example", "cover-b.example", "cover-c.example"}, false, 0, nil},
		{"comma string", `,"cover_sni":"cover-a.example,cover-b.example"`, []string{"cover-a.example", "cover-b.example"}, false, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, _ := credentialFixture(t)
			raw := `{"descriptor":"` + opts.Descriptor + `","credentials_dir":"` + opts.CredentialsPath + `"` + tc.fields + `}`
			if err := json.Unmarshal([]byte(raw), &opts); err != nil {
				t.Fatal(err)
			}
			a, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "tl1", opts)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			cfg, erase, err := a.(*Endpoint).clientConfig()
			if err != nil {
				t.Fatal(err)
			}
			defer erase()
			if !reflect.DeepEqual(cfg.CoverSNIs, tc.covers) || cfg.NoCoverProbe != tc.noProbe || cfg.CoverProbationS != tc.probation || !reflect.DeepEqual(cfg.SetupOrder, tc.order) {
				t.Fatalf("covers=%v probe=%v probation=%d order=%v", cfg.CoverSNIs, cfg.NoCoverProbe, cfg.CoverProbationS, cfg.SetupOrder)
			}
		})
	}
}
