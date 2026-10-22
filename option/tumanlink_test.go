package option

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Catches cover fields lost by the descriptor-union JSON methods.
func TestTumanLinkCoverJSONRoundTrip(t *testing.T) {
	for _, cover := range []string{`"github.com"`, `["a.example","b.example"]`, `"a.example,b.example"`, `["a.example,b.example","c.example"]`} {
		t.Run(cover, func(t *testing.T) {
			raw := `{"descriptor":{"base64":"YWJj"},"credentials_dir":"/private/tl1","setup_order":["quic","dns"],"cover_sni":` + cover + `,"no_cover_probe":true,"cover_probation":"30s"}`
			var opts TumanLinkEndpointOptions
			if err := json.Unmarshal([]byte(raw), &opts); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(opts)
			if err != nil {
				t.Fatal(err)
			}
			var want, got map[string]any
			if err = json.Unmarshal([]byte(raw), &want); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("lost options: %s", encoded)
			}
			var again TumanLinkEndpointOptions
			if err = json.Unmarshal(encoded, &again); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(again, opts) {
				t.Fatalf("round trip changed options: %+v", again)
			}
		})
	}
}

// Catches misspelled options being ignored instead of failing check.
func TestTumanLinkUnknownField(t *testing.T) {
	for _, field := range []string{"cover_snis", "cover_profiles"} {
		var opts TumanLinkEndpointOptions
		err := json.Unmarshal([]byte(`{"descriptor":"YWJj","credentials_dir":"/private/tl1","`+field+`":"apple"}`), &opts)
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("accepted unknown field %s: %v", field, err)
		}
	}
}

// Catches cover_profile rejected, lost by the descriptor union, or emitted when omitted.
func TestTumanLinkCoverProfileJSONRoundTrip(t *testing.T) {
	for _, profile := range []string{"", "chrome", "chrome-1pkt", "apple"} {
		t.Run(profile, func(t *testing.T) {
			raw := `{"descriptor":{"base64":"YWJj"},"credentials_dir":"/private/tl1","setup_order":["quic"]`
			if profile != "" {
				raw += `,"cover_profile":"` + profile + `"`
			}
			raw += `}`
			var opts TumanLinkEndpointOptions
			if err := json.Unmarshal([]byte(raw), &opts); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(opts)
			if err != nil {
				t.Fatal(err)
			}
			var want, got map[string]any
			if err = json.Unmarshal([]byte(raw), &want); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cover profile changed: %s", encoded)
			}
			var again TumanLinkEndpointOptions
			if err = json.Unmarshal(encoded, &again); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(again, opts) {
				t.Fatalf("round trip changed options: %+v", again)
			}
		})
	}
}

// Catches `sing-box format` flipping the descriptor form: slash-prefixed
// base64 must stay base64 and a file absent on this host must stay a file.
func TestTumanLinkDescriptorForm(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"base64":"/w=="}`, `{"base64":"/w=="}`},
		{`{"base64":"/etc/hosts"}`, `{"base64":"/etc/hosts"}`},
		{`"YWJj"`, `{"base64":"YWJj"}`},
		{`{"file":"/nonexistent/gateway.tl1"}`, `{"file":"/nonexistent/gateway.tl1"}`},
		{`{"file":"./gateway.tl1"}`, `{"file":"./gateway.tl1"}`},
	} {
		var opts TumanLinkEndpointOptions
		if err := json.Unmarshal([]byte(`{"descriptor":`+tc.in+`}`), &opts); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(opts)
		if err != nil || !strings.Contains(string(raw), `"descriptor":`+tc.want) {
			t.Fatalf("%s marshaled as %s (%v)", tc.in, raw, err)
		}
	}
}
