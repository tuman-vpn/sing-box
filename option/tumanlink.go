package option

import (
	"context"
	"fmt"
	"strings"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// TumanLinkEndpointOptions configures the host side of a TL1 link. Identity and
// its enrolled descriptor root live in credentials_dir/credentials.json.
type TumanLinkEndpointOptions struct {
	// Descriptor is the signed descriptor in standard base64, or its path
	// when DescriptorFile is set. JSON accepts {"base64":"..."},
	// {"file":"/path"} or a compact base64 string and writes the object form,
	// keeping file versus base64.
	Descriptor      string                     `json:"descriptor"`
	DescriptorFile  bool                       `json:"-"`
	CredentialsPath string                     `json:"credentials_dir"`
	SetupOrder      []string                   `json:"setup_order,omitempty"`
	CoverSNI        badoption.Listable[string] `json:"cover_sni,omitempty"`
	CoverProfile    string                     `json:"cover_profile,omitempty"`
	NoCoverProbe    bool                       `json:"no_cover_probe,omitempty"`
	CoverProbation  badoption.Duration         `json:"cover_probation,omitempty"`
	Resolver        string                     `json:"resolver,omitempty"`
	DirectTimeout   badoption.Duration         `json:"direct_timeout,omitempty"`
	MTU             uint32                     `json:"mtu,omitempty"`
	Workers         int                        `json:"workers,omitempty"`
	DialerOptions
}

func (o *TumanLinkEndpointOptions) UnmarshalJSON(data []byte) error {
	return o.UnmarshalJSONContext(context.Background(), data)
}

// Accept the documented descriptor union as well as the compact string form.
// Unknown fields are rejected like in every other endpoint, so a misspelled
// option fails `sing-box check` instead of silently keeping its default.
func (o *TumanLinkEndpointOptions) UnmarshalJSONContext(ctx context.Context, data []byte) error {
	type plain TumanLinkEndpointOptions
	var raw struct {
		Descriptor json.RawMessage `json:"descriptor"`
		*plain
	}
	decoded := plain{}
	raw.plain = &decoded
	if err := json.UnmarshalContextDisallowUnknownFields(ctx, data, &raw); err != nil {
		return err
	}
	if len(raw.Descriptor) == 0 {
		return fmt.Errorf("missing descriptor")
	}
	var input string
	isFile := false
	if err := json.Unmarshal(raw.Descriptor, &input); err != nil {
		var object map[string]string
		if err = json.Unmarshal(raw.Descriptor, &object); err != nil {
			return fmt.Errorf("invalid descriptor: %w", err)
		}
		if len(object) != 1 {
			return fmt.Errorf("descriptor requires exactly one of base64 or file")
		}
		if value, ok := object["base64"]; ok {
			input = value
		} else if value, ok := object["file"]; ok {
			input, isFile = value, true
			if !strings.HasPrefix(input, "/") && !strings.HasPrefix(input, "./") {
				return fmt.Errorf("descriptor file must start with / or ./")
			}
		} else {
			return fmt.Errorf("descriptor requires base64 or file")
		}
	}
	if input == "" {
		return fmt.Errorf("empty descriptor")
	}
	decoded.Descriptor, decoded.DescriptorFile = input, isFile
	*o = TumanLinkEndpointOptions(decoded)
	return nil
}

func (o TumanLinkEndpointOptions) MarshalJSON() ([]byte, error) {
	type plain TumanLinkEndpointOptions
	key := "base64"
	if o.DescriptorFile {
		key = "file"
	}
	return json.Marshal(struct {
		Descriptor map[string]string `json:"descriptor"`
		*plain
	}{map[string]string{key: o.Descriptor}, (*plain)(&o)})
}
