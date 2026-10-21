package option

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sagernet/sing/common/json/badoption"
)

// TumanLinkEndpointOptions configures the host side of a TL1 link. Identity and
// its enrolled descriptor root live in credentials_dir/credentials.json.
type TumanLinkEndpointOptions struct {
	Descriptor      string             `json:"descriptor"`
	CredentialsPath string             `json:"credentials_dir"`
	SetupOrder      []string           `json:"setup_order,omitempty"`
	Resolver        string             `json:"resolver,omitempty"`
	DirectTimeout   badoption.Duration `json:"direct_timeout,omitempty"`
	MTU             uint32             `json:"mtu,omitempty"`
	Workers         int                `json:"workers,omitempty"`
	DialerOptions
}

// Accept the documented descriptor union as well as the compact string form.
func (o *TumanLinkEndpointOptions) UnmarshalJSON(data []byte) error {
	type plain TumanLinkEndpointOptions
	var raw struct {
		Descriptor json.RawMessage `json:"descriptor"`
		*plain
	}
	decoded := plain{}
	raw.plain = &decoded
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Descriptor) == 0 {
		return fmt.Errorf("missing descriptor")
	}
	var input string
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
			input = value
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
	decoded.Descriptor = input
	*o = TumanLinkEndpointOptions(decoded)
	return nil
}

func (o TumanLinkEndpointOptions) MarshalJSON() ([]byte, error) {
	type plain TumanLinkEndpointOptions
	key := "base64"
	if TumanLinkDescriptorIsFile(o.Descriptor) {
		key = "file"
	}
	return json.Marshal(struct {
		Descriptor map[string]string `json:"descriptor"`
		*plain
	}{map[string]string{key: o.Descriptor}, (*plain)(&o)})
}

// TumanLinkDescriptorIsFile disambiguates slash-prefixed base64 from paths.
func TumanLinkDescriptorIsFile(value string) bool {
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "./") {
		return false
	}
	_, err := os.Stat(value)
	return err == nil
}
