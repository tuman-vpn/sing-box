package option

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTumanLinkSlashBase64(t *testing.T) {
	var opts TumanLinkEndpointOptions
	if err := json.Unmarshal([]byte(`{"descriptor":{"base64":"/w=="}}`), &opts); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(opts)
	if err != nil || !strings.Contains(string(raw), `"base64":"/w=="`) {
		t.Fatalf("slash-base64 is not a file: %s %v", raw, err)
	}
	path := filepath.Join(t.TempDir(), "gateway.tl1")
	if err = os.WriteFile(path, []byte("descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	opts.Descriptor = path
	raw, err = json.Marshal(opts)
	if err != nil || !strings.Contains(string(raw), `"file":`) {
		t.Fatalf("existing file lost: %s %v", raw, err)
	}
}
