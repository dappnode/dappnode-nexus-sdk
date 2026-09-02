package attestation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validPolicy() Policy {
	measurement := strings.Repeat("ab", pcrBytes)
	return Policy{
		SchemaVersion:         PolicySchemaVersion,
		ManifestSchemaVersion: ManifestSchemaVersion,
		Workload:              GatewayWorkload,
		Profile:               GatewayProfile,
		Releases: []Release{{
			SourceRevision: strings.Repeat("a", 40),
			PCR0:           measurement,
			PCR1:           measurement,
			PCR2:           measurement,
		}},
		E2EE: E2EEPolicy{
			Protocol:          EHBPProtocol,
			Suite:             EHBPSuite,
			Endpoint:          ConfidentialEndpoint,
			RequestEncrypted:  true,
			ResponseEncrypted: true,
		},
	}
}

func TestLoadPolicy(t *testing.T) {
	policy := validPolicy()
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	if len(loaded.Releases) != 1 {
		t.Fatalf("release count = %d, want 1", len(loaded.Releases))
	}
	if loaded.Releases[0].SourceRevision != policy.Releases[0].SourceRevision {
		t.Fatalf("source revision = %q, want %q", loaded.Releases[0].SourceRevision, policy.Releases[0].SourceRevision)
	}
	if len(loaded.Releases[0].expectedPCRs()) != 3 {
		t.Fatalf("expected PCR count = %d, want 3", len(loaded.Releases[0].expectedPCRs()))
	}
}

func TestParsePolicy(t *testing.T) {
	encoded, err := json.Marshal(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicy(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Releases) != 1 || len(parsed.Releases[0].expectedPCRs()) != 3 {
		t.Fatalf("parsed policy = %+v", parsed)
	}
	if _, err := ParsePolicy(nil); err == nil {
		t.Fatal("ParsePolicy(nil) succeeded")
	}
	if _, err := ParsePolicy(make([]byte, maxPolicyBytes+1)); err == nil {
		t.Fatal("ParsePolicy accepted an oversized policy")
	}
}

func TestPolicyRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
		want   string
	}{
		{name: "policy schema", mutate: func(p *Policy) { p.SchemaVersion++ }, want: "schema_version"},
		{name: "manifest schema", mutate: func(p *Policy) { p.ManifestSchemaVersion-- }, want: "manifest_schema_version"},
		{name: "workload", mutate: func(p *Policy) { p.Workload = "other" }, want: "workload"},
		{name: "profile", mutate: func(p *Policy) { p.Profile = "other" }, want: "profile"},
		{name: "short revision", mutate: func(p *Policy) { p.Releases[0].SourceRevision = "abc" }, want: "source_revision"},
		{name: "uppercase revision", mutate: func(p *Policy) { p.Releases[0].SourceRevision = strings.Repeat("A", 40) }, want: "source_revision"},
		{name: "zero PCR", mutate: func(p *Policy) { p.Releases[0].PCR0 = strings.Repeat("0", pcrBytes*2) }, want: "all zero"},
		{name: "uppercase PCR", mutate: func(p *Policy) { p.Releases[0].PCR1 = strings.ToUpper(p.Releases[0].PCR1) }, want: "lowercase"},
		{name: "no releases", mutate: func(p *Policy) { p.Releases = nil }, want: "at least one"},
		{
			name: "too many releases",
			mutate: func(p *Policy) {
				for len(p.Releases) <= maxPolicyReleases {
					extra := p.Releases[0]
					extra.SourceRevision = strings.Repeat(string(rune('a'+len(p.Releases))), 40)
					p.Releases = append(p.Releases, extra)
				}
			},
			want: "more than",
		},
		{
			name:   "duplicate release",
			mutate: func(p *Policy) { p.Releases = append(p.Releases, p.Releases[0]) },
			want:   "more than once",
		},
		{name: "wrong endpoint", mutate: func(p *Policy) { p.E2EE.Endpoint = "/other" }, want: "e2ee"},
		{name: "unencrypted response", mutate: func(p *Policy) { p.E2EE.ResponseEncrypted = false }, want: "e2ee"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			err := policy.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	policy := validPolicy()
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] = ','
	encoded = append(encoded, []byte(`"unexpected":true}`)...)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadPolicy(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadPolicy() error = %v, want unknown field", err)
	}
}
