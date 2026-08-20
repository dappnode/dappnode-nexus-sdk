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
		SourceRevision:        strings.Repeat("a", 40),
		PCR0:                  measurement,
		PCR1:                  measurement,
		PCR2:                  measurement,
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
	if loaded.SourceRevision != policy.SourceRevision {
		t.Fatalf("source revision = %q, want %q", loaded.SourceRevision, policy.SourceRevision)
	}
	if len(loaded.expectedPCRs()) != 3 {
		t.Fatalf("expected PCR count = %d, want 3", len(loaded.expectedPCRs()))
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
		{name: "short revision", mutate: func(p *Policy) { p.SourceRevision = "abc" }, want: "source_revision"},
		{name: "uppercase revision", mutate: func(p *Policy) { p.SourceRevision = strings.Repeat("A", 40) }, want: "source_revision"},
		{name: "zero PCR", mutate: func(p *Policy) { p.PCR0 = strings.Repeat("0", pcrBytes*2) }, want: "all zero"},
		{name: "uppercase PCR", mutate: func(p *Policy) { p.PCR1 = strings.ToUpper(p.PCR1) }, want: "lowercase"},
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
