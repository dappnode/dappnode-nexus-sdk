package attestation

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testPolicyJSON(revision string) []byte {
	document, err := json.Marshal(map[string]any{
		"schema_version":          PolicySchemaVersion,
		"manifest_schema_version": ManifestSchemaVersion,
		"workload":                GatewayWorkload,
		"profile":                 GatewayProfile,
		"e2ee": map[string]any{
			"protocol":           EHBPProtocol,
			"suite":              EHBPSuite,
			"endpoint":           ConfidentialEndpoint,
			"request_encrypted":  true,
			"response_encrypted": true,
		},
		"releases": []map[string]any{{
			"source_revision": revision,
			"pcr0":            hex.EncodeToString(bytesRepeat(0x11, pcrBytes)),
			"pcr1":            hex.EncodeToString(bytesRepeat(0x22, pcrBytes)),
			"pcr2":            hex.EncodeToString(bytesRepeat(0x33, pcrBytes)),
		}},
	})
	if err != nil {
		panic(err)
	}
	return document
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}

func TestSetPolicyReplacesAndRejects(t *testing.T) {
	first := strings.Repeat("a", 40)
	second := strings.Repeat("b", 40)

	policy, err := ParsePolicy(testPolicyJSON(first))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier("https://gateway.example/v1/attestation", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifier.Policy().Releases[0].SourceRevision; got != first {
		t.Fatalf("initial revision = %q", got)
	}

	replacement, err := ParsePolicy(testPolicyJSON(second))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.SetPolicy(replacement); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if got := verifier.Policy().Releases[0].SourceRevision; got != second {
		t.Fatalf("replaced revision = %q", got)
	}

	// A rejected policy must leave the previous one in force: a bad refresh can
	// never empty or widen what this verifier accepts.
	if err := verifier.SetPolicy(nil); err == nil {
		t.Error("SetPolicy accepted a nil policy")
	}
	if err := verifier.SetPolicy(&Policy{}); err == nil {
		t.Error("SetPolicy accepted an invalid policy")
	}
	if got := verifier.Policy().Releases[0].SourceRevision; got != second {
		t.Fatalf("rejected refresh changed the policy to %q", got)
	}
}

// The derived-policy path must satisfy exactly the rules a hand-written file
// does, since it reuses ParsePolicy rather than building a Policy directly.
func TestSetPolicyEnforcesEncryptionContract(t *testing.T) {
	policy, err := ParsePolicy(testPolicyJSON(strings.Repeat("c", 40)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier("https://gateway.example/v1/attestation", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	weakened := *policy
	weakened.E2EE.RequestEncrypted = false
	if err := verifier.SetPolicy(&weakened); err == nil {
		t.Fatal("SetPolicy accepted a policy that does not encrypt requests")
	}
}
