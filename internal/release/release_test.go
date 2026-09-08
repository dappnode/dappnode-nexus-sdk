package release

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
)

// The fixtures are the real published Gateway v0.1.61 release assets. They keep
// verifying after the signing certificate's ten-minute validity window because
// Sigstore checks the certificate against the transparency-log timestamp, not
// against the clock at verification time.
const (
	fixtureRevision = "893f4c9f306707b83f3b41782f25eb05adbc4f30"
	fixturePCR0     = "61e070dd4c7e2956affe2684413ccaa5dac8a6fb0f55ca144d9671ce578e72464e30eaf09226a3073f0a3d03a2f809c1"
)

func readFixture(t *testing.T) (manifest, bundle []byte) {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join("testdata", "v0.1.61.release.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = os.ReadFile(filepath.Join("testdata", "v0.1.61.release.json.sigstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	return manifest, bundle
}

func newFixtureVerifier(t *testing.T) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(trustedRootJSON)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func TestVerifyAcceptsPublishedRelease(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	manifest, err := newFixtureVerifier(t).Verify(context.Background(), manifestBytes, bundleBytes)
	if err != nil {
		t.Fatalf("genuine release rejected: %v", err)
	}
	if manifest.Source.Revision != fixtureRevision {
		t.Errorf("revision = %q, want %q", manifest.Source.Revision, fixtureRevision)
	}
	if manifest.Enclave.Measurements.PCR0 != fixturePCR0 {
		t.Errorf("pcr0 = %q, want %q", manifest.Enclave.Measurements.PCR0, fixturePCR0)
	}
	if manifest.Release.Environment != Environment {
		t.Errorf("environment = %q, want %q", manifest.Release.Environment, Environment)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"changed pcr0", func(document map[string]any) {
			enclave := document["enclave"].(map[string]any)
			measurements := enclave["measurements"].(map[string]any)
			measurements["pcr0"] = "0" + fixturePCR0[1:]
		}},
		{"changed source revision", func(document map[string]any) {
			document["source"].(map[string]any)["revision"] = strings.Repeat("a", 40)
		}},
		{"weakened encryption", func(document map[string]any) {
			profile := document["security_profile"].(map[string]any)
			profile["body_e2ee"].(map[string]any)["protocol"] = "plaintext"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(manifestBytes, &document); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newFixtureVerifier(t).Verify(context.Background(), mutated, bundleBytes); err == nil {
				t.Fatal("tampered manifest accepted")
			}
		})
	}
}

func TestVerifyRejectsMissingInput(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	verifier := newFixtureVerifier(t)
	if _, err := verifier.Verify(context.Background(), nil, bundleBytes); err == nil {
		t.Error("empty manifest accepted")
	}
	if _, err := verifier.Verify(context.Background(), manifestBytes, nil); err == nil {
		t.Error("empty bundle accepted")
	}
	if _, err := verifier.Verify(context.Background(), manifestBytes, []byte("{}")); err == nil {
		t.Error("empty bundle object accepted")
	}
}

// A staging build carries a valid signature from the same workflow identity, so
// only the environment claim keeps it out of a production client.
func TestParseManifestRejectsNonProduction(t *testing.T) {
	manifestBytes, _ := readFixture(t)
	var document map[string]any
	if err := json.Unmarshal(manifestBytes, &document); err != nil {
		t.Fatal(err)
	}
	document["release"].(map[string]any)["environment"] = "staging"
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(mutated); err == nil {
		t.Fatal("staging release accepted as production")
	}
}

func TestParseManifestRejectsUnsafeMeasurements(t *testing.T) {
	manifestBytes, _ := readFixture(t)
	for _, testCase := range []struct {
		name  string
		value string
	}{
		{"debug all-zero pcr0", strings.Repeat("0", 96)},
		{"uppercase pcr0", strings.ToUpper(fixturePCR0)},
		{"short pcr0", fixturePCR0[:94]},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(manifestBytes, &document); err != nil {
				t.Fatal(err)
			}
			enclave := document["enclave"].(map[string]any)
			enclave["measurements"].(map[string]any)["pcr0"] = testCase.value
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseManifest(mutated); err == nil {
				t.Fatalf("accepted %s", testCase.name)
			}
		})
	}
}

func TestPolicyMatchesHandPinnedPolicy(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	manifest, err := newFixtureVerifier(t).Verify(context.Background(), manifestBytes, bundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := Policy(manifest)
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if len(policy.Releases) != 1 {
		t.Fatalf("releases = %d, want 1", len(policy.Releases))
	}
	if policy.Releases[0].SourceRevision != fixtureRevision {
		t.Errorf("revision = %q", policy.Releases[0].SourceRevision)
	}
	if policy.Releases[0].PCR0 != fixturePCR0 {
		t.Errorf("pcr0 = %q", policy.Releases[0].PCR0)
	}
	if policy.Profile != attestation.GatewayProfile || policy.Workload != attestation.GatewayWorkload {
		t.Errorf("profile/workload = %q/%q", policy.Profile, policy.Workload)
	}
	if !policy.E2EE.RequestEncrypted || !policy.E2EE.ResponseEncrypted {
		t.Error("derived policy does not require both directions encrypted")
	}
}

func TestPolicyRejectsTooManyReleases(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	manifest, err := newFixtureVerifier(t).Verify(context.Background(), manifestBytes, bundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifests := make([]*Manifest, attestation.MaxPolicyReleases+1)
	for index := range manifests {
		manifests[index] = manifest
	}
	if _, err := Policy(manifests...); err == nil {
		t.Fatal("policy accepted more releases than the cap")
	}
	if _, err := Policy(); err == nil {
		t.Fatal("policy accepted an empty release set")
	}
}

func TestCheckDownloadURLAllowlist(t *testing.T) {
	for _, testCase := range []struct {
		url     string
		allowed bool
	}{
		{"https://api.github.com/repos/a/b/releases", true},
		{"https://objects.githubusercontent.com/x", true},
		{"http://api.github.com/repos/a/b/releases", false},
		{"https://evil.example/releases", false},
		{"https://api.github.com.evil.example/x", false},
		{"https://user:pass@api.github.com/x", false},
		{"https://127.0.0.1/x", false},
		{"file:///etc/passwd", false},
	} {
		err := checkDownloadURL(testCase.url)
		if testCase.allowed && err != nil {
			t.Errorf("%s: rejected: %v", testCase.url, err)
		}
		if !testCase.allowed && err == nil {
			t.Errorf("%s: accepted", testCase.url)
		}
	}
}

func TestNewSourceValidation(t *testing.T) {
	if _, err := NewSource("not-a-repo", 0, nil); err == nil {
		t.Error("accepted a repository without an owner")
	}
	if _, err := NewSource("owner/name", attestation.MaxPolicyReleases+1, nil); err == nil {
		t.Error("accepted a release count above the policy cap")
	}
	source, err := NewSource("", 0, nil)
	if err != nil {
		t.Fatalf("default source: %v", err)
	}
	if source.repository != DefaultRepository || source.count != DefaultReleaseCount {
		t.Errorf("defaults = %q/%d", source.repository, source.count)
	}
}

func TestFileCacheRoundTripAndRejection(t *testing.T) {
	manifestBytes, bundleBytes := readFixture(t)
	path := filepath.Join(t.TempDir(), "nested", "cache.json")
	cache, err := NewFileCache(path)
	if err != nil {
		t.Fatal(err)
	}

	if entries, err := cache.Load(); err != nil || entries != nil {
		t.Fatalf("missing cache should load empty, got %v / %v", entries, err)
	}
	if err := cache.Store(nil); err == nil {
		t.Error("stored an empty release set")
	}

	entry := SignedRelease{Manifest: manifestBytes, Bundle: bundleBytes}
	if err := cache.Store([]SignedRelease{entry}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 || !bytes.Equal(loaded[0].Manifest, manifestBytes) {
		t.Fatal("cache did not round-trip the signed manifest")
	}

	// A cache on ordinary disk is no more trusted than the network: a swapped
	// manifest must fail verification on load rather than be believed.
	source, err := NewSource("", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), manifestBytes...)
	tampered = bytes.Replace(tampered, []byte(fixturePCR0), []byte("0"+fixturePCR0[1:]), 1)
	if err := cache.Store([]SignedRelease{{Manifest: tampered, Bundle: bundleBytes}}); err != nil {
		t.Fatal(err)
	}
	source = source.WithCache(cache)
	if _, err := source.cached(); err == nil {
		t.Fatal("tampered cache accepted")
	}
}
