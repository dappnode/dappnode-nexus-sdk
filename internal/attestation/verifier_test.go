package attestation

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anchorageoss/awsnitroverifier"
)

type fakeDocumentVerifier struct {
	result *awsnitroverifier.ValidationResult
	err    error
}

func (v *fakeDocumentVerifier) Validate([]byte) (*awsnitroverifier.ValidationResult, error) {
	return v.result, v.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestVerifierFetchesNonceBoundKeyFromAttestationOnly(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixedNonce := bytes.Repeat([]byte{0x77}, nonceBytes)
	fixture.verifier.random = bytes.NewReader(fixedNonce)
	fixture.result.Nonce = append([]byte(nil), fixedNonce...)
	var calls int
	fixture.verifier.httpClient = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != "https://gateway.example/v1/attestation" {
			t.Fatalf("unexpected attestation request: %s %s", request.Method, request.URL)
		}
		if request.URL.Path == "/.well-known/hpke-keys" {
			t.Fatal("verifier attempted EHBP key discovery")
		}
		var requestBody struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		if requestBody.Nonce != base64.RawURLEncoding.EncodeToString(fixedNonce) {
			t.Fatalf("nonce = %q, want fixed nonce", requestBody.Nonce)
		}
		payload := endpointResponse{
			Document:              base64.StdEncoding.EncodeToString([]byte("signed-document")),
			Format:                "aws-nitro-cose-sign1",
			Encoding:              "base64",
			UserData:              hex.EncodeToString(fixture.fetched.userData),
			UserDataEncoding:      "sha384-hex",
			HPKEPublicKey:         hex.EncodeToString(fixture.fetched.publicKeyCopy),
			HPKEPublicKeyEncoding: "raw-x25519-hex",
			Manifest:              fixture.fetched.manifest,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
		}, nil
	})

	evidence, err := fixture.verifier.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls)
	}
	if !bytes.Equal(evidence.PublicKey, fixture.result.PublicKey) {
		t.Fatalf("evidence key = %x, want %x", evidence.PublicKey, fixture.result.PublicKey)
	}
	if !evidence.ExpiresAt.Equal(evidence.AttestedAt.Add(defaultMaximumAge)) {
		t.Fatalf("expiry = %s, want attested_at + max age", evidence.ExpiresAt)
	}
}

func TestNewVerifierRequiresExactHTTPSURLAndRedirectPolicy(t *testing.T) {
	policy := validPolicy()
	redirectRejectingClient := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirects are not allowed")
	}}
	tests := []string{
		"",
		"http://gateway.example/v1/attestation",
		"https://user@gateway.example/v1/attestation",
		"https://gateway.example/attestation",
		"https://gateway.example/v1/attestation?next=value",
		"https://gateway.example/v1/attestation#fragment",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := NewVerifier(endpoint, &policy, redirectRejectingClient); err == nil {
				t.Fatalf("NewVerifier(%q) succeeded", endpoint)
			}
		})
	}
	if _, err := NewVerifier("https://gateway.example/v1/attestation", &policy, &http.Client{}); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("NewVerifier() error = %v, want redirect policy error", err)
	}
	if _, err := NewVerifier("https://gateway.example/v1/attestation", &policy, redirectRejectingClient); err != nil {
		t.Fatalf("valid NewVerifier() error = %v", err)
	}
}

func TestVerifierRejectsAttestationAndPolicyMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*verificationFixture)
		want   string
	}{
		{
			name: "untrusted chain",
			mutate: func(f *verificationFixture) {
				f.result.ChainTrusted = false
			},
			want: "expected AWS Nitro CA",
		},
		{
			name: "nonce substitution",
			mutate: func(f *verificationFixture) {
				f.result.Nonce[0] ^= 0xff
			},
			want: "nonce",
		},
		{
			name: "manifest substitution",
			mutate: func(f *verificationFixture) {
				f.fetched.manifest = append(f.fetched.manifest, ' ')
			},
			want: "SHA-384(manifest)",
		},
		{
			name: "source revision",
			mutate: func(f *verificationFixture) {
				f.replaceManifest(t, func(manifest map[string]any) {
					manifest["source_revision"] = strings.Repeat("b", 40)
				})
			},
			want: "source_revision",
		},
		{
			name: "e2ee suite",
			mutate: func(f *verificationFixture) {
				f.replaceManifest(t, func(manifest map[string]any) {
					ingress := manifest["ingress"].(map[string]any)
					e2ee := ingress["e2ee"].(map[string]any)
					e2ee["suite"] = "unsupported"
				})
			},
			want: "ingress.e2ee",
		},
		{
			name: "unknown e2ee claim",
			mutate: func(f *verificationFixture) {
				f.replaceManifest(t, func(manifest map[string]any) {
					ingress := manifest["ingress"].(map[string]any)
					e2ee := ingress["e2ee"].(map[string]any)
					e2ee["downgrade"] = true
				})
			},
			want: "unknown field",
		},
		{
			name: "public key mirror substitution",
			mutate: func(f *verificationFixture) {
				f.fetched.publicKeyCopy[0] ^= 0xff
			},
			want: "does not match",
		},
		{
			name: "missing signed public key",
			mutate: func(f *verificationFixture) {
				f.result.PublicKey = nil
			},
			want: "signed HPKE public key",
		},
		{
			name: "stale",
			mutate: func(f *verificationFixture) {
				f.result.Document.Timestamp = uint64(f.now.Add(-defaultMaximumAge - time.Millisecond).UnixMilli())
			},
			want: "stale",
		},
		{
			name: "future",
			mutate: func(f *verificationFixture) {
				f.result.Document.Timestamp = uint64(f.now.Add(defaultMaximumFutureSkew + time.Millisecond).UnixMilli())
			},
			want: "future",
		},
		{
			name: "PCR mismatch",
			mutate: func(f *verificationFixture) {
				f.result.Document.PCRs[2][0] ^= 0xff
			},
			want: "PCR2",
		},
		{
			name: "invalid signature result",
			mutate: func(f *verificationFixture) {
				f.result.Valid = false
				f.result.Errors = []error{errors.New("signature mismatch")}
			},
			want: "signature mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			test.mutate(fixture)
			_, err := fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

type verificationFixture struct {
	verifier *Verifier
	fetched  *fetchedEvidence
	result   *awsnitroverifier.ValidationResult
	nonce    []byte
	now      time.Time
}

func newVerificationFixture(t *testing.T) *verificationFixture {
	t.Helper()
	policy := validPolicy()
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version":  policy.ManifestSchemaVersion,
		"profile":         policy.Profile,
		"workload":        policy.Workload,
		"source_revision": policy.Releases[0].SourceRevision,
		"ingress": map[string]any{
			"gateway_vsock_port": float64(8080),
			"tls_in_enclave":     false,
			"e2ee": map[string]any{
				"protocol":           policy.E2EE.Protocol,
				"suite":              policy.E2EE.Suite,
				"endpoint":           policy.E2EE.Endpoint,
				"request_encrypted":  true,
				"response_encrypted": true,
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(manifestBytes)
	nonce := bytes.Repeat([]byte{0x42}, nonceBytes)
	publicKey := bytes.Repeat([]byte{0x24}, hpkePublicKeyBytes)
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	pcrs := policy.Releases[0].expectedPCRs()
	result := &awsnitroverifier.ValidationResult{
		Valid:           true,
		ChainTrusted:    true,
		RootFingerprint: expectedAWSRootFingerprint,
		UserData:        append([]byte(nil), digest[:]...),
		PublicKey:       append([]byte(nil), publicKey...),
		Nonce:           append([]byte(nil), nonce...),
		Document: &awsnitroverifier.AttestationDocument{
			Timestamp: uint64(now.Add(-time.Second).UnixMilli()),
			PCRs: map[uint][]byte{
				0: append([]byte(nil), pcrs[0]...),
				1: append([]byte(nil), pcrs[1]...),
				2: append([]byte(nil), pcrs[2]...),
			},
		},
	}
	verifier := &Verifier{
		endpoint:      "https://gateway.example/v1/attestation",
		policy:        policy,
		document:      &fakeDocumentVerifier{result: result},
		random:        bytes.NewReader(bytes.Repeat([]byte{0x77}, nonceBytes)),
		now:           func() time.Time { return now },
		maxAge:        defaultMaximumAge,
		maxFutureSkew: defaultMaximumFutureSkew,
	}
	return &verificationFixture{
		verifier: verifier,
		fetched: &fetchedEvidence{
			document:      []byte("signed-document"),
			manifest:      manifestBytes,
			userData:      append([]byte(nil), digest[:]...),
			publicKeyCopy: append([]byte(nil), publicKey...),
		},
		result: result,
		nonce:  nonce,
		now:    now,
	}
}

func (f *verificationFixture) replaceManifest(t *testing.T, mutate func(map[string]any)) {
	t.Helper()
	var manifest map[string]any
	if err := json.Unmarshal(f.fetched.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(manifest)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(encoded)
	f.fetched.manifest = encoded
	f.fetched.userData = append([]byte(nil), digest[:]...)
	f.result.UserData = append([]byte(nil), digest[:]...)
}

// secondRelease is a distinct pinned build: different revision, different
// measurements. Policies carry two entries during a Gateway rollout.
func secondRelease() Release {
	return Release{
		SourceRevision: strings.Repeat("b", 40),
		PCR0:           strings.Repeat("cd", pcrBytes),
		PCR1:           strings.Repeat("ce", pcrBytes),
		PCR2:           strings.Repeat("cf", pcrBytes),
	}
}

// pinTwoReleases adds a second pinned release and revalidates, so the fixture
// still describes the first one.
func (f *verificationFixture) pinTwoReleases(t *testing.T) Release {
	t.Helper()
	extra := secondRelease()
	f.verifier.policy.Releases = append(f.verifier.policy.Releases, extra)
	if err := f.verifier.policy.validate(); err != nil {
		t.Fatal(err)
	}
	return f.verifier.policy.Releases[1]
}

func TestPolicyAcceptsEitherPinnedRelease(t *testing.T) {
	// The release already described by the fixture stays acceptable once a
	// second one is pinned: adding the incoming build must not break clients
	// still talking to the outgoing one.
	fixture := newVerificationFixture(t)
	fixture.pinTwoReleases(t)
	evidence, err := fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
	if err != nil {
		t.Fatalf("validate() error = %v, want the outgoing release to stay accepted", err)
	}
	if evidence.Proof.SourceRevision != strings.Repeat("a", 40) {
		t.Fatalf("proof revision = %q, want the matched release", evidence.Proof.SourceRevision)
	}

	// And the newly pinned release is accepted on its own terms.
	second := fixture.verifier.policy.Releases[1]
	fixture.replaceManifest(t, func(manifest map[string]any) {
		manifest["source_revision"] = second.SourceRevision
	})
	expected := second.expectedPCRs()
	for index := range uint(3) {
		fixture.result.Document.PCRs[index] = append([]byte(nil), expected[index]...)
	}
	evidence, err = fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
	if err != nil {
		t.Fatalf("validate() error = %v, want the incoming release accepted", err)
	}
	if evidence.Proof.SourceRevision != second.SourceRevision {
		t.Fatalf("proof revision = %q, want %q", evidence.Proof.SourceRevision, second.SourceRevision)
	}
}

// TestMeasurementsAreNotMixedAcrossReleases is the load-bearing test for a
// multi-release policy: each release must be satisfied as a whole. Evidence
// naming one release while carrying another's measurements must fail, or
// pinning two releases would silently widen what counts as trusted to every
// combination of their measurements.
func TestMeasurementsAreNotMixedAcrossReleases(t *testing.T) {
	fixture := newVerificationFixture(t)
	second := fixture.pinTwoReleases(t)

	// Claim the second release, but keep the first release's measurements.
	fixture.replaceManifest(t, func(manifest map[string]any) {
		manifest["source_revision"] = second.SourceRevision
	})
	_, err := fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
	if err == nil || !strings.Contains(err.Error(), "PCR0") {
		t.Fatalf("validate() error = %v, want a PCR mismatch for the claimed release", err)
	}

	// The mirror image: keep the first release's revision, swap in the
	// second release's PCR0.
	fixture = newVerificationFixture(t)
	second = fixture.pinTwoReleases(t)
	fixture.result.Document.PCRs[0] = append([]byte(nil), second.expectedPCRs()[0]...)
	_, err = fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
	if err == nil || !strings.Contains(err.Error(), "PCR0") {
		t.Fatalf("validate() error = %v, want a PCR mismatch", err)
	}
}

func TestUnpinnedReleaseIsRejected(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.pinTwoReleases(t)
	fixture.replaceManifest(t, func(manifest map[string]any) {
		manifest["source_revision"] = strings.Repeat("f", 40)
	})
	_, err := fixture.verifier.validate(fixture.fetched, fixture.nonce, fixture.now)
	if err == nil || !strings.Contains(err.Error(), "not a pinned Gateway release") {
		t.Fatalf("validate() error = %v, want an unpinned-release rejection", err)
	}
}
