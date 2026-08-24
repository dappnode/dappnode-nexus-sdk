package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/anchorageoss/awsnitroverifier"
	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

const (
	nonceBytes                 = 32
	hpkePublicKeyBytes         = 32
	maxAttestationResponse     = 1 << 20
	expectedAWSRootFingerprint = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
	defaultMaximumAge          = 2 * time.Minute
	defaultMaximumFutureSkew   = 30 * time.Second
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type documentVerifier interface {
	Validate([]byte) (*awsnitroverifier.ValidationResult, error)
}

type endpointResponse struct {
	Document              string          `json:"document"`
	Format                string          `json:"format"`
	Encoding              string          `json:"encoding"`
	UserData              string          `json:"user_data"`
	UserDataEncoding      string          `json:"user_data_encoding"`
	HPKEPublicKey         string          `json:"hpke_public_key"`
	HPKEPublicKeyEncoding string          `json:"hpke_public_key_encoding"`
	Manifest              json.RawMessage `json:"manifest"`
}

type fetchedEvidence struct {
	document      []byte
	manifest      json.RawMessage
	userData      []byte
	publicKeyCopy []byte
}

type manifestClaims struct {
	SchemaVersion  int             `json:"schema_version"`
	Profile        string          `json:"profile"`
	Workload       string          `json:"workload"`
	SourceRevision string          `json:"source_revision"`
	Ingress        ingressManifest `json:"ingress"`
}

type ingressManifest struct {
	E2EE json.RawMessage `json:"e2ee"`
}

// Evidence is the verified, signed binding between a measured Gateway build
// and its process-local EHBP key.
//
// Proof carries the signed material behind that binding so the local
// verification ledger can display it and hand it back for independent
// re-verification. None of it is secret: it is exactly what a third party
// needs to re-check this verification offline.
type Evidence struct {
	PublicKey  []byte
	AttestedAt time.Time
	ExpiresAt  time.Time
	Proof      Proof
}

// Proof is the signed evidence and the pinned claims it satisfied.
type Proof struct {
	Document        []byte
	Manifest        json.RawMessage
	Nonce           []byte
	ModuleID        string
	PCRs            map[uint][]byte
	RootFingerprint string
	SourceRevision  string
	Workload        string
	Profile         string
	E2EE            E2EEPolicy
}

// Verifier fetches nonce-bound evidence and validates it against a Policy.
type Verifier struct {
	endpoint      string
	policy        Policy
	httpClient    httpDoer
	document      documentVerifier
	random        io.Reader
	now           func() time.Time
	maxAge        time.Duration
	maxFutureSkew time.Duration
}

// NewVerifier creates a production verifier. endpoint must be the full
// Gateway /v1/attestation HTTPS URL.
func NewVerifier(endpoint string, policy *Policy, client *http.Client) (*Verifier, error) {
	if err := validateEndpointURL(endpoint, "/v1/attestation"); err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("trust policy is required")
	}
	policyCopy := *policy
	if err := policyCopy.validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("attestation redirects are not allowed")
		}}
	}
	if client.CheckRedirect == nil {
		return nil, errors.New("attestation HTTP client must reject redirects")
	}

	return &Verifier{
		endpoint:   endpoint,
		policy:     policyCopy,
		httpClient: client,
		// No PCRRules: the policy may pin more than one release, and a rule
		// list cannot express "any one of these complete measurement sets".
		// validate() compares all three PCRs in constant time against the one
		// release matched by the attested source revision, which is the same
		// check this option would perform.
		document: awsnitroverifier.NewVerifier(awsnitroverifier.AWSNitroVerifierOptions{
			SkipTimestampCheck: false,
		}),
		random:        rand.Reader,
		now:           time.Now,
		maxAge:        defaultMaximumAge,
		maxFutureSkew: defaultMaximumFutureSkew,
	}, nil
}

func validateEndpointURL(raw, expectedPath string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid attestation endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" || parsed.Path != expectedPath ||
		parsed.RawPath != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("attestation endpoint must be an exact HTTPS URL ending in %s", expectedPath)
	}
	return nil
}

// Verify obtains new, nonce-bound evidence. It never obtains key material from
// an unauthenticated discovery endpoint.
func (v *Verifier) Verify(ctx context.Context) (*Evidence, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(v.random, nonce); err != nil {
		return nil, fmt.Errorf("generate attestation nonce: %w", err)
	}
	fetched, err := v.fetch(ctx, nonce)
	if err != nil {
		return nil, err
	}
	return v.validate(fetched, nonce, v.now())
}

func (v *Verifier) fetch(ctx context.Context, nonce []byte) (*fetchedEvidence, error) {
	body, err := json.Marshal(struct {
		Nonce string `json:"nonce"`
	}{Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		return nil, fmt.Errorf("encode attestation request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create attestation request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "nexus-proxy/1")

	response, err := v.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request Gateway attestation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation endpoint returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("attestation endpoint returned a non-JSON content type")
	}

	responseBody, err := jsonutil.ReadAllLimited(response.Body, maxAttestationResponse)
	if err != nil {
		return nil, fmt.Errorf("read attestation response: %w", err)
	}
	var payload endpointResponse
	if err := jsonutil.DecodeStrict(responseBody, &payload); err != nil {
		return nil, fmt.Errorf("decode attestation response: %w", err)
	}
	if payload.Format != "aws-nitro-cose-sign1" || payload.Encoding != "base64" {
		return nil, errors.New("unsupported attestation format or encoding")
	}
	if payload.UserDataEncoding != "sha384-hex" {
		return nil, errors.New("unsupported attestation user_data encoding")
	}
	if payload.HPKEPublicKeyEncoding != "raw-x25519-hex" {
		return nil, errors.New("unsupported attestation HPKE public-key encoding")
	}
	if len(payload.Manifest) == 0 || !json.Valid(payload.Manifest) || bytes.Equal(payload.Manifest, []byte("null")) {
		return nil, errors.New("attestation response contains an invalid manifest")
	}

	document, err := decodeCanonicalBase64(payload.Document)
	if err != nil || len(document) == 0 {
		return nil, errors.New("attestation response contains an invalid document")
	}
	userData, err := decodeCanonicalHex(payload.UserData, sha512.Size384)
	if err != nil {
		return nil, errors.New("attestation response contains invalid user_data")
	}
	publicKeyCopy, err := decodeCanonicalHex(payload.HPKEPublicKey, hpkePublicKeyBytes)
	if err != nil || allZero(publicKeyCopy) {
		return nil, errors.New("attestation response contains an invalid HPKE public key")
	}

	return &fetchedEvidence{
		document:      document,
		manifest:      append(json.RawMessage(nil), payload.Manifest...),
		userData:      userData,
		publicKeyCopy: publicKeyCopy,
	}, nil
}

func (v *Verifier) validate(fetched *fetchedEvidence, nonce []byte, now time.Time) (*Evidence, error) {
	if fetched == nil {
		return nil, errors.New("attestation response is nil")
	}
	if len(nonce) != nonceBytes || now.IsZero() || v.maxAge <= 0 || v.maxFutureSkew < 0 {
		return nil, errors.New("invalid attestation verifier state")
	}

	manifestDigest := sha512.Sum384(fetched.manifest)
	if subtle.ConstantTimeCompare(fetched.userData, manifestDigest[:]) != 1 {
		return nil, errors.New("response user_data does not match SHA-384(manifest)")
	}
	release, err := v.validateManifest(fetched.manifest)
	if err != nil {
		return nil, err
	}

	result, err := v.document.Validate(fetched.document)
	if err != nil {
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}
	if result == nil {
		return nil, errors.New("attestation verifier returned no result")
	}
	if !result.Valid {
		return nil, fmt.Errorf("AWS Nitro attestation validation failed: %s", validationErrors(result.Errors))
	}
	if !result.ChainTrusted || result.RootFingerprint != expectedAWSRootFingerprint {
		return nil, errors.New("attestation certificate chain is not rooted in the expected AWS Nitro CA")
	}
	if result.Document == nil {
		return nil, errors.New("attestation document is missing decoded fields")
	}
	if subtle.ConstantTimeCompare(result.Nonce, nonce) != 1 || len(result.Nonce) != nonceBytes {
		return nil, errors.New("attestation nonce does not match the request")
	}
	if subtle.ConstantTimeCompare(result.UserData, manifestDigest[:]) != 1 || len(result.UserData) != sha512.Size384 {
		return nil, errors.New("signed user_data does not match SHA-384(manifest)")
	}
	if len(result.PublicKey) != hpkePublicKeyBytes || allZero(result.PublicKey) {
		return nil, errors.New("signed HPKE public key is missing or malformed")
	}
	if subtle.ConstantTimeCompare(result.PublicKey, fetched.publicKeyCopy) != 1 {
		return nil, errors.New("response HPKE public key does not match the signed attestation key")
	}
	if result.Document.Timestamp > math.MaxInt64 {
		return nil, errors.New("attestation timestamp is out of range")
	}
	attestedAt := time.UnixMilli(int64(result.Document.Timestamp))
	if attestedAt.After(now.Add(v.maxFutureSkew)) {
		return nil, errors.New("attestation timestamp is too far in the future")
	}
	if attestedAt.Before(now.Add(-v.maxAge)) {
		return nil, errors.New("attestation timestamp is stale")
	}

	expectedPCRs := release.expectedPCRs()
	for _, index := range []uint{0, 1, 2} {
		actual, present := result.Document.PCRs[index]
		if !present || len(actual) != pcrBytes || allZero(actual) {
			return nil, fmt.Errorf("attestation PCR%d is missing, malformed, or unsafe", index)
		}
		if subtle.ConstantTimeCompare(actual, expectedPCRs[index]) != 1 {
			return nil, fmt.Errorf("attestation PCR%d does not match the pinned measurement for release %s", index, release.SourceRevision)
		}
	}

	retainedPCRs := make(map[uint][]byte, 3)
	for _, index := range []uint{0, 1, 2} {
		retainedPCRs[index] = append([]byte(nil), result.Document.PCRs[index]...)
	}

	return &Evidence{
		PublicKey:  append([]byte(nil), result.PublicKey...),
		AttestedAt: attestedAt,
		ExpiresAt:  attestedAt.Add(v.maxAge),
		Proof: Proof{
			Document:        append([]byte(nil), fetched.document...),
			Manifest:        append(json.RawMessage(nil), fetched.manifest...),
			Nonce:           append([]byte(nil), result.Nonce...),
			ModuleID:        result.Document.ModuleID,
			PCRs:            retainedPCRs,
			RootFingerprint: result.RootFingerprint,
			SourceRevision:  release.SourceRevision,
			Workload:        v.policy.Workload,
			Profile:         v.policy.Profile,
			E2EE:            v.policy.E2EE,
		},
	}, nil
}

// MaximumAge is the attestation validity window this verifier enforces.
func (v *Verifier) MaximumAge() time.Duration { return v.maxAge }

// validateManifest checks the claims every pinned release shares, then selects
// the single release the evidence claims to be. The manifest is bound to the
// signed document through user_data, so the selected release cannot be chosen
// by an attacker independently of the measurements that are checked against it.
func (v *Verifier) validateManifest(raw json.RawMessage) (*Release, error) {
	var manifest manifestClaims
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode attested manifest: %w", err)
	}
	if manifest.SchemaVersion != v.policy.ManifestSchemaVersion {
		return nil, errors.New("attested manifest schema_version does not match the trust policy")
	}
	if manifest.Workload != v.policy.Workload {
		return nil, errors.New("attested workload does not match the trust policy")
	}
	if manifest.Profile != v.policy.Profile {
		return nil, errors.New("attested profile does not match the trust policy")
	}
	if len(manifest.Ingress.E2EE) == 0 || bytes.Equal(manifest.Ingress.E2EE, []byte("null")) {
		return nil, errors.New("attested manifest is missing ingress.e2ee")
	}
	var e2ee E2EEPolicy
	if err := jsonutil.DecodeStrict(manifest.Ingress.E2EE, &e2ee); err != nil {
		return nil, fmt.Errorf("decode attested ingress.e2ee: %w", err)
	}
	if e2ee != v.policy.E2EE {
		return nil, errors.New("attested ingress.e2ee does not match the trust policy")
	}
	release, pinned := v.policy.releaseFor(manifest.SourceRevision)
	if !pinned {
		return nil, errors.New("attested source_revision is not a pinned Gateway release")
	}
	return release, nil
}

func decodeCanonicalBase64(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("non-canonical base64")
	}
	return decoded, nil
}

func decodeCanonicalHex(encoded string, size int) ([]byte, error) {
	if len(encoded) != size*2 {
		return nil, errors.New("invalid encoded size")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(decoded) != encoded {
		return nil, errors.New("non-canonical hexadecimal")
	}
	return decoded, nil
}

func validationErrors(items []error) string {
	if len(items) == 0 {
		return "unspecified validation failure"
	}
	messages := make([]string, 0, len(items))
	for _, item := range items {
		if item != nil {
			messages = append(messages, item.Error())
		}
	}
	if len(messages) == 0 {
		return "unspecified validation failure"
	}
	return fmt.Sprintf("%v", messages)
}
