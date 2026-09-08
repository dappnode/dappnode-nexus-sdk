package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigroot "github.com/sigstore/sigstore-go/pkg/root"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// CertificateIdentity is the exact Fulcio certificate SAN the release
	// workflow receives from GitHub's OIDC provider. It is the whole point of
	// this package: a signature is acceptable only if a certificate was issued
	// to this workflow, on this branch, in this repository.
	//
	// It must stay byte-identical to the --certificate-identity the release
	// workflow verifies with immediately after signing.
	CertificateIdentity = "https://github.com/dappnode/dappnode-nexus-gateway/" +
		".github/workflows/release-and-push.yml@refs/heads/main"

	// CertificateOIDCIssuer is GitHub Actions' OIDC issuer. Pinning it stops a
	// certificate for the same SAN string issued through any other identity
	// provider from being accepted.
	CertificateOIDCIssuer = "https://token.actions.githubusercontent.com"

	// SourceRepository is cross-checked against the manifest body so a
	// manifest naming some other repository is rejected even if this client's
	// identity constants are later widened.
	SourceRepository = "https://github.com/dappnode/dappnode-nexus-gateway"
)

// Verifier checks Sigstore bundles against a trusted root fixed at build time.
//
// The trusted root is embedded rather than fetched with root.FetchTrustedRoot:
// fetching it would add a second network dependency on the path that decides
// what code this client will talk to, and would mean an offline client cannot
// verify anything. Embedding keeps the trust decision inside the measured
// binary, exactly like the AWS Nitro root fingerprint.
type Verifier struct {
	inner *sigverify.Verifier
}

// NewVerifier builds a release verifier from an embedded Sigstore trusted root.
// Pass the contents of a trusted_root.json produced by `cosign trusted-root
// create`, refreshed whenever the client is rebuilt.
func NewVerifier(trustedRootJSON []byte) (*Verifier, error) {
	if len(trustedRootJSON) == 0 {
		return nil, errors.New("embedded Sigstore trusted root is required")
	}
	trustedRoot, err := sigroot.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("load Sigstore trusted root: %w", err)
	}
	// Require a transparency-log entry and an observer timestamp: without them
	// a signature carries no evidence of when it was made, and a leaked
	// short-lived certificate could be reused indefinitely.
	inner, err := sigverify.NewVerifier(
		trustedRoot,
		sigverify.WithSignedCertificateTimestamps(1),
		sigverify.WithTransparencyLog(1),
		sigverify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("configure Sigstore verifier: %w", err)
	}
	return &Verifier{inner: inner}, nil
}

// Verify checks that bundleJSON is a valid Sigstore bundle over manifestJSON,
// signed by a certificate issued to the pinned release workflow identity, then
// parses and validates the manifest itself.
//
// Both arguments are untrusted bytes from any source. Nothing about where they
// came from is consulted.
func (v *Verifier) Verify(_ context.Context, manifestJSON, bundleJSON []byte) (*Manifest, error) {
	if v == nil || v.inner == nil {
		return nil, errors.New("release verifier is not configured")
	}
	if len(manifestJSON) == 0 || len(bundleJSON) == 0 {
		return nil, errors.New("release manifest and signature bundle are both required")
	}
	if len(manifestJSON) > maxManifestBytes {
		return nil, fmt.Errorf("release manifest exceeds %d bytes", maxManifestBytes)
	}

	var parsedBundle sigbundle.Bundle
	if err := parsedBundle.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("decode signature bundle: %w", err)
	}

	identity, err := sigverify.NewShortCertificateIdentity(
		CertificateOIDCIssuer, "", CertificateIdentity, "",
	)
	if err != nil {
		return nil, fmt.Errorf("build certificate identity policy: %w", err)
	}

	if _, err := v.inner.Verify(&parsedBundle, sigverify.NewPolicy(
		sigverify.WithArtifact(bytes.NewReader(manifestJSON)),
		sigverify.WithCertificateIdentity(identity),
	)); err != nil {
		return nil, fmt.Errorf("verify release manifest signature: %w", err)
	}

	manifest, err := ParseManifest(manifestJSON)
	if err != nil {
		return nil, err
	}
	if manifest.Source.Repository != SourceRepository {
		return nil, fmt.Errorf("release manifest names repository %q", manifest.Source.Repository)
	}
	if err := manifest.checkEncryptionFloor(); err != nil {
		return nil, err
	}
	return manifest, nil
}

// checkEncryptionFloor rejects a correctly signed manifest that advertises a
// weaker body-encryption profile than this client will accept. The floor lives
// in the measured client binary; a fetched manifest may choose which build to
// trust, never what protection that build owes the caller.
func (m *Manifest) checkEncryptionFloor() error {
	profile := m.SecurityProfile.BodyE2EE
	if profile.Protocol != attestation.EHBPProtocol ||
		profile.Suite != attestation.EHBPSuite ||
		profile.Endpoint != attestation.ConfidentialEndpoint {
		return errors.New("release manifest advertises an unsupported body-encryption profile")
	}
	return nil
}

// Policy converts verified manifests into the pinned trust policy the
// attestation verifier already enforces.
//
// It deliberately round-trips through attestation.ParsePolicy instead of
// constructing a Policy directly: every rule that guards a hand-written policy
// file — schema versions, the e2ee contract, release count, canonical PCR
// encoding, duplicate revisions — then guards a fetched one too, in the same
// code path, with no second implementation to drift.
//
// Pass the releases a client should accept during a rollout, newest first.
func Policy(manifests ...*Manifest) (*attestation.Policy, error) {
	if len(manifests) == 0 {
		return nil, errors.New("at least one verified release manifest is required")
	}
	releases := make([]attestation.Release, 0, len(manifests))
	for _, manifest := range manifests {
		if manifest == nil {
			return nil, errors.New("verified release manifest is nil")
		}
		releases = append(releases, attestation.Release{
			SourceRevision: manifest.Source.Revision,
			PCR0:           manifest.Enclave.Measurements.PCR0,
			PCR1:           manifest.Enclave.Measurements.PCR1,
			PCR2:           manifest.Enclave.Measurements.PCR2,
		})
	}
	document, err := json.Marshal(struct {
		SchemaVersion         int                    `json:"schema_version"`
		ManifestSchemaVersion int                    `json:"manifest_schema_version"`
		Workload              string                 `json:"workload"`
		Profile               string                 `json:"profile"`
		E2EE                  attestation.E2EEPolicy `json:"e2ee"`
		Releases              []attestation.Release  `json:"releases"`
	}{
		SchemaVersion:         attestation.PolicySchemaVersion,
		ManifestSchemaVersion: attestation.ManifestSchemaVersion,
		Workload:              attestation.GatewayWorkload,
		Profile:               attestation.GatewayProfile,
		E2EE: attestation.E2EEPolicy{
			Protocol:          attestation.EHBPProtocol,
			Suite:             attestation.EHBPSuite,
			Endpoint:          attestation.ConfidentialEndpoint,
			RequestEncrypted:  true,
			ResponseEncrypted: true,
		},
		Releases: releases,
	})
	if err != nil {
		return nil, fmt.Errorf("encode derived trust policy: %w", err)
	}
	return attestation.ParsePolicy(document)
}
