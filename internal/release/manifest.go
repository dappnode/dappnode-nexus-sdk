// Package release verifies signed Gateway release manifests and converts them
// into the pinned trust policy the attestation verifier already enforces.
//
// The client does not trust the transport that delivered a manifest. It trusts
// exactly one thing: that a Sigstore certificate was issued to the release
// workflow identity compiled in below. GitHub, a CDN, or the Gateway itself may
// all serve the bytes; none of them can change what they say.
package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const (
	// ManifestSchemaVersion is the release manifest layout this client reads.
	// deploy/nitro/build-release-assets.sh emits it.
	ManifestSchemaVersion = 2

	// MeasurementsSchemaVersion is the nested measurement block's layout.
	MeasurementsSchemaVersion = 2

	// Environment separates production releases from every other build the
	// same workflow can produce. A staging release is correctly signed by the
	// same identity, so the environment is the only thing keeping it out of a
	// production client.
	Environment = "prod"

	maxManifestBytes = 64 << 10
	pcrHexLength     = 96
)

var (
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	pcrPattern      = regexp.MustCompile(`^[0-9a-f]{96}$`)
	versionPattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Manifest is the subset of the signed release manifest this client relies on.
// Fields the client does not enforce are deliberately omitted: parsing a claim
// invites trusting it, and everything trusted here must be checked.
type Manifest struct {
	SchemaVersion int `json:"schema_version"`
	Release       struct {
		Version     string `json:"version"`
		Environment string `json:"environment"`
	} `json:"release"`
	Source struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
	} `json:"source"`
	Enclave struct {
		Measurements struct {
			SchemaVersion int    `json:"schema_version"`
			PCR0          string `json:"pcr0"`
			PCR1          string `json:"pcr1"`
			PCR2          string `json:"pcr2"`
		} `json:"measurements"`
	} `json:"enclave"`
	SecurityProfile struct {
		BodyE2EE struct {
			Protocol string `json:"protocol"`
			Suite    string `json:"suite"`
			Endpoint string `json:"endpoint"`
		} `json:"body_e2ee"`
	} `json:"security_profile"`
}

// ParseManifest decodes and strictly validates manifest bytes whose signature
// has already been verified. Calling it on unverified bytes is a bug: nothing
// in here authenticates anything.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, errors.New("release manifest is empty")
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("release manifest exceeds %d bytes", maxManifestBytes)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m *Manifest) validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("release manifest schema_version must be %d", ManifestSchemaVersion)
	}
	if m.Enclave.Measurements.SchemaVersion != MeasurementsSchemaVersion {
		return fmt.Errorf("release measurements schema_version must be %d", MeasurementsSchemaVersion)
	}
	// A staging build carries a valid signature from the same workflow, so the
	// environment is a security check, not cosmetics.
	if m.Release.Environment != Environment {
		return fmt.Errorf("release environment must be %q, got %q", Environment, m.Release.Environment)
	}
	if !versionPattern.MatchString(m.Release.Version) {
		return fmt.Errorf("release version must look like v1.2.3, got %q", m.Release.Version)
	}
	if !revisionPattern.MatchString(m.Source.Revision) {
		return errors.New("source revision must be a full lowercase 40-character Git revision")
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{"pcr0", m.Enclave.Measurements.PCR0},
		{"pcr1", m.Enclave.Measurements.PCR1},
		{"pcr2", m.Enclave.Measurements.PCR2},
	} {
		if len(item.value) != pcrHexLength || !pcrPattern.MatchString(item.value) {
			return fmt.Errorf("%s must be %d canonical lowercase hexadecimal characters", item.name, pcrHexLength)
		}
		if allZeroHex(item.value) {
			return fmt.Errorf("%s is all zero (unsafe debug measurement)", item.name)
		}
	}
	return nil
}

func allZeroHex(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '0' {
			return false
		}
	}
	return true
}
