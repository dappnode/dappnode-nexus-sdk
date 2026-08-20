// Package attestation verifies AWS Nitro evidence against a client-pinned
// Nexus Gateway trust policy.
package attestation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

const (
	PolicySchemaVersion   = 1
	ManifestSchemaVersion = 4
	GatewayWorkload       = "dappnode-nexus-gateway"
	GatewayProfile        = "nexus-gateway-v2"
	ConfidentialEndpoint  = "/v1/confidential/chat/completions"
	EHBPProtocol          = "ehbp-v1"
	EHBPSuite             = "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-256-GCM"

	maxPolicyBytes = 64 << 10
	pcrBytes       = 48
)

var sourceRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// E2EEPolicy is the exact body-encryption contract that the client expects the
// measured Gateway binary to advertise.
type E2EEPolicy struct {
	Protocol          string `json:"protocol"`
	Suite             string `json:"suite"`
	Endpoint          string `json:"endpoint"`
	RequestEncrypted  bool   `json:"request_encrypted"`
	ResponseEncrypted bool   `json:"response_encrypted"`
}

// Policy is distributed out of band by the client. It deliberately pins both
// code measurements and human-readable workload claims.
type Policy struct {
	SchemaVersion         int        `json:"schema_version"`
	ManifestSchemaVersion int        `json:"manifest_schema_version"`
	Workload              string     `json:"workload"`
	Profile               string     `json:"profile"`
	SourceRevision        string     `json:"source_revision"`
	PCR0                  string     `json:"pcr0"`
	PCR1                  string     `json:"pcr1"`
	PCR2                  string     `json:"pcr2"`
	E2EE                  E2EEPolicy `json:"e2ee"`

	pcrs map[uint][]byte
}

// LoadPolicy reads and strictly validates a pinned trust policy.
func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return nil, errors.New("trust policy path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open trust policy: %w", err)
	}
	defer file.Close()

	data, err := jsonutil.ReadAllLimited(file, maxPolicyBytes)
	if err != nil {
		return nil, fmt.Errorf("read trust policy: %w", err)
	}
	var policy Policy
	if err := jsonutil.DecodeStrict(data, &policy); err != nil {
		return nil, fmt.Errorf("decode trust policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (p *Policy) validate() error {
	if p.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("trust policy schema_version must be %d", PolicySchemaVersion)
	}
	if p.ManifestSchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("trust policy manifest_schema_version must be %d", ManifestSchemaVersion)
	}
	if p.Workload != GatewayWorkload {
		return fmt.Errorf("trust policy workload must be %q", GatewayWorkload)
	}
	if p.Profile != GatewayProfile {
		return fmt.Errorf("trust policy profile must be %q", GatewayProfile)
	}
	if !sourceRevisionPattern.MatchString(p.SourceRevision) {
		return errors.New("trust policy source_revision must be a full lowercase 40-character Git revision")
	}
	if p.E2EE != (E2EEPolicy{
		Protocol:          EHBPProtocol,
		Suite:             EHBPSuite,
		Endpoint:          ConfidentialEndpoint,
		RequestEncrypted:  true,
		ResponseEncrypted: true,
	}) {
		return errors.New("trust policy e2ee contract is unsupported")
	}

	p.pcrs = make(map[uint][]byte, 3)
	for _, item := range []struct {
		index uint
		value string
	}{{0, p.PCR0}, {1, p.PCR1}, {2, p.PCR2}} {
		decoded, err := decodePCR(item.index, item.value)
		if err != nil {
			return err
		}
		p.pcrs[item.index] = decoded
	}
	return nil
}

func decodePCR(index uint, encoded string) ([]byte, error) {
	if len(encoded) != pcrBytes*2 {
		return nil, fmt.Errorf("trust policy pcr%d must contain exactly %d hexadecimal characters", index, pcrBytes*2)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("trust policy pcr%d must be canonical lowercase hexadecimal", index)
	}
	if allZero(decoded) {
		return nil, fmt.Errorf("trust policy pcr%d is all zero (unsafe debug measurement)", index)
	}
	return decoded, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func (p *Policy) expectedPCRs() map[uint][]byte {
	result := make(map[uint][]byte, len(p.pcrs))
	for index, value := range p.pcrs {
		result[index] = append([]byte(nil), value...)
	}
	return result
}
