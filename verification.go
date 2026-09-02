package nexus

import (
	"encoding/json"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

// Check is one condition that passed or failed during Gateway verification.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Attestation is one verification attempt against the pinned trust policy.
// It contains no secret values.
type Attestation struct {
	ID         string    `json:"id"`
	Outcome    string    `json:"outcome"`
	VerifiedAt time.Time `json:"verified_at"`
	Failure    string    `json:"failure,omitempty"`

	AttestedAt      time.Time `json:"attested_at,omitzero"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	ModuleID        string    `json:"module_id,omitempty"`
	HPKEPublicKey   string    `json:"hpke_public_key,omitempty"`
	Nonce           string    `json:"nonce,omitempty"`
	PCR0            string    `json:"pcr0,omitempty"`
	PCR1            string    `json:"pcr1,omitempty"`
	PCR2            string    `json:"pcr2,omitempty"`
	SourceRevision  string    `json:"source_revision,omitempty"`
	Workload        string    `json:"workload,omitempty"`
	Profile         string    `json:"profile,omitempty"`
	RootFingerprint string    `json:"root_fingerprint,omitempty"`
	Checks          []Check   `json:"checks,omitempty"`
	DocumentBytes   int       `json:"document_bytes,omitempty"`
}

// Request is metadata for one inference request. It never contains an API key,
// prompt, or response.
type Request struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	DurationMS    int64     `json:"duration_ms"`
	AttestationID string    `json:"attestation_id,omitempty"`
	Outcome       string    `json:"outcome"`
	Failure       string    `json:"failure,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	RequestBytes  int       `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
	Streaming     bool      `json:"streaming"`
}

// Snapshot is the current verification state and bounded local history.
type Snapshot struct {
	Status         string        `json:"status"`
	GeneratedAt    time.Time     `json:"generated_at"`
	VerifiedTotal  uint64        `json:"verified_total"`
	RejectedTotal  uint64        `json:"rejected_total"`
	EncryptedTotal uint64        `json:"encrypted_total"`
	FailedTotal    uint64        `json:"failed_total"`
	Current        *Attestation  `json:"current,omitempty"`
	Attestations   []Attestation `json:"attestations"`
	Requests       []Request     `json:"requests"`
}

// Evidence contains the signed material needed to re-check one verification
// independently.
type Evidence struct {
	AttestationID string          `json:"attestation_id"`
	Document      []byte          `json:"document"`
	Manifest      json.RawMessage `json:"manifest"`
}

func snapshotFromLedger(source ledger.Snapshot) Snapshot {
	result := Snapshot{
		Status:         source.Status,
		GeneratedAt:    source.GeneratedAt,
		VerifiedTotal:  source.VerifiedTotal,
		RejectedTotal:  source.RejectedTotal,
		EncryptedTotal: source.EncryptedTotal,
		FailedTotal:    source.FailedTotal,
		Attestations:   make([]Attestation, len(source.Attestations)),
		Requests:       make([]Request, len(source.Requests)),
	}
	for index, record := range source.Attestations {
		result.Attestations[index] = attestationFromLedger(record)
	}
	for index, record := range source.Requests {
		result.Requests[index] = Request{
			ID:            record.ID,
			StartedAt:     record.StartedAt,
			DurationMS:    record.DurationMS,
			AttestationID: record.AttestationID,
			Outcome:       record.Outcome,
			Failure:       record.Failure,
			StatusCode:    record.StatusCode,
			RequestBytes:  record.RequestBytes,
			ResponseBytes: record.ResponseBytes,
			Streaming:     record.Streaming,
		}
	}
	if source.Current != nil {
		current := attestationFromLedger(*source.Current)
		result.Current = &current
	}
	return result
}

func attestationFromLedger(source ledger.Attestation) Attestation {
	checks := make([]Check, len(source.Checks))
	for index, check := range source.Checks {
		checks[index] = Check(check)
	}
	return Attestation{
		ID:              source.ID,
		Outcome:         source.Outcome,
		VerifiedAt:      source.VerifiedAt,
		Failure:         source.Failure,
		AttestedAt:      source.AttestedAt,
		ExpiresAt:       source.ExpiresAt,
		ModuleID:        source.ModuleID,
		HPKEPublicKey:   source.HPKEPublicKey,
		Nonce:           source.Nonce,
		PCR0:            source.PCR0,
		PCR1:            source.PCR1,
		PCR2:            source.PCR2,
		SourceRevision:  source.SourceRevision,
		Workload:        source.Workload,
		Profile:         source.Profile,
		RootFingerprint: source.RootFingerprint,
		Checks:          checks,
		DocumentBytes:   source.DocumentBytes,
	}
}
