// Package ledger keeps a small in-memory record of Gateway attestation
// verifications and the requests each one covered.
//
// The ledger deliberately never receives prompt or completion content. It
// stores verification evidence, which is public by construction, and per
// request metadata the local process already handles. Nothing is written to
// disk, so a restart starts an empty ledger.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

const (
	// Attestation is re-verified whenever the previous evidence expires, so
	// these bounds hold roughly the last few hours of an active proxy.
	maxAttestations = 64
	maxRequests     = 256

	OutcomeVerified = "verified"
	OutcomeRejected = "rejected"

	OutcomeEncrypted = "encrypted"
	OutcomeFailed    = "failed"
)

// Check is one condition the client required before it would encrypt anything
// to the Gateway.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Attestation is one verification attempt against the pinned trust policy.
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

	document []byte
	manifest json.RawMessage
}

// Request is one local inference request. It records no request or response
// content, only the envelope identifier, sizes and outcome.
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

// Ledger is safe for concurrent use.
type Ledger struct {
	mu           sync.Mutex
	attestations []Attestation
	requests     []Request
	now          func() time.Time

	verifiedTotal  uint64
	rejectedTotal  uint64
	encryptedTotal uint64
	failedTotal    uint64
}

func New() *Ledger {
	return &Ledger{
		attestations: make([]Attestation, 0, maxAttestations),
		requests:     make([]Request, 0, maxRequests),
		now:          time.Now,
	}
}

// FingerprintKey derives the stable short identifier the UI uses to link a
// request to the attested key that protected it.
func FingerprintKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

// RecordVerified stores a successful verification. document and manifest are
// retained so the operator can export and re-check them independently.
func (l *Ledger) RecordVerified(record Attestation, document []byte, manifest json.RawMessage) {
	if l == nil {
		return
	}
	record.Outcome = OutcomeVerified
	record.document = append([]byte(nil), document...)
	record.manifest = append(json.RawMessage(nil), manifest...)
	record.DocumentBytes = len(record.document)

	l.mu.Lock()
	defer l.mu.Unlock()
	if record.VerifiedAt.IsZero() {
		record.VerifiedAt = l.now().UTC()
	}
	l.verifiedTotal++
	l.attestations = appendCapped(l.attestations, record, maxAttestations)
}

// RecordRejected stores a verification the client refused to trust. A rejected
// attestation means no prompt was encrypted to that Gateway.
func (l *Ledger) RecordRejected(failure string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rejectedTotal++
	l.attestations = appendCapped(l.attestations, Attestation{
		ID:         "rejected-" + hex.EncodeToString([]byte{byte(l.rejectedTotal >> 8), byte(l.rejectedTotal)}),
		Outcome:    OutcomeRejected,
		VerifiedAt: l.now().UTC(),
		Failure:    failure,
	}, maxAttestations)
}

// RecordRequest stores one request's metadata.
func (l *Ledger) RecordRequest(record Request) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if record.Outcome == OutcomeEncrypted {
		l.encryptedTotal++
	} else {
		l.failedTotal++
	}
	l.requests = appendCapped(l.requests, record, maxRequests)
}

// Snapshot is the JSON view served to the verification UI.
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

// Snapshot returns the ledger newest-first.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()

	snapshot := Snapshot{
		GeneratedAt:    l.now().UTC(),
		VerifiedTotal:  l.verifiedTotal,
		RejectedTotal:  l.rejectedTotal,
		EncryptedTotal: l.encryptedTotal,
		FailedTotal:    l.failedTotal,
		Attestations:   withoutEvidence(reversed(l.attestations)),
		Requests:       reversed(l.requests),
	}
	switch {
	case len(snapshot.Attestations) == 0:
		snapshot.Status = "starting"
	case snapshot.Attestations[0].Outcome == OutcomeVerified:
		snapshot.Status = OutcomeVerified
		current := snapshot.Attestations[0]
		snapshot.Current = &current
	default:
		snapshot.Status = OutcomeRejected
	}
	return snapshot
}

// Document returns the raw COSE_Sign1 attestation document and its signed
// manifest for one verification, for offline re-verification.
func (l *Ledger) Document(id string) (document []byte, manifest json.RawMessage, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for index := len(l.attestations) - 1; index >= 0; index-- {
		if l.attestations[index].ID == id && len(l.attestations[index].document) > 0 {
			return l.attestations[index].document, l.attestations[index].manifest, true
		}
	}
	return nil, nil, false
}

// withoutEvidence drops the retained document and manifest from the polled
// view. They are reachable only through the explicit export endpoint, so the
// UI's refresh loop does not copy them on every poll.
func withoutEvidence(items []Attestation) []Attestation {
	for index := range items {
		items[index].document = nil
		items[index].manifest = nil
	}
	return items
}

func appendCapped[T any](items []T, item T, limit int) []T {
	if len(items) < limit {
		return append(items, item)
	}
	copy(items, items[1:])
	items[len(items)-1] = item
	return items
}

func reversed[T any](items []T) []T {
	result := make([]T, len(items))
	for index, item := range items {
		result[len(items)-1-index] = item
	}
	return result
}
