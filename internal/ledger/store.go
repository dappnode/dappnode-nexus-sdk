package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stateSchemaVersion guards the on-disk format. A file written by a different
// version is discarded rather than half-read: losing verification history is a
// cosmetic loss, misreporting it is not.
const stateSchemaVersion = 1

// maxStateBytes bounds what will be read back from disk.
const maxStateBytes = 32 << 20

// persistedAttestation carries the evidence that Attestation keeps unexported,
// so a restart can still serve /v1/verification/document for past
// verifications. All of it is public by construction: a signed AWS document
// and the manifest it commits to.
type persistedAttestation struct {
	Attestation
	Document []byte          `json:"document,omitempty"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
}

// persistedState is the whole ledger as written to disk. It deliberately has
// no field that could hold a prompt or a completion: the in-memory ledger
// never receives one, and this format cannot express one either.
type persistedState struct {
	SchemaVersion  int                    `json:"schema_version"`
	WrittenAt      time.Time              `json:"written_at"`
	VerifiedTotal  uint64                 `json:"verified_total"`
	RejectedTotal  uint64                 `json:"rejected_total"`
	EncryptedTotal uint64                 `json:"encrypted_total"`
	FailedTotal    uint64                 `json:"failed_total"`
	Attestations   []persistedAttestation `json:"attestations"`
	Requests       []Request              `json:"requests"`
}

// store writes the ledger to disk. It is separate from Ledger so a ledger with
// no store stays exactly what it was before: memory only, nothing on disk.
type store struct {
	path string

	mu    sync.Mutex
	dirty bool
}

// Open returns a Ledger that persists to path, loading any state already
// there. A missing, unreadable, or unrecognised file is not an error: the
// proxy starts with an empty history rather than refusing to run, because
// verification history is evidence about the past, not a precondition for
// protecting the next request.
func Open(path string) (*Ledger, error) {
	if path == "" {
		return nil, errors.New("ledger state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ledger state directory: %w", err)
	}

	ledger := New()
	ledger.store = &store{path: path}
	ledger.loadFrom(path)
	return ledger, nil
}

// loadFrom restores previously written state. Errors are deliberately
// swallowed; see Open.
func (l *Ledger) loadFrom(path string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > maxStateBytes {
		return
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil || state.SchemaVersion != stateSchemaVersion {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.verifiedTotal = state.VerifiedTotal
	l.rejectedTotal = state.RejectedTotal
	l.encryptedTotal = state.EncryptedTotal
	l.failedTotal = state.FailedTotal
	for _, entry := range state.Attestations {
		record := entry.Attestation
		record.document = append([]byte(nil), entry.Document...)
		record.manifest = append(json.RawMessage(nil), entry.Manifest...)
		l.attestations = appendCapped(l.attestations, record, maxAttestations)
	}
	for _, request := range state.Requests {
		l.requests = appendCapped(l.requests, request, maxRequests)
	}
}

// markDirty notes that the ledger changed. Callers already hold l.mu.
func (l *Ledger) markDirty() {
	if l.store == nil {
		return
	}
	l.store.mu.Lock()
	l.store.dirty = true
	l.store.mu.Unlock()
}

// Flush writes the ledger to disk if it changed since the last write. It is a
// no-op for a ledger with no state file.
func (l *Ledger) Flush() error {
	if l == nil || l.store == nil {
		return nil
	}
	l.store.mu.Lock()
	if !l.store.dirty {
		l.store.mu.Unlock()
		return nil
	}
	l.store.dirty = false
	l.store.mu.Unlock()

	data, err := json.Marshal(l.snapshotForDisk())
	if err != nil {
		l.markDirty()
		return fmt.Errorf("encode ledger state: %w", err)
	}
	if err := writeFileAtomic(l.store.path, data); err != nil {
		l.markDirty()
		return err
	}
	return nil
}

func (l *Ledger) snapshotForDisk() persistedState {
	l.mu.Lock()
	defer l.mu.Unlock()

	state := persistedState{
		SchemaVersion:  stateSchemaVersion,
		WrittenAt:      l.now().UTC(),
		VerifiedTotal:  l.verifiedTotal,
		RejectedTotal:  l.rejectedTotal,
		EncryptedTotal: l.encryptedTotal,
		FailedTotal:    l.failedTotal,
		Attestations:   make([]persistedAttestation, 0, len(l.attestations)),
		Requests:       append([]Request(nil), l.requests...),
	}
	for _, record := range l.attestations {
		state.Attestations = append(state.Attestations, persistedAttestation{
			Attestation: record,
			Document:    append([]byte(nil), record.document...),
			Manifest:    append(json.RawMessage(nil), record.manifest...),
		})
	}
	return state
}

// writeFileAtomic replaces path in one step so a crash mid-write cannot leave
// a truncated ledger behind.
func writeFileAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nexus-ledger-*")
	if err != nil {
		return fmt.Errorf("create ledger temp file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set ledger state permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write ledger state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync ledger state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close ledger state: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace ledger state: %w", err)
	}
	return nil
}
