package ledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newPersistedLedger(t *testing.T, path string) *Ledger {
	t.Helper()
	record, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func seed(t *testing.T, record *Ledger) {
	t.Helper()
	record.RecordVerified(Attestation{
		ID:             "abc123",
		VerifiedAt:     time.Unix(1700000000, 0).UTC(),
		PCR0:           "f9dc7325",
		SourceRevision: "bda15a3",
		Checks:         []Check{{Name: "pcr0", Passed: true, Detail: "matched"}},
	}, []byte("cose-document-bytes"), json.RawMessage(`{"workload":"gateway"}`))
	record.RecordRequest(Request{ID: "r1", Outcome: OutcomeEncrypted, RequestBytes: 120, ResponseBytes: 340})
	record.RecordRejected("pinned measurement mismatch")
}

func TestLedgerSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "ledger.json")

	first := newPersistedLedger(t, path)
	seed(t, first)
	if err := first.Flush(); err != nil {
		t.Fatal(err)
	}

	second := newPersistedLedger(t, path)
	snapshot := second.Snapshot()

	if snapshot.VerifiedTotal != 1 || snapshot.RejectedTotal != 1 || snapshot.EncryptedTotal != 1 {
		t.Fatalf("counters = verified %d, rejected %d, encrypted %d",
			snapshot.VerifiedTotal, snapshot.RejectedTotal, snapshot.EncryptedTotal)
	}
	if len(snapshot.Requests) != 1 || snapshot.Requests[0].ID != "r1" {
		t.Fatalf("requests = %+v", snapshot.Requests)
	}
	if len(snapshot.Attestations) != 2 {
		t.Fatalf("attestations = %d, want 2", len(snapshot.Attestations))
	}

	// The exported evidence must survive too, or the page can show a past
	// verification it cannot back up with the signed document.
	document, manifest, found := second.Document("abc123")
	if !found {
		t.Fatal("attestation evidence did not survive the restart")
	}
	if string(document) != "cose-document-bytes" {
		t.Fatalf("document = %q", document)
	}
	if string(manifest) != `{"workload":"gateway"}` {
		t.Fatalf("manifest = %q", manifest)
	}
}

// The load-bearing property: the ledger never receives a prompt or completion,
// and the on-disk format cannot express one either.
func TestPersistedStateNeverContainsBodies(t *testing.T) {
	const promptCanary = "PROMPT-CANARY-do-not-persist"
	const completionCanary = "COMPLETION-CANARY-do-not-persist"

	path := filepath.Join(t.TempDir(), "ledger.json")
	record := newPersistedLedger(t, path)
	seed(t, record)
	// Whatever a caller puts in the metadata fields, bodies are not among them.
	record.RecordRequest(Request{ID: "r2", Outcome: OutcomeFailed, Failure: "Gateway attestation failed"})
	if err := record.Flush(); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{promptCanary, completionCanary} {
		if bytes.Contains(written, []byte(canary)) {
			t.Fatalf("persisted state contains %q", canary)
		}
	}
	// The format has no field that could carry one.
	for _, forbidden := range []string{"\"messages\"", "\"choices\"", "\"content\"", "\"prompt\"", "\"completion\""} {
		if bytes.Contains(written, []byte(forbidden)) {
			t.Fatalf("persisted state exposes a body-shaped field: %s", forbidden)
		}
	}
}

func TestStateFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	record := newPersistedLedger(t, path)
	seed(t, record)
	if err := record.Flush(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("state file mode = %v, want 0600", mode)
	}
}

// A corrupt or foreign state file must not stop the proxy from starting: the
// history is evidence about the past, not a precondition for protecting the
// next request.
func TestUnreadableStateStartsEmptyInsteadOfFailing(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":      "not json at all",
		"wrong schema": `{"schema_version":99,"verified_total":7}`,
		"empty":        "",
		"truncated":    `{"schema_version":1,"attestations":[`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			record, err := Open(path)
			if err != nil {
				t.Fatalf("Open refused to start: %v", err)
			}
			snapshot := record.Snapshot()
			if snapshot.VerifiedTotal != 0 || len(snapshot.Attestations) != 0 {
				t.Fatalf("recovered state from an unusable file: %+v", snapshot)
			}
		})
	}
}

// A ledger with no state file must behave exactly as before: nothing on disk.
func TestMemoryOnlyLedgerWritesNothing(t *testing.T) {
	directory := t.TempDir()
	record := New()
	seed(t, record)
	if err := record.Flush(); err != nil {
		t.Fatalf("Flush on a memory-only ledger errored: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("memory-only ledger wrote %d files", len(entries))
	}
}

func TestFlushIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ledger.json")
	record := newPersistedLedger(t, path)
	for i := 0; i < 5; i++ {
		seed(t, record)
		if err := record.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ledger.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory contains %v, want only ledger.json", names)
	}
}
