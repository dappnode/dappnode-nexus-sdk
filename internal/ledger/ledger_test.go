package ledger

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestSnapshotIsNewestFirstAndCapped(t *testing.T) {
	record := New()
	for index := range maxRequests + 20 {
		record.RecordRequest(Request{ID: fmt.Sprintf("req-%03d", index), Outcome: OutcomeEncrypted})
	}
	snapshot := record.Snapshot()
	if len(snapshot.Requests) != maxRequests {
		t.Fatalf("kept %d requests, want %d", len(snapshot.Requests), maxRequests)
	}
	newest := fmt.Sprintf("req-%03d", maxRequests+19)
	if snapshot.Requests[0].ID != newest {
		t.Fatalf("newest = %q, want %q", snapshot.Requests[0].ID, newest)
	}
	oldest := fmt.Sprintf("req-%03d", 20)
	if snapshot.Requests[len(snapshot.Requests)-1].ID != oldest {
		t.Fatalf("oldest = %q, want %q", snapshot.Requests[len(snapshot.Requests)-1].ID, oldest)
	}
	if snapshot.EncryptedTotal != uint64(maxRequests+20) {
		t.Fatalf("encrypted total = %d, want %d", snapshot.EncryptedTotal, maxRequests+20)
	}
}

func TestStatusFollowsTheNewestAttestation(t *testing.T) {
	record := New()
	if record.Snapshot().Status != "starting" {
		t.Fatal("an empty ledger must report starting")
	}

	record.RecordVerified(Attestation{ID: "aaaa", ExpiresAt: time.Now().Add(time.Minute)}, []byte("doc"), json.RawMessage(`{}`))
	if snapshot := record.Snapshot(); snapshot.Status != OutcomeVerified || snapshot.Current == nil || snapshot.Current.ID != "aaaa" {
		t.Fatalf("snapshot after success = %+v", snapshot)
	}

	record.RecordRejected("stale evidence")
	snapshot := record.Snapshot()
	if snapshot.Status != OutcomeRejected || snapshot.Current != nil {
		t.Fatalf("a later rejection must clear the verified status: %+v", snapshot)
	}
	if snapshot.VerifiedTotal != 1 || snapshot.RejectedTotal != 1 {
		t.Fatalf("totals = %d/%d", snapshot.VerifiedTotal, snapshot.RejectedTotal)
	}
}

// Retained evidence must survive being re-verified many times so an operator
// can still export an older document from the history.
func TestDocumentLookupCoversRetainedHistory(t *testing.T) {
	record := New()
	record.RecordVerified(Attestation{ID: "first"}, []byte("first-doc"), json.RawMessage(`{"a":1}`))
	for index := range 5 {
		record.RecordVerified(Attestation{ID: fmt.Sprintf("later-%d", index)}, []byte("later-doc"), json.RawMessage(`{}`))
	}
	document, manifest, ok := record.Document("first")
	if !ok || string(document) != "first-doc" || string(manifest) != `{"a":1}` {
		t.Fatalf("Document(first) = %q, %q, %v", document, manifest, ok)
	}
	if _, _, ok := record.Document("missing"); ok {
		t.Fatal("Document(missing) must not resolve")
	}
}

func TestSnapshotJSONCarriesNoBodyFields(t *testing.T) {
	record := New()
	record.RecordVerified(Attestation{ID: "aaaa"}, []byte("secret-document"), json.RawMessage(`{"manifest":true}`))
	encoded, err := json.Marshal(record.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	// The document and manifest are unexported: they are reachable only through
	// the explicit export endpoint, never through the polling snapshot.
	if string(encoded) == "" || contains(string(encoded), "secret-document") || contains(string(encoded), "manifest\":true") {
		t.Fatalf("snapshot JSON embedded retained evidence: %s", encoded)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && func() bool {
		for index := 0; index+len(needle) <= len(haystack); index++ {
			if haystack[index:index+len(needle)] == needle {
				return true
			}
		}
		return false
	}()
}

func TestFingerprintKeyIsStableAndShort(t *testing.T) {
	first := FingerprintKey([]byte("x25519-public-key"))
	if first != FingerprintKey([]byte("x25519-public-key")) {
		t.Fatal("FingerprintKey is not deterministic")
	}
	if first == FingerprintKey([]byte("another-key")) {
		t.Fatal("distinct keys share a fingerprint")
	}
	if len(first) != 16 {
		t.Fatalf("fingerprint length = %d, want 16", len(first))
	}
}
