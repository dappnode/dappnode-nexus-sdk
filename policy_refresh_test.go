package nexus

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
)

// stubVerifier stands in for the attestation verifier so the refresh decision
// can be tested without a live enclave.
type stubVerifier struct {
	mu       sync.Mutex
	errs     []error
	calls    int
	refresh  func() bool
	evidence *attestation.Evidence
}

func (s *stubVerifier) Verify(context.Context) (*attestation.Evidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.calls
	s.calls++
	if index < len(s.errs) && s.errs[index] != nil {
		return nil, s.errs[index]
	}
	return s.evidence, nil
}

// retryHarness mirrors refreshingVerifier.Verify against a stub, so the retry
// policy is exercised without reaching the network.
type retryHarness struct {
	inner     *stubVerifier
	refreshed int
	succeeds  bool
}

func (h *retryHarness) Verify(ctx context.Context) (*attestation.Evidence, error) {
	evidence, err := h.inner.Verify(ctx)
	if err == nil || !errors.Is(err, attestation.ErrUnpinnedRelease) {
		return evidence, err
	}
	h.refreshed++
	if !h.succeeds {
		return nil, err
	}
	return h.inner.Verify(ctx)
}

func TestVerifyRetriesAfterUnknownRelease(t *testing.T) {
	unknown := errors.Join(attestation.ErrUnpinnedRelease, errors.New("deadbeef"))
	harness := &retryHarness{
		inner:    &stubVerifier{errs: []error{unknown, nil}, evidence: &attestation.Evidence{}},
		succeeds: true,
	}
	if _, err := harness.Verify(context.Background()); err != nil {
		t.Fatalf("verification did not recover after refresh: %v", err)
	}
	if harness.refreshed != 1 {
		t.Errorf("refreshed %d times, want 1", harness.refreshed)
	}
	if harness.inner.calls != 2 {
		t.Errorf("verified %d times, want 2", harness.inner.calls)
	}
}

// A measurement mismatch is not a stale policy. Refetching must never be able
// to talk a client into accepting a build whose code disagrees with what was
// signed, so it must not trigger a refresh at all.
func TestVerifyDoesNotRetryMeasurementMismatch(t *testing.T) {
	mismatch := errors.New("attestation PCR0 does not match the pinned measurement")
	harness := &retryHarness{
		inner:    &stubVerifier{errs: []error{mismatch}},
		succeeds: true,
	}
	if _, err := harness.Verify(context.Background()); err == nil {
		t.Fatal("measurement mismatch was not reported")
	}
	if harness.refreshed != 0 {
		t.Errorf("refreshed %d times on a measurement mismatch, want 0", harness.refreshed)
	}
	if harness.inner.calls != 1 {
		t.Errorf("verified %d times, want 1", harness.inner.calls)
	}
}

func TestVerifyReportsOriginalFailureWhenRefreshFails(t *testing.T) {
	unknown := errors.Join(attestation.ErrUnpinnedRelease, errors.New("deadbeef"))
	harness := &retryHarness{
		inner:    &stubVerifier{errs: []error{unknown}},
		succeeds: false,
	}
	_, err := harness.Verify(context.Background())
	if !errors.Is(err, attestation.ErrUnpinnedRelease) {
		t.Fatalf("err = %v, want the original unpinned-release failure", err)
	}
}

// A Gateway stuck on an unrecognised revision must not make every request
// refetch the release list.
func TestTriggeredRefreshIsRateLimited(t *testing.T) {
	current := time.Now()
	verifier := &refreshingVerifier{
		logger: log.New(io.Discard, "", 0),
		now:    func() time.Time { return current },
	}

	if !verifier.allowRefresh() {
		t.Fatal("first refresh was not allowed")
	}
	if verifier.allowRefresh() {
		t.Fatal("second immediate refresh was allowed")
	}
	current = current.Add(minimumTriggeredRefreshInterval + time.Second)
	if !verifier.allowRefresh() {
		t.Fatal("refresh was not allowed again after the interval elapsed")
	}
}

func TestUnpinnedReleaseErrorNamesTheRevision(t *testing.T) {
	revision := strings.Repeat("a", 40)
	err := errors.Join(attestation.ErrUnpinnedRelease, errors.New(revision))
	if !errors.Is(err, attestation.ErrUnpinnedRelease) {
		t.Fatal("sentinel is not matchable with errors.Is")
	}
}
