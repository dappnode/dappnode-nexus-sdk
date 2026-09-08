package nexus

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/release"
)

// evidenceVerifier is the attestation surface the confidential client needs.
// Declaring it here lets a plain verifier and a policy-refreshing one be used
// interchangeably.
type evidenceVerifier interface {
	Verify(context.Context) (*attestation.Evidence, error)
}

// minimumTriggeredRefreshInterval bounds how often a failed verification may
// cause a refresh. Without it a Gateway serving an unrecognised revision would
// make every request fetch the release list again.
const minimumTriggeredRefreshInterval = time.Minute

// refreshingVerifier refreshes the trust policy the moment it meets a Gateway
// release it does not recognise, then verifies once more.
//
// This is the event that actually matters, and it needs no push channel: a
// newly deployed Gateway announces itself by attesting a revision the current
// policy has never heard of. Waiting for the next periodic refresh would fail
// closed in the meantime, which is correct but needlessly disruptive when the
// signed release proving that revision is already published.
//
// Only ErrUnpinnedRelease triggers this. A pinned revision whose measurements
// disagree is never retried: refetching must not be able to talk a client into
// accepting a build whose code does not match what was signed.
type refreshingVerifier struct {
	inner  *attestation.Verifier
	source *release.Source
	logger *log.Logger

	mu          sync.Mutex
	lastRefresh time.Time
	now         func() time.Time
}

func newRefreshingVerifier(
	inner *attestation.Verifier,
	source *release.Source,
	logger *log.Logger,
) *refreshingVerifier {
	return &refreshingVerifier{inner: inner, source: source, logger: logger, now: time.Now}
}

// allowRefresh reports whether enough time has passed since the last triggered
// refresh, recording the attempt when it does.
func (v *refreshingVerifier) allowRefresh() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.lastRefresh.IsZero() && v.now().Sub(v.lastRefresh) < minimumTriggeredRefreshInterval {
		return false
	}
	v.lastRefresh = v.now()
	return true
}

func (v *refreshingVerifier) Verify(ctx context.Context) (*attestation.Evidence, error) {
	evidence, err := v.inner.Verify(ctx)
	if err == nil || !errors.Is(err, attestation.ErrUnpinnedRelease) {
		return evidence, err
	}
	if !v.refresh(ctx) {
		// Return the original verification failure, not the refresh error: the
		// caller's request failed because the Gateway is unrecognised, and
		// saying so is more useful than reporting how the retry went.
		return nil, err
	}
	return v.inner.Verify(ctx)
}

// refresh re-derives the policy from signed releases, reporting whether the
// policy in force actually changed. A failure leaves the previous policy
// untouched.
func (v *refreshingVerifier) refresh(ctx context.Context) bool {
	if !v.allowRefresh() {
		return false
	}
	policy, err := v.source.Policy(ctx)
	if err != nil {
		v.logger.Printf("refresh trust policy after meeting an unknown Gateway release: %v", err)
		return false
	}
	if err := v.inner.SetPolicy(policy); err != nil {
		v.logger.Printf("apply refreshed trust policy: %v", err)
		return false
	}
	return true
}
