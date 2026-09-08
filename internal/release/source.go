package release

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

// trustedRootJSON is the Sigstore trusted root this client verifies against,
// fixed at build time. Regenerate it when the client is rebuilt; see
// CONTRIBUTING.md. Embedding rather than fetching keeps the decision about
// which signing authority to believe inside the measured binary, exactly like
// the AWS Nitro root fingerprint.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

const (
	// DefaultRepository is the Gateway repository whose signed releases
	// describe the enclave builds this client may trust.
	DefaultRepository = "dappnode/dappnode-nexus-gateway"

	// DefaultReleaseCount is how many recent releases are fetched. A Gateway
	// rollout is only ever between two adjacent releases, so three covers any
	// realistic deploy window while keeping the trusted set small. It must stay
	// at or below attestation's own policy cap.
	DefaultReleaseCount = 3

	manifestSuffix = ".release.json"
	bundleSuffix   = ".release.json.sigstore.json"

	maxReleaseListBytes = 1 << 20
	maxBundleBytes      = 512 << 10
	maxAssetsPerRelease = 32
	maxRedirects        = 5
)

// allowedDownloadHosts are the only hosts an asset may be fetched from. The
// release listing is untrusted JSON, so the URLs in it are treated as
// attacker-chosen: without this an attacker could point the client at an
// internal address and use it as a probe.
var allowedDownloadHosts = map[string]struct{}{
	"api.github.com":                       {},
	"github.com":                           {},
	"objects.githubusercontent.com":        {},
	"release-assets.githubusercontent.com": {},
}

// Source discovers and verifies signed Gateway release manifests.
//
// Nothing it downloads is trusted on the strength of where it came from. The
// release listing only supplies candidate URLs; every manifest is accepted
// solely because a Sigstore certificate issued to the pinned release workflow
// signed it.
type Source struct {
	repository string
	count      int
	client     *http.Client
	verifier   *Verifier

	mu    sync.Mutex
	cache Cache
}

// Cache persists the raw signed material of the last successful fetch so an
// offline client can rebuild the same policy. Implementations store opaque
// bytes; the SDK re-verifies every signature on load, so a tampered cache is
// rejected rather than trusted.
type Cache interface {
	Load() ([]SignedRelease, error)
	Store([]SignedRelease) error
}

// SignedRelease is one manifest and the detached bundle that signs it.
type SignedRelease struct {
	Manifest []byte `json:"manifest"`
	Bundle   []byte `json:"bundle"`
}

// NewSource creates a release source. repository is "owner/name"; an empty
// value uses DefaultRepository. A count of zero uses DefaultReleaseCount.
func NewSource(repository string, count int, client *http.Client) (*Source, error) {
	if repository == "" {
		repository = DefaultRepository
	}
	if !validRepository(repository) {
		return nil, fmt.Errorf("invalid repository %q, want owner/name", repository)
	}
	if count == 0 {
		count = DefaultReleaseCount
	}
	if count < 1 || count > attestation.MaxPolicyReleases {
		return nil, fmt.Errorf("release count must be between 1 and %d", attestation.MaxPolicyReleases)
	}
	verifier, err := NewVerifier(trustedRootJSON)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{}
	}
	guarded := *client
	guarded.CheckRedirect = allowGitHubRedirects
	return &Source{repository: repository, count: count, client: &guarded, verifier: verifier}, nil
}

// WithCache stores every successful fetch so a later offline start can reuse
// it. Without a cache the source is network-only.
func (s *Source) WithCache(cache Cache) *Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = cache
	return s
}

// Policy fetches the most recent signed releases and derives a trust policy.
//
// If the network is unavailable it falls back to the cached signed material and
// re-verifies it. It never falls back to trusting something unverified: an
// error here means the caller must keep whatever policy it already had, or
// refuse to start.
func (s *Source) Policy(ctx context.Context) (*attestation.Policy, error) {
	manifests, fetchErr := s.fetch(ctx)
	if fetchErr == nil {
		return Policy(manifests...)
	}
	cached, cacheErr := s.cached()
	if cacheErr != nil {
		return nil, fmt.Errorf("%w (cached releases unusable: %v)", fetchErr, cacheErr)
	}
	return Policy(cached...)
}

func (s *Source) fetch(ctx context.Context) ([]*Manifest, error) {
	listed, err := s.listReleases(ctx)
	if err != nil {
		return nil, err
	}
	signed := make([]SignedRelease, 0, len(listed))
	manifests := make([]*Manifest, 0, len(listed))
	var firstErr error
	for _, candidate := range listed {
		manifestBytes, err := s.download(ctx, candidate.manifestURL, maxManifestBytes)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		bundleBytes, err := s.download(ctx, candidate.bundleURL, maxBundleBytes)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		manifest, err := s.verifier.Verify(ctx, manifestBytes, bundleBytes)
		if err != nil {
			// A release that fails verification is skipped, not fatal: a
			// staging build or a schema the client predates must not stop it
			// from trusting the releases it does understand.
			firstErr = errors.Join(firstErr, err)
			continue
		}
		manifests = append(manifests, manifest)
		signed = append(signed, SignedRelease{Manifest: manifestBytes, Bundle: bundleBytes})
		if len(manifests) == s.count {
			break
		}
	}
	if len(manifests) == 0 {
		if firstErr == nil {
			firstErr = errors.New("no signed releases found")
		}
		return nil, fmt.Errorf("fetch signed Gateway releases: %w", firstErr)
	}
	s.store(signed)
	return manifests, nil
}

func (s *Source) cached() ([]*Manifest, error) {
	s.mu.Lock()
	cache := s.cache
	s.mu.Unlock()
	if cache == nil {
		return nil, errors.New("no release cache configured")
	}
	entries, err := cache.Load()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("release cache is empty")
	}
	manifests := make([]*Manifest, 0, len(entries))
	for _, entry := range entries {
		// Re-verified on every load. The cache file lives on ordinary disk, so
		// its contents are no more trusted than the network's.
		manifest, err := s.verifier.Verify(context.Background(), entry.Manifest, entry.Bundle)
		if err != nil {
			return nil, fmt.Errorf("cached release failed verification: %w", err)
		}
		manifests = append(manifests, manifest)
		if len(manifests) == s.count {
			break
		}
	}
	return manifests, nil
}

func (s *Source) store(entries []SignedRelease) {
	s.mu.Lock()
	cache := s.cache
	s.mu.Unlock()
	if cache == nil || len(entries) == 0 {
		return
	}
	_ = cache.Store(entries)
}

type candidate struct {
	manifestURL string
	bundleURL   string
	publishedAt string
}

type releaseListing struct {
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (s *Source) listReleases(ctx context.Context) ([]candidate, error) {
	// Ask for more than count: drafts, prereleases, and releases whose assets
	// do not match are skipped, and a strict page of count could return none.
	perPage := s.count * 3
	endpoint := fmt.Sprintf(
		"https://api.github.com/repos/%s/releases?per_page=%d",
		s.repository, perPage,
	)
	body, err := s.download(ctx, endpoint, maxReleaseListBytes)
	if err != nil {
		return nil, fmt.Errorf("list Gateway releases: %w", err)
	}
	var listings []releaseListing
	if err := json.Unmarshal(body, &listings); err != nil {
		return nil, fmt.Errorf("decode Gateway release listing: %w", err)
	}
	candidates := make([]candidate, 0, len(listings))
	for _, listing := range listings {
		if listing.Draft || listing.Prerelease || len(listing.Assets) > maxAssetsPerRelease {
			continue
		}
		var manifestURL, bundleURL string
		for _, asset := range listing.Assets {
			switch {
			case strings.HasSuffix(asset.Name, bundleSuffix):
				bundleURL = asset.URL
			case strings.HasSuffix(asset.Name, manifestSuffix):
				manifestURL = asset.URL
			}
		}
		if manifestURL == "" || bundleURL == "" {
			continue
		}
		candidates = append(candidates, candidate{
			manifestURL: manifestURL,
			bundleURL:   bundleURL,
			publishedAt: listing.PublishedAt,
		})
	}
	if len(candidates) == 0 {
		return nil, errors.New("no release carries both a manifest and a signature bundle")
	}
	// GitHub returns newest first, but the order is not contractual and the
	// listing is untrusted input. Sorting makes "most recent" mean the same
	// thing regardless of what the server sent.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].publishedAt > candidates[j].publishedAt
	})
	return candidates, nil
}

func (s *Source) download(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	if err := checkDownloadURL(rawURL); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create release request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "nexus-proxy/1")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", redact(rawURL), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", redact(rawURL), response.StatusCode)
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err == nil {
		if mediaType != "application/json" && mediaType != "application/octet-stream" {
			return nil, fmt.Errorf("%s returned unexpected content type %q", redact(rawURL), mediaType)
		}
	}
	body, err := jsonutil.ReadAllLimited(response.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", redact(rawURL), err)
	}
	return body, nil
}

func checkDownloadURL(rawURL string) error {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid release URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("release URLs must be HTTPS without credentials")
	}
	if _, allowed := allowedDownloadHosts[parsed.Hostname()]; !allowed {
		return fmt.Errorf("release host %q is not allowed", parsed.Hostname())
	}
	return nil
}

// allowGitHubRedirects permits the redirect GitHub uses to hand an asset off to
// its object store, while refusing to follow one anywhere else.
func allowGitHubRedirects(request *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return checkDownloadURL(request.URL.String())
}

func redact(rawURL string) string {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "release URL"
	}
	return parsed.Hostname() + parsed.EscapedPath()
}

func validRepository(value string) bool {
	owner, name, found := strings.Cut(value, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return false
	}
	for _, part := range []string{owner, name} {
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			case r == '-', r == '_', r == '.':
			default:
				return false
			}
		}
	}
	return true
}
