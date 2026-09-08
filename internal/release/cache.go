package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

const (
	cacheSchemaVersion = 1
	maxCacheBytes      = 8 << 20
)

// FileCache stores the signed material of the last successful release fetch so
// a client that starts without a network can rebuild the same trust policy.
//
// Nothing here is trusted on load. The file holds only the manifest and the
// detached bundle exactly as they were downloaded, and Source re-verifies both
// signatures every time it reads them, so a tampered or swapped cache file is
// rejected rather than believed. It contains no secret and no prompt.
type FileCache struct {
	path string
}

// NewFileCache stores cached releases at path.
func NewFileCache(path string) (*FileCache, error) {
	if path == "" {
		return nil, errors.New("release cache path is required")
	}
	return &FileCache{path: path}, nil
}

type cacheFile struct {
	SchemaVersion int             `json:"schema_version"`
	Releases      []SignedRelease `json:"releases"`
}

// Load returns the cached signed releases. A missing file is not an error: a
// first run legitimately has no cache, and the caller distinguishes "nothing
// cached" from "cache rejected" by the empty result.
func (c *FileCache) Load() ([]SignedRelease, error) {
	file, err := os.Open(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open release cache: %w", err)
	}
	defer file.Close()

	data, err := jsonutil.ReadAllLimited(file, maxCacheBytes)
	if err != nil {
		return nil, fmt.Errorf("read release cache: %w", err)
	}
	var parsed cacheFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decode release cache: %w", err)
	}
	if parsed.SchemaVersion != cacheSchemaVersion {
		return nil, fmt.Errorf("release cache schema_version must be %d", cacheSchemaVersion)
	}
	return parsed.Releases, nil
}

// Store replaces the cache with entries, written atomically so a crash cannot
// leave a half-written file that would fail verification on the next start.
func (c *FileCache) Store(entries []SignedRelease) error {
	if len(entries) == 0 {
		return errors.New("refusing to cache an empty release set")
	}
	data, err := json.Marshal(cacheFile{SchemaVersion: cacheSchemaVersion, Releases: entries})
	if err != nil {
		return fmt.Errorf("encode release cache: %w", err)
	}
	if len(data) > maxCacheBytes {
		return fmt.Errorf("release cache exceeds %d bytes", maxCacheBytes)
	}
	directory := filepath.Dir(c.path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create release cache directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".release-cache-*")
	if err != nil {
		return fmt.Errorf("create release cache temporary file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write release cache: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync release cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close release cache: %w", err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("set release cache mode: %w", err)
	}
	if err := os.Rename(name, c.path); err != nil {
		return fmt.Errorf("replace release cache: %w", err)
	}
	return nil
}
