package confidential

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const (
	maxEncryptedResponseFrame = 64 << 20
	maxProblemResponseBody    = 64 << 10
)

type guardingTransport struct {
	next http.RoundTripper
}

// GuardEHBPResponses validates raw EHBP response framing before the upstream
// EHBP library decrypts it. This rejects zero frames (which v0.2.6 skips using
// recursion), oversized allocations, and truncated prefixes/ciphertexts.
func GuardEHBPResponses(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &guardingTransport{next: next}
}

func (t *guardingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	responseNonces := response.Header.Values(protocol.ResponseNonceHeader)
	if len(responseNonces) > 0 && (len(responseNonces) != 1 || !canonicalResponseNonce(responseNonces[0])) {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errors.New("invalid EHBP response nonce header")
	}
	if len(responseNonces) == 1 && response.Body != nil {
		response.Body = &frameGuardReader{source: response.Body}
	}
	if response.StatusCode == http.StatusUnprocessableEntity &&
		isMediaType(response.Header.Get("Content-Type"), protocol.ProblemJSONMediaType) && response.Body != nil {
		response.Body = &boundedReadCloser{source: response.Body, remaining: maxProblemResponseBody}
	}
	return response, nil
}

func canonicalResponseNonce(encoded string) bool {
	if len(encoded) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == encoded
}

func isMediaType(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, expected)
}

type boundedReadCloser struct {
	source    io.ReadCloser
	remaining int64
	checked   bool
}

func (r *boundedReadCloser) Read(destination []byte) (int, error) {
	if r.remaining > 0 {
		if int64(len(destination)) > r.remaining {
			destination = destination[:r.remaining]
		}
		count, err := r.source.Read(destination)
		r.remaining -= int64(count)
		return count, err
	}
	if r.checked {
		return 0, errors.New("EHBP problem response exceeds 65536 bytes")
	}
	r.checked = true
	var probe [1]byte
	count, err := r.source.Read(probe[:])
	if count > 0 {
		return 0, errors.New("EHBP problem response exceeds 65536 bytes")
	}
	return 0, err
}

func (r *boundedReadCloser) Close() error {
	return r.source.Close()
}

type frameGuardReader struct {
	source         io.ReadCloser
	header         [4]byte
	headerOffset   int
	frameRemaining uint32
	pendingError   error
	eof            bool
}

func (r *frameGuardReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if r.pendingError != nil {
		err := r.pendingError
		r.pendingError = nil
		return 0, err
	}
	if r.eof {
		return 0, io.EOF
	}

	written := 0
	for written < len(destination) {
		if r.headerOffset < len(r.header) && (r.headerOffset > 0 || r.frameRemaining > 0) {
			copied := copy(destination[written:], r.header[r.headerOffset:])
			r.headerOffset += copied
			written += copied
			if written == len(destination) {
				return written, nil
			}
			continue
		}

		if r.frameRemaining > 0 {
			want := min(len(destination)-written, int(r.frameRemaining))
			count, err := r.source.Read(destination[written : written+want])
			written += count
			r.frameRemaining -= uint32(count)
			if err != nil {
				if errors.Is(err, io.EOF) && r.frameRemaining > 0 {
					err = errors.New("truncated EHBP response ciphertext")
				}
				if written > 0 {
					r.pendingError = err
					return written, nil
				}
				return 0, err
			}
			if count == 0 {
				continue
			}
			if r.frameRemaining == 0 {
				r.headerOffset = 0
				r.header = [4]byte{}
			}
			continue
		}

		count, err := io.ReadFull(r.source, r.header[:])
		if err != nil {
			if errors.Is(err, io.EOF) && count == 0 {
				r.eof = true
				if written > 0 {
					return written, nil
				}
				return 0, io.EOF
			}
			frameErr := errors.New("truncated EHBP response frame prefix")
			if written > 0 {
				r.pendingError = frameErr
				return written, nil
			}
			return 0, frameErr
		}
		frameLength := binary.BigEndian.Uint32(r.header[:])
		if frameLength == 0 {
			return written, errors.New("zero-length EHBP response frame")
		}
		if frameLength > maxEncryptedResponseFrame {
			return written, fmt.Errorf("EHBP response frame exceeds %d bytes", maxEncryptedResponseFrame)
		}
		r.frameRemaining = frameLength
		r.headerOffset = 0
	}
	return written, nil
}

func (r *frameGuardReader) Close() error {
	return r.source.Close()
}
