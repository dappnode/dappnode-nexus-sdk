package confidential

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type staticRoundTripper struct {
	response *http.Response
	err      error
}

func (t *staticRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return t.response, t.err
}

func TestFrameGuardPassesValidFramesUnchanged(t *testing.T) {
	wire := append(frame([]byte("first")), frame([]byte("second"))...)
	reader := &frameGuardReader{source: io.NopCloser(bytes.NewReader(wire))}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("guard output = %x, want %x", got, wire)
	}
}

func TestFrameGuardRejectsHostileFraming(t *testing.T) {
	oversized := make([]byte, 4)
	binary.BigEndian.PutUint32(oversized, maxEncryptedResponseFrame+1)
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{name: "zero frame", wire: []byte{0, 0, 0, 0}, want: "zero-length"},
		{name: "partial prefix", wire: []byte{0, 0, 1}, want: "truncated"},
		{name: "oversized", wire: oversized, want: "exceeds"},
		{name: "truncated ciphertext", wire: append([]byte{0, 0, 0, 5}, []byte("abc")...), want: "truncated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &frameGuardReader{source: io.NopCloser(bytes.NewReader(test.wire))}
			_, err := io.ReadAll(reader)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ReadAll() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGuardCapsUnauthenticatedKeyMismatchBody(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusUnprocessableEntity,
		Header: http.Header{
			"Content-Type": {protocol.ProblemJSONMediaType},
		},
		Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxProblemResponseBody+1))),
	}
	transport := GuardEHBPResponses(&staticRoundTripper{response: response})
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(gotResponse.Body)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ReadAll() error = %v, want size error", err)
	}
	if len(body) > maxProblemResponseBody {
		t.Fatalf("body length = %d, want at most %d", len(body), maxProblemResponseBody)
	}
}

func TestGuardRejectsMalformedOrDuplicateResponseNonce(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
	}{
		{name: "malformed", header: http.Header{protocol.ResponseNonceHeader: {"bad"}}},
		{name: "uppercase", header: http.Header{protocol.ResponseNonceHeader: {strings.Repeat("AA", 32)}}},
		{name: "duplicate", header: http.Header{protocol.ResponseNonceHeader: {strings.Repeat("aa", 32), strings.Repeat("bb", 32)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header:     test.header,
				Body:       io.NopCloser(bytes.NewReader(frame([]byte("ciphertext")))),
			}
			transport := GuardEHBPResponses(&staticRoundTripper{response: response})
			request, err := http.NewRequest(http.MethodPost, "https://gateway.example", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.RoundTrip(request)
			if err == nil || !strings.Contains(err.Error(), "nonce") {
				t.Fatalf("RoundTrip() error = %v, want nonce error", err)
			}
		})
	}
}

func frame(payload []byte) []byte {
	result := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(result, uint32(len(payload)))
	copy(result[4:], payload)
	return result
}
