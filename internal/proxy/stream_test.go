package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

// scriptedBody replays chunks and then fails with a chosen error, which is how
// an upstream stream ends when the frame guard cannot finish a length prefix.
type scriptedBody struct {
	chunks []string
	err    error
	index  int
}

func (b *scriptedBody) Read(p []byte) (int, error) {
	if b.index < len(b.chunks) {
		count := copy(p, b.chunks[b.index])
		b.index++
		return count, nil
	}
	return 0, b.err
}

func (b *scriptedBody) Close() error { return nil }

func forwardScripted(t *testing.T, ctx context.Context, chunks []string, err error) (*httptest.ResponseRecorder, ledger.Request, any) {
	t.Helper()
	handler, e := NewHandler(&healthTestSender{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       &scriptedBody{chunks: chunks, err: err},
	}
	recorder := httptest.NewRecorder()
	record := ledger.Request{Outcome: ledger.OutcomeFailed}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler.forwardEventStream(ctx, recorder, response, &record)
	}()
	return recorder, record, recovered
}

// The regression: a client that closes the response body the moment it reads
// [DONE] cancels the request context, the upstream read is torn down
// mid-prefix, and the frame guard surfaces a non-EOF error AFTER a complete,
// fully authenticated response. That is a success, not a failure.
func TestStreamSucceedsWhenTheReadFailsAfterDone(t *testing.T) {
	recorder, record, recovered := forwardScripted(t,
		context.Background(),
		[]string{"data: {\"choices\":[]}\n\n", "data: [DONE]\n\n"},
		errors.New("truncated EHBP response frame prefix"))

	if recovered != nil {
		t.Fatalf("aborted a stream that had already delivered [DONE]: %v", recovered)
	}
	if record.Outcome != ledger.OutcomeEncrypted {
		t.Fatalf("outcome = %q, want %q", record.Outcome, ledger.OutcomeEncrypted)
	}
	if record.Failure != "" {
		t.Fatalf("failure = %q, want none", record.Failure)
	}
	if !strings.Contains(recorder.Body.String(), "data: [DONE]") {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

// Same, when the terminator arrives without its trailing newline.
func TestStreamSucceedsWhenDoneHasNoTrailingNewline(t *testing.T) {
	_, record, recovered := forwardScripted(t,
		context.Background(),
		[]string{"data: [DONE]"},
		errors.New("truncated EHBP response frame prefix"))

	if recovered != nil {
		t.Fatalf("aborted: %v", recovered)
	}
	if record.Outcome != ledger.OutcomeEncrypted {
		t.Fatalf("outcome = %q, want %q", record.Outcome, ledger.OutcomeEncrypted)
	}
}

func TestStreamStillSucceedsOnACleanEOFAfterDone(t *testing.T) {
	_, record, recovered := forwardScripted(t,
		context.Background(),
		[]string{"data: [DONE]\n\n"},
		io.EOF)

	if recovered != nil {
		t.Fatalf("aborted: %v", recovered)
	}
	if record.Outcome != ledger.OutcomeEncrypted {
		t.Fatalf("outcome = %q, want %q", record.Outcome, ledger.OutcomeEncrypted)
	}
}

// Fail-closed is the property that must survive the fix: a stream cut before
// the terminator is still aborted and still recorded as a failure.
func TestStreamFailsClosedWhenTheReadFailsBeforeDone(t *testing.T) {
	_, record, recovered := forwardScripted(t,
		context.Background(),
		[]string{"data: {\"choices\":[]}\n\n"},
		errors.New("truncated EHBP response frame prefix"))

	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
	}
	if record.Outcome == ledger.OutcomeEncrypted {
		t.Fatal("a stream cut before [DONE] was reported as encrypted")
	}
	if record.Failure != "authenticated event stream failed mid-response" {
		t.Fatalf("failure = %q", record.Failure)
	}
}

func TestStreamFailsClosedOnEOFBeforeDone(t *testing.T) {
	_, record, recovered := forwardScripted(t,
		context.Background(),
		[]string{"data: {\"choices\":[]}\n\n"},
		io.EOF)

	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
	}
	if record.Failure != "authenticated event stream ended without a terminating [DONE]" {
		t.Fatalf("failure = %q", record.Failure)
	}
}

// An incomplete stream is still a failure, but blaming the Gateway for the
// local client hanging up sends an operator looking in the wrong place.
func TestIncompleteStreamBlamesTheClientWhenItDisconnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, record, recovered := forwardScripted(t, ctx,
		[]string{"data: {\"choices\":[]}\n\n"},
		errors.New("truncated EHBP response frame prefix"))

	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
	}
	if record.Failure != "local client disconnected mid-stream" {
		t.Fatalf("failure = %q, want the client to be named", record.Failure)
	}
}
