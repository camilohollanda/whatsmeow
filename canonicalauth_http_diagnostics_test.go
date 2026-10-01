// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type canonicalDiagnosticTransport func(*http.Request) (*http.Response, error)

func (transport canonicalDiagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

type canonicalDiagnosticReader struct{ err error }

func (reader canonicalDiagnosticReader) Read([]byte) (int, error) { return 0, reader.err }
func (canonicalDiagnosticReader) Close() error                    { return nil }

func canonicalDiagnosticResponse(path string) *http.Response {
	body := `{"data":{"xwa_canonical_user_valid":{"success":true}}}`
	if path == "/" {
		body = `["LSD",[],{"token":"synthetic-lsd"}]`
	}
	if path == "/auth/token/" {
		body = `{"payload":{"status":"success"}}`
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func canonicalDiagnosticFields(t *testing.T, job *canonicalAuthJob) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(job.diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-secret", "synthetic-lsd", "synthetic-nonce", "https://", "secret-cookie"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("diagnostic exposed sensitive input: %s", encoded)
		}
	}
	var fields map[string]any
	if err = json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestCanonicalHTTPDiagnosticClassifiesFailure(t *testing.T) {
	tests := []struct {
		name, path, stage, outcome, category string
		err                                  error
		read                                 bool
	}{
		{"dns", "/", "bootstrap", "transport_error", "dns", &net.DNSError{Err: "synthetic-secret", Name: "synthetic-secret.invalid"}, false},
		{"unknown authority", "/auth/token/", "exchange", "transport_error", "tls", x509.UnknownAuthorityError{}, false},
		{"hostname", "/", "bootstrap", "transport_error", "tls", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "synthetic-secret.invalid"}, false},
		{"certificate", "/", "bootstrap", "transport_error", "tls", &tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}}, false},
		{"tls record", "/", "bootstrap", "transport_error", "tls", tls.RecordHeaderError{Msg: "synthetic-secret"}, false},
		{"tls alert", "/", "bootstrap", "transport_error", "tls", tls.AlertError(40), false},
		{"timeout", "/graphql/", "validation", "timeout", "timeout", &net.DNSError{Err: "synthetic-secret", IsTimeout: true}, false},
		{"deadline", "/", "bootstrap", "timeout", "timeout", context.DeadlineExceeded, false},
		{"cancel", "/", "bootstrap", "cancelled", "cancelled", context.Canceled, false},
		{"transport", "/", "bootstrap", "transport_error", "transport", errors.New("synthetic-secret"), false},
		{"read", "/graphql/", "validation", "read_error", "read", errors.New("synthetic-secret"), true},
		{"read timeout", "/graphql/", "validation", "timeout", "timeout", context.DeadlineExceeded, true},
		{"read cancellation", "/graphql/", "validation", "cancelled", "cancelled", context.Canceled, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) {
				response := canonicalDiagnosticResponse(req.URL.Path)
				if req.URL.Path != tc.path {
					return response, nil
				}
				wrapped := fmt.Errorf("synthetic-secret: %w", tc.err)
				if tc.read {
					response.Body = canonicalDiagnosticReader{wrapped}
					return response, nil
				}
				return nil, wrapped
			})}
			job := &canonicalAuthJob{nonce: "synthetic-nonce"}
			stage, outcome, status := exchangeCanonicalNonce(context.Background(), client, job)
			wantStatus := 0
			if tc.read {
				wantStatus = 200
			}
			if stage != tc.stage || outcome != tc.outcome || status != wantStatus {
				t.Errorf("got %s/%s/%d, want %s/%s/%d", stage, outcome, status, tc.stage, tc.outcome, wantStatus)
			}
			if got := canonicalDiagnosticFields(t, job)["ErrorCategory"]; got != tc.category {
				t.Errorf("category = %v, want %s", got, tc.category)
			}
		})
	}
}

func TestCanonicalHTTPDiagnosticClientTimeout(t *testing.T) {
	ctx := context.Background()
	client := &http.Client{Timeout: 10 * time.Millisecond, Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	job := &canonicalAuthJob{}
	stage, outcome, status := exchangeCanonicalNonce(ctx, client, job)
	if ctx.Err() != nil || stage != "bootstrap" || outcome != "timeout" || status != 0 {
		t.Fatalf("incorrect client timeout: %s/%s/%d, parent context: %v", stage, outcome, status, ctx.Err())
	}
	if got := canonicalDiagnosticFields(t, job)["ErrorCategory"]; got != "timeout" {
		t.Errorf("category = %v", got)
	}
}

func TestCanonicalHTTPDiagnosticGraphQLCodes(t *testing.T) {
	tests := []struct {
		name, path, stage, body string
		status                  int
		outcome                 string
		codes                   []any
	}{
		{"allowlisted codes", "/graphql/", "validation", `{"errors":[{"code":190,"message":"synthetic-secret","extensions":{"code":1357004,"message":"synthetic-secret","user_id":123456789},"user_id":123456789},{"code":190},{"code":"42"},{"code":1.5},{"code":-1},{"code":0},{"code":2147483648},{"code":null},{"code":true},{"code":{"code":17}}],"code":99,"data":{"code":88}}`, 200, "rejected", []any{float64(190), float64(1357004)}},
		{"non success HTTP", "/graphql/", "validation", `for (;;);{"errors":[{"message":"synthetic-secret","extensions":{"code":1675030}}]}`, 429, "http_error", []any{float64(1675030)}},
		{"exchange HTTP", "/auth/token/", "exchange", `{"errors":[{"code":190}],"cookie":"secret-cookie"}`, 403, "http_error", []any{float64(190)}},
		{"bounded codes", "/graphql/", "validation", `{"errors":[{"code":1},{"code":2},{"code":3},{"code":4},{"code":5},{"code":6},{"code":7},{"code":8},{"code":9}]}`, 200, "rejected", []any{float64(1), float64(2), float64(3), float64(4), float64(5), float64(6), float64(7), float64(8)}},
		{"malformed body", "/graphql/", "validation", `{"errors":[{"code":190}]`, 200, "invalid_response", nil},
		{"no code", "/graphql/", "validation", `{"errors":[{"message":"synthetic-secret 190","extensions":{"details":{"code":99}}}]}`, 200, "rejected", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) {
				response := canonicalDiagnosticResponse(req.URL.Path)
				if req.URL.Path == tc.path {
					response.StatusCode = tc.status
					response.Body = io.NopCloser(strings.NewReader(tc.body))
				}
				return response, nil
			})}
			job := &canonicalAuthJob{}
			stage, outcome, status := exchangeCanonicalNonce(context.Background(), client, job)
			if stage != tc.stage || outcome != tc.outcome || status != tc.status {
				t.Errorf("wrong response metadata: %s/%s/%d", stage, outcome, status)
			}
			fields := canonicalDiagnosticFields(t, job)
			codes, _ := fields["ErrorCodes"].([]any)
			if !reflect.DeepEqual(codes, tc.codes) {
				t.Errorf("codes = %v, want %v", codes, tc.codes)
			}
		})
	}
}

func TestCanonicalHTTPDiagnosticPreservesStatusWhenErrorBodyFails(t *testing.T) {
	client := &http.Client{Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: canonicalDiagnosticReader{io.ErrUnexpectedEOF}}, nil
	})}
	job := &canonicalAuthJob{}
	stage, outcome, status := exchangeCanonicalNonce(context.Background(), client, job)
	if stage != "bootstrap" || outcome != "http_error" || status != 503 {
		t.Fatalf("lost HTTP failure: %s/%s/%d", stage, outcome, status)
	}
	fields := canonicalDiagnosticFields(t, job)
	if fields["ErrorCategory"] != "read" || fields["ErrorCodes"] != nil {
		t.Fatalf("wrong read failure diagnostic: %+v", fields)
	}
}

func TestCanonicalHTTPDiagnosticIsEmitted(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"errors":[{"code":190,"message":"synthetic-secret"}]}`)
	})
	deliverCanonical(cli, "failure-code", "synthetic-nonce", true)
	event := awaitCanonical(t, observed, "failure-code", "http_error")
	fields := canonicalDiagnosticFields(t, &canonicalAuthJob{diagnostic: event})
	if event.Stage != "bootstrap" || event.HTTPStatus != 403 || !reflect.DeepEqual(fields["ErrorCodes"], []any{float64(190)}) {
		t.Fatalf("wrong emitted failure: %+v", fields)
	}
}

func TestCanonicalHTTPDiagnosticCodesBelongToFailedStage(t *testing.T) {
	client := &http.Client{Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/graphql/" {
			return nil, errors.New("synthetic-secret")
		}
		response := canonicalDiagnosticResponse(req.URL.Path)
		if req.URL.Path == "/auth/token/" {
			response.Body = io.NopCloser(strings.NewReader(`{"payload":{"status":"success"},"errors":[{"code":190}]}`))
		}
		return response, nil
	})}
	job := &canonicalAuthJob{}
	stage, outcome, status := exchangeCanonicalNonce(context.Background(), client, job)
	fields := canonicalDiagnosticFields(t, job)
	if stage != "validation" || outcome != "transport_error" || status != 0 || fields["ErrorCodes"] != nil {
		t.Fatalf("diagnostic mixed stages: %s/%s/%d %+v", stage, outcome, status, fields)
	}
}
