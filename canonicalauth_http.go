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
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"go.mau.fi/whatsmeow/types/events"
)

const canonicalWebOrigin = "https://web.whatsapp.com"
const canonicalBodyLimit = 4 << 20
const canonicalValidationDocument = "25995999653397511"

var canonicalLSDPattern = regexp.MustCompile(`"LSD"\s*,\s*\[\s*\]\s*,\s*\{\s*"token"\s*:\s*("(?:[^"\\]|\\.)*")`)

func exchangeCanonicalNonce(ctx context.Context, client *http.Client, job *canonicalAuthJob) (stage, outcome string, status int) {
	body, status, outcome := canonicalRequestDiagnostic(ctx, client, "/", nil, "", &job.diagnostic)
	if outcome != "" {
		return "bootstrap", outcome, status
	}
	match := canonicalLSDPattern.FindSubmatch(body)
	var lsd string
	if len(match) != 2 || json.Unmarshal(match[1], &lsd) != nil || lsd == "" {
		return "bootstrap", "missing_lsd", status
	}
	form := canonicalForm(lsd)
	form.Set("nonce", job.nonce)
	form.Set("access_token", "")
	form.Set("user_id", job.userID)
	form.Set("device_id", strconv.Itoa(int(job.deviceID)))
	body, status, outcome = canonicalRequestDiagnostic(ctx, client, "/auth/token/", form, lsd, &job.diagnostic)
	if outcome != "" {
		return "exchange", outcome, status
	}
	var exchanged struct {
		Payload struct {
			Status string `json:"status"`
		} `json:"payload"`
	}
	if json.Unmarshal(canonicalJSON(body), &exchanged) != nil {
		return "exchange", "invalid_response", status
	}
	if exchanged.Payload.Status != "success" {
		return "exchange", "rejected", status
	}
	form = canonicalForm(lsd)
	form.Set("doc_id", canonicalValidationDocument)
	form.Set("variables", "{}")
	form.Set("locale", "en_US")
	body, status, outcome = canonicalRequestDiagnostic(ctx, client, "/graphql/", form, lsd, &job.diagnostic)
	if outcome != "" {
		return "validation", outcome, status
	}
	var validation struct {
		Errors []json.RawMessage `json:"errors"`
		Data   struct {
			User struct {
				Success *bool `json:"success"`
			} `json:"xwa_canonical_user_valid"`
		} `json:"data"`
	}
	if json.Unmarshal(canonicalJSON(body), &validation) != nil {
		return "validation", "invalid_response", status
	}
	if len(validation.Errors) > 0 || validation.Data.User.Success == nil || !*validation.Data.User.Success {
		return "validation", "rejected", status
	}
	return "validation", "validated", status
}

func canonicalForm(lsd string) url.Values {
	checksum := 0
	for _, r := range lsd {
		checksum += int(r)
	}
	return url.Values{"__a": {"1"}, "__user": {"0"}, "lsd": {lsd}, "jazoest": {"2" + strconv.Itoa(checksum)}}
}

func canonicalJSON(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	text = strings.TrimPrefix(text, "for (;;);")
	text = strings.TrimPrefix(text, "for(;;);")
	return []byte(text)
}

func canonicalRequest(ctx context.Context, client *http.Client, path string, form url.Values, lsd string) ([]byte, int, string) {
	return canonicalRequestDiagnostic(ctx, client, path, form, lsd, nil)
}

func canonicalRequestDiagnostic(ctx context.Context, client *http.Client, path string, form url.Values, lsd string, diagnostic *events.CanonicalAuth) ([]byte, int, string) {
	if diagnostic != nil {
		diagnostic.ErrorCategory, diagnostic.ErrorCodes = "", nil
	}
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, canonicalWebOrigin+path, body)
	if err != nil {
		return nil, 0, "invalid_request"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if form == nil {
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", canonicalWebOrigin)
		req.Header.Set("Referer", canonicalWebOrigin+"/")
		req.Header.Set("X-FB-LSD", lsd)
		req.Header.Set("X-ASBD-ID", "359341")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, canonicalHTTPFailure(ctx, err, "transport", diagnostic)
	}
	defer resp.Body.Close()
	httpFailure := resp.StatusCode < 200 || resp.StatusCode >= 300
	data, err := io.ReadAll(io.LimitReader(resp.Body, canonicalBodyLimit+1))
	if err != nil {
		outcome := canonicalHTTPFailure(ctx, err, "read", diagnostic)
		if httpFailure {
			outcome = "http_error"
		}
		return nil, resp.StatusCode, outcome
	}
	if len(data) > canonicalBodyLimit {
		if httpFailure {
			return nil, resp.StatusCode, "http_error"
		}
		return nil, resp.StatusCode, "response_too_large"
	}
	if diagnostic != nil {
		diagnostic.ErrorCodes = canonicalGraphQLErrorCodes(data)
	}
	if httpFailure {
		return nil, resp.StatusCode, "http_error"
	}
	return data, resp.StatusCode, ""
}

func canonicalHTTPFailure(ctx context.Context, err error, fallback string, diagnostic *events.CanonicalAuth) string {
	category := canonicalHTTPErrorCategory(ctx, err, fallback)
	if diagnostic != nil {
		diagnostic.ErrorCategory = category
	}
	if category == "timeout" || category == "cancelled" {
		return category
	}
	return fallback + "_error"
}

func canonicalHTTPErrorCategory(ctx context.Context, err error, fallback string) string {
	switch {
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	// A URL error's Timeout method may not follow wrapped transport errors.
	for current := err; current != nil; current = errors.Unwrap(current) {
		if networkError, ok := current.(net.Error); ok && networkError.Timeout() {
			return "timeout"
		}
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "dns"
	}
	var verificationError *tls.CertificateVerificationError
	var authorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateError x509.CertificateInvalidError
	var rootsError x509.SystemRootsError
	var recordError tls.RecordHeaderError
	var alertError tls.AlertError
	if errors.As(err, &verificationError) || errors.As(err, &authorityError) ||
		errors.As(err, &hostnameError) || errors.As(err, &certificateError) ||
		errors.As(err, &rootsError) || errors.As(err, &recordError) || errors.As(err, &alertError) {
		return "tls"
	}
	return fallback
}

func canonicalGraphQLErrorCodes(body []byte) []int {
	var response struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(canonicalJSON(body), &response) != nil {
		return nil
	}
	var codes []int
	for _, rawError := range response.Errors {
		var item struct {
			Code       json.RawMessage `json:"code"`
			Extensions struct {
				Code json.RawMessage `json:"code"`
			} `json:"extensions"`
		}
		if json.Unmarshal(rawError, &item) != nil {
			continue
		}
		for _, rawCode := range []json.RawMessage{item.Code, item.Extensions.Code} {
			// Only positive integer codes fit the diagnostic; arbitrary error fields may contain credentials.
			var code int32
			if json.Unmarshal(rawCode, &code) != nil || code <= 0 {
				continue
			}
			duplicate := false
			for _, existing := range codes {
				if existing == int(code) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				codes = append(codes, int(code))
			}
			if len(codes) == 8 {
				return codes
			}
		}
	}
	return codes
}
