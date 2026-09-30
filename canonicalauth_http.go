// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const canonicalWebOrigin = "https://web.whatsapp.com"
const canonicalBodyLimit = 4 << 20
const canonicalValidationDocument = "25995999653397511"

var canonicalLSDPattern = regexp.MustCompile(`"LSD"\s*,\s*\[\s*\]\s*,\s*\{\s*"token"\s*:\s*("(?:[^"\\]|\\.)*")`)

func exchangeCanonicalNonce(ctx context.Context, client *http.Client, job *canonicalAuthJob) (stage, outcome string, status int) {
	body, status, outcome := canonicalRequest(ctx, client, "/", nil, "")
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
	body, status, outcome = canonicalRequest(ctx, client, "/auth/token/", form, lsd)
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
	body, status, outcome = canonicalRequest(ctx, client, "/graphql/", form, lsd)
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
		if ctx.Err() != nil {
			return nil, 0, "cancelled"
		}
		return nil, 0, "transport_error"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, "http_error"
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, canonicalBodyLimit+1))
	if err != nil {
		return nil, resp.StatusCode, "read_error"
	}
	if len(data) > canonicalBodyLimit {
		return nil, resp.StatusCode, "response_too_large"
	}
	return data, resp.StatusCode, ""
}
