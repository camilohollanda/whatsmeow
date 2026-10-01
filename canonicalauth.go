// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"sync"
	"time"

	waE2E "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"golang.org/x/net/publicsuffix"
)

// CanonicalAuthConfig enables experimental Web authentication from companion nonce
// responses. Configure it before connecting. Nil leaves observation enabled but
// makes no HTTP requests. Credentials are held only for this Client's lifetime.
type CanonicalAuthConfig struct {
	// ShouldAuthenticate optionally gates each nonce before HTTP work is queued.
	// It must be safe for concurrent calls and must not block. Nil allows all clients.
	ShouldAuthenticate func() bool
	// HTTPClient supplies the transport. Its cookies and redirect policy are not
	// shared: the experiment uses a private jar and never follows redirects.
	HTTPClient *http.Client
	// Timeout bounds the entire bootstrap, exchange and validation attempt.
	// A non-positive value uses 20 seconds.
	Timeout time.Duration
}

type canonicalAuthState struct {
	traceEnded    bool
	connectionID  string
	summary       events.CanonicalAuthSummary
	mu            sync.Mutex
	active        *canonicalAuthJob
	pending       *canonicalAuthJob
	http          *http.Client
	authenticated bool
	userID        string
	lastNonce     [32]byte
	generation    uint64
	cancel        context.CancelFunc
}

type canonicalAuthJob struct {
	finished   bool
	diagnostic events.CanonicalAuth
	nonce      string
	userID     string
	deviceID   uint16
	digest     [32]byte
	timeout    time.Duration
	generation uint64
}

type canonicalGenerationKey struct{}

type canonicalConnection struct {
	generation uint64
	id         string
}

func (cli *Client) canonicalAuthContext(ctx context.Context) context.Context {
	cli.canonicalAuth.mu.Lock()
	connection := canonicalConnection{cli.canonicalAuth.generation, cli.canonicalAuth.connectionID}
	cli.canonicalAuth.mu.Unlock()
	return context.WithValue(ctx, canonicalGenerationKey{}, connection)
}

func (cli *Client) handleCanonicalAuth(ctx context.Context, info *types.MessageInfo, response *waE2E.PeerDataOperationRequestResponseMessage) {
	if info.IsGroup {
		return
	}
	state := &cli.canonicalAuth
	connection, fromConnection := ctx.Value(canonicalGenerationKey{}).(canonicalConnection)
	generation := connection.generation
	var result *waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult_CompanionCanonicalUserNonceFetchResponse
	if len(response.GetPeerDataOperationResult()) > 0 {
		result = response.GetPeerDataOperationResult()[0].GetCompanionCanonicalUserNonceFetchRequestResponse()
	}
	job := &canonicalAuthJob{diagnostic: events.CanonicalAuth{
		ConnectionID: connection.id, MessageID: info.ID, ForceRefresh: result.GetForceRefresh(),
		HasNonce: result.GetNonce() != "", HasUserID: result.GetWaFbid() != "",
		Stage: "received", Outcome: "observed",
	}, nonce: result.GetNonce(), userID: result.GetWaFbid()}
	observed := job.diagnostic
	cli.emitCanonicalDiagnostic(observed)
	if cli.CanonicalAuth == nil {
		cli.canonicalAuthDiagnostic(job, "decision", "disabled", 0, 0)
		return
	}
	if cli.CanonicalAuth.ShouldAuthenticate != nil && !cli.CanonicalAuth.ShouldAuthenticate() {
		cli.canonicalAuthDiagnostic(job, "decision", "ineligible", 0, 0)
		return
	}
	if !fromConnection {
		cli.canonicalAuthDiagnostic(job, "decision", "no_connection", 0, 0)
		return
	}
	job.deviceID = cli.getOwnLID().Device
	if job.deviceID == 0 {
		job.deviceID = cli.getOwnID().Device
	}
	userID, err := strconv.ParseUint(job.userID, 10, 64)
	if err != nil || userID == 0 || job.nonce == "" || len(job.nonce) > 8192 || job.deviceID == 0 {
		cli.canonicalAuthDiagnostic(job, "decision", "invalid_payload", 0, 0)
		return
	}
	job.timeout = cli.CanonicalAuth.Timeout
	if job.timeout <= 0 {
		job.timeout = 20 * time.Second
	}
	job.digest = sha256.Sum256([]byte(job.userID + "\x00" + job.nonce + strconv.FormatBool(job.diagnostic.ForceRefresh)))
	state.mu.Lock()
	job.generation = generation
	if job.generation != state.generation {
		state.mu.Unlock()
		cli.canonicalAuthDiagnostic(job, "decision", "cancelled", 0, 0)
		return
	}
	if state.active != nil && state.active.generation == job.generation && state.active.digest == job.digest || state.pending != nil && state.pending.digest == job.digest || state.authenticated && state.lastNonce == job.digest {
		state.mu.Unlock()
		cli.canonicalAuthDiagnostic(job, "decision", "duplicate", 0, 0)
		return
	}
	if state.active != nil {
		if state.pending != nil && state.pending.diagnostic.ForceRefresh && !job.diagnostic.ForceRefresh {
			state.mu.Unlock()
			cli.canonicalAuthDiagnostic(job, "decision", "superseded", 0, 0)
			return
		}
		superseded := state.pending
		state.pending = job
		state.mu.Unlock()
		if superseded != nil {
			cli.canonicalAuthDiagnostic(superseded, "decision", "superseded", 0, 0)
		}
		return
	}
	state.active = job
	state.mu.Unlock()
	go cli.runCanonicalAuth(job)
}

func (cli *Client) canonicalAuthDiagnostic(job *canonicalAuthJob, stage, outcome string, status int, duration time.Duration) {
	diagnostic := job.diagnostic
	diagnostic.Stage, diagnostic.Outcome = stage, outcome
	diagnostic.HTTPStatus, diagnostic.Duration = status, duration
	cli.emitCanonicalDiagnostic(diagnostic)
}

func (cli *Client) runCanonicalAuth(job *canonicalAuthJob) {
	state := &cli.canonicalAuth
	for job != nil {
		started := time.Now()
		cli.canonicalAuthDiagnostic(job, "started", "in_progress", 0, 0)
		stage, outcome, status := cli.runCanonicalAuthJob(job)
		state.mu.Lock()
		job.finished = true
		state.mu.Unlock()
		cli.canonicalAuthDiagnostic(job, stage, outcome, status, time.Since(started))
		state.mu.Lock()
		job, state.pending = state.pending, nil
		state.active = job
		state.mu.Unlock()
	}
}

func (cli *Client) runCanonicalAuthJob(job *canonicalAuthJob) (string, string, int) {
	state := &cli.canonicalAuth
	state.mu.Lock()
	if job.generation != state.generation {
		state.mu.Unlock()
		return "decision", "cancelled", 0
	}
	if state.authenticated && state.userID == job.userID && !job.diagnostic.ForceRefresh {
		state.mu.Unlock()
		return "decision", "already_authenticated", 0
	}
	if state.http == nil {
		base := cli.CanonicalAuth.HTTPClient
		if base == nil {
			base = cli.preLoginHTTP
		}
		client := *base
		client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		state.http = &client
	}
	client := state.http
	ctx, cancel := context.WithTimeout(cli.BackgroundEventCtx, job.timeout)
	state.cancel = cancel
	state.mu.Unlock()
	stage, outcome, status := exchangeCanonicalNonce(ctx, client, job)
	state.mu.Lock()
	if state.generation != job.generation || ctx.Err() == context.Canceled {
		outcome = "cancelled"
	} else if ctx.Err() == context.DeadlineExceeded {
		outcome = "timeout"
	}
	if state.generation == job.generation {
		state.cancel = nil
		state.authenticated = outcome == "validated"
		if state.authenticated {
			state.userID, state.lastNonce = job.userID, job.digest
		}
	}
	state.mu.Unlock()
	cancel()
	return stage, outcome, status
}

func (cli *Client) cancelCanonicalAuth() {
	if pending := cli.resetCanonicalAuth(); pending != nil {
		cli.canonicalAuthDiagnostic(pending, "decision", "cancelled", 0, 0)
	}
}

func (cli *Client) resetCanonicalAuth() *canonicalAuthJob {
	state := &cli.canonicalAuth
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.resetLocked()
}

func (state *canonicalAuthState) resetLocked() *canonicalAuthJob {
	state.generation++
	if state.cancel != nil {
		state.cancel()
		state.cancel = nil
	}
	pending := state.pending
	state.pending, state.http = nil, nil
	state.authenticated, state.userID = false, ""
	return pending
}
