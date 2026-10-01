// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types/events"
)

func (cli *Client) beginConnectionTrace() string {
	state := &cli.canonicalAuth
	state.mu.Lock()
	pending := state.resetLocked()
	state.connectionID = uuid.NewString()
	state.summary = events.CanonicalAuthSummary{}
	state.traceEnded = false
	id := state.connectionID
	state.mu.Unlock()
	if pending != nil {
		go cli.canonicalAuthDiagnostic(pending, "decision", "cancelled", 0, 0)
	}
	return id
}

// ConnectionDiagnosticSnapshot returns a credential-free snapshot for correlating
// local lifecycle commands. It never acquires the network socket lock.
func (cli *Client) ConnectionDiagnosticSnapshot() events.ConnectionDiagnostic {
	state := &cli.canonicalAuth
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.snapshotLocked()
}

func (state *canonicalAuthState) snapshotLocked() events.ConnectionDiagnostic {
	summary := state.summary
	summary.InFlight = state.active != nil && !state.active.finished && state.active.diagnostic.ConnectionID == state.connectionID
	summary.Pending = state.pending != nil && state.pending.diagnostic.ConnectionID == state.connectionID
	return events.ConnectionDiagnostic{ConnectionID: state.connectionID, AuthSummaryAvailable: state.connectionID != "", Auth: summary}
}

func (cli *Client) connectionDiagnosticForContext(ctx context.Context) events.ConnectionDiagnostic {
	connection, ok := ctx.Value(canonicalGenerationKey{}).(canonicalConnection)
	if !ok {
		return events.ConnectionDiagnostic{}
	}
	state := &cli.canonicalAuth
	state.mu.Lock()
	defer state.mu.Unlock()
	if connection.id == "" || connection.id != state.connectionID {
		return events.ConnectionDiagnostic{ConnectionID: connection.id}
	}
	return state.snapshotLocked()
}

func (cli *Client) emitCanonicalDiagnostic(diagnostic events.CanonicalAuth) {
	state := &cli.canonicalAuth
	state.mu.Lock()
	if diagnostic.ConnectionID == state.connectionID {
		if diagnostic.Stage == "received" {
			state.summary.NonceReceived = state.summary.NonceReceived || diagnostic.HasNonce
			state.summary.LastForceRefresh = diagnostic.ForceRefresh
			state.summary.LastMessageID = diagnostic.MessageID
		}
		state.summary.LastStage, state.summary.LastOutcome = diagnostic.Stage, diagnostic.Outcome
		state.summary.LastResultMessageID = diagnostic.MessageID
		if diagnostic.Outcome == "validated" {
			state.summary.LastValidatedAt = time.Now()
		}
	}
	state.mu.Unlock()
	cli.dispatchEvent(&diagnostic)
}

func (cli *Client) connectionTrace(event, origin string, expected bool) events.ConnectionDiagnostic {
	diagnostic := cli.ConnectionDiagnosticSnapshot()
	diagnostic.Event, diagnostic.Origin, diagnostic.Expected = event, origin, expected
	return diagnostic
}

func (cli *Client) endConnectionTrace(event, origin string, expected bool) *events.ConnectionDiagnostic {
	state := &cli.canonicalAuth
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.traceEnded || state.connectionID == "" {
		return nil
	}
	diagnostic := state.snapshotLocked()
	diagnostic.Event, diagnostic.Origin, diagnostic.Expected = event, origin, expected
	state.traceEnded = true
	return &diagnostic
}
