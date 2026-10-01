// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

import "time"

// CanonicalAuthSummary describes authentication in one connection without credentials.
// Zero timestamps mean no such event has been observed in that connection.
type CanonicalAuthSummary struct {
	NonceReceived       bool
	LastForceRefresh    bool
	LastMessageID       string
	LastResultMessageID string
	LastStage           string
	LastOutcome         string
	LastValidatedAt     time.Time
	InFlight            bool
	Pending             bool
}

// ConnectionDiagnostic supplements lifecycle events with an opaque connection ID
// and the authentication state captured before disconnection cancels work.
type ConnectionDiagnostic struct {
	// AuthSummaryAvailable is false when the originating connection no longer has a retained summary.
	AuthSummaryAvailable bool
	ConnectionID         string
	Event                string
	Origin               string
	Expected             bool
	Auth                 CanonicalAuthSummary
}
