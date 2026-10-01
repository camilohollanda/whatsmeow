// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

import (
	"time"

	"go.mau.fi/whatsmeow/types"
)

// CanonicalAuth describes a companion nonce observation or an experimental Web
// authentication attempt. It never includes nonces, user IDs, cookies or HTTP bodies.
type CanonicalAuth struct {
	ConnectionID  string
	MessageID     types.MessageID
	ForceRefresh  bool
	HasNonce      bool
	HasUserID     bool
	Stage         string
	Outcome       string
	HTTPStatus    int
	ErrorCategory string
	ErrorCodes    []int
	Duration      time.Duration
}
