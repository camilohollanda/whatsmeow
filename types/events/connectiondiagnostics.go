// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

// ConnectionFailureDetails preserves server diagnostics even for failure codes
// consumed internally. It supplements, and never replaces, lifecycle events.
// Text fields are bounded to 2048 bytes; raw stanzas are deliberately excluded.
type ConnectionFailureDetails struct {
	OnConnect            bool
	Code                 string
	Message              string
	Conflict             string
	LogoutMessageHeader  string
	LogoutMessageSubtext string
}
