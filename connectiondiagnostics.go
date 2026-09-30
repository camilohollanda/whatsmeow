// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types/events"
)

func (cli *Client) emitConnectionFailureDetails(node *waBinary.Node, onConnect bool) {
	attrs := node.AttrGetter()
	codeKey := "code"
	if onConnect {
		codeKey = "reason"
	}
	text := func(key string) string {
		value := attrs.OptionalString(key)
		if len(value) > 2048 {
			return value[:2048]
		}
		return value
	}
	conflict, _ := node.GetOptionalChildByTag("conflict")
	conflictType := conflict.AttrGetter().OptionalString("type")
	if len(conflictType) > 2048 {
		conflictType = conflictType[:2048]
	}
	cli.dispatchEvent(&events.ConnectionFailureDetails{
		OnConnect: onConnect, Code: text(codeKey), Message: text("message"), Conflict: conflictType,
		LogoutMessageHeader: text("logout_message_header"), LogoutMessageSubtext: text("logout_message_subtext"),
	})
}
