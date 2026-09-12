// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"testing"

	"go.mau.fi/whatsmeow/types"
)

// A retry receipt for a peer message must be marked `category="peer"`, or the sender acks the
// receipt and never redelivers. The marker arrives on the wire as the message's `category`
// attribute — `<message category="peer" type="text">` — which the parser stores in
// MessageInfo.Category. The predicate used to read MessageInfo.Type instead, comparing it to
// "peer_msg", a string nothing in this repository ever assigns.
func TestShouldMarkPeerRetry(t *testing.T) {
	peer := func(category, msgType string, fromMe bool) *types.MessageInfo {
		info := &types.MessageInfo{Category: category, Type: msgType}
		info.IsFromMe = fromMe
		return info
	}

	tests := []struct {
		name string
		info *types.MessageInfo
		want bool
	}{
		{"category peer from own device", peer("peer", "text", true), true},
		{"legacy peer_msg type", peer("", "peer_msg", true), true},
		{"peer category but not from me", peer("peer", "text", false), false},
		{"ordinary message from own device", peer("", "text", true), false},
		{"ordinary message from someone else", peer("", "text", false), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldMarkPeerRetry(tt.info); got != tt.want {
				t.Errorf("shouldMarkPeerRetry() = %v, want %v", got, tt.want)
			}
		})
	}
}
