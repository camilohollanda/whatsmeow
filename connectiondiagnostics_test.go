// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types/events"
)

type diagnosticDeviceContainer struct{ deleted bool }

func (s *diagnosticDeviceContainer) PutDevice(context.Context, *store.Device) error { return nil }
func (s *diagnosticDeviceContainer) DeleteDevice(context.Context, *store.Device) error {
	s.deleted = true
	return nil
}

func TestConnectionDiagnosticsPreserve403DetailsAndTerminalEvent(t *testing.T) {
	container := &diagnosticDeviceContainer{}
	cli := NewClient(&store.Device{Container: container}, nil)
	details := make(chan events.ConnectionFailureDetails, 1)
	logout := make(chan events.LoggedOut, 1)
	cli.AddEventHandler(func(evt any) {
		switch v := evt.(type) {
		case *events.ConnectionFailureDetails:
			details <- *v
		case *events.LoggedOut:
			logout <- *v
		}
	})
	cli.handleConnectFailure(context.Background(), &waBinary.Node{Tag: "failure", Attrs: waBinary.Attrs{
		"reason": "403", "message": "locked", "logout_message_header": "Account unavailable", "logout_message_subtext": "Open the primary application",
	}})
	select {
	case got := <-details:
		if !got.OnConnect || got.Code != "403" || got.Message != "locked" || got.LogoutMessageHeader != "Account unavailable" || got.LogoutMessageSubtext != "Open the primary application" {
			t.Fatalf("missing server details: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("403 details were not emitted")
	}
	select {
	case got := <-logout:
		if got.Reason != events.ConnectFailureMainDeviceGone {
			t.Fatal("terminal reason changed")
		}
	case <-time.After(time.Second):
		t.Fatal("terminal event was lost")
	}
	if !container.deleted {
		t.Fatal("diagnostics changed session deletion")
	}
}

func TestConnectionDiagnosticsObserveHandled503(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	details := make(chan events.ConnectionFailureDetails, 1)
	cli.AddEventHandler(func(evt any) {
		if v, ok := evt.(*events.ConnectionFailureDetails); ok {
			details <- *v
		}
	})
	cli.handleStreamError(context.Background(), &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}})
	select {
	case got := <-details:
		if got.OnConnect || got.Code != "503" {
			t.Fatalf("wrong stream detail: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("handled 503 is invisible")
	}
}
