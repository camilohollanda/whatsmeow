// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types/events"
)

func TestConnectionTraceKeepsAuthSummaryAndSeparatesReconnects(t *testing.T) {
	var posts atomic.Int32
	cli, observed := canonicalTestClient(t, canonicalSuccessHandler(t, &posts))
	first := cli.beginConnectionTrace()
	if first == "" {
		t.Fatal("missing connection identity")
	}
	deliverCanonical(cli, "auth-1", "synthetic-nonce", true)
	evt := awaitCanonical(t, observed, "auth-1", "validated")
	if evt.ConnectionID != first {
		t.Fatal("authentication lost connection identity")
	}
	details := make(chan events.ConnectionFailureDetails, 1)
	cli.AddEventHandler(func(evt any) {
		if v, ok := evt.(*events.ConnectionFailureDetails); ok {
			details <- *v
		}
	})
	cli.handleStreamError(cli.canonicalAuthContext(context.Background()), &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}})
	got := <-details
	if got.ConnectionID != first || !got.Auth.NonceReceived || !got.Auth.LastForceRefresh || got.Auth.LastOutcome != "validated" || got.Auth.LastValidatedAt.IsZero() {
		t.Fatalf("lost auth summary: %+v", got)
	}
	cli.Disconnect()
	second := cli.beginConnectionTrace()
	if first == second {
		t.Fatal("reconnect reused connection ID")
	}
	snapshot := cli.ConnectionDiagnosticSnapshot()
	if snapshot.Auth.NonceReceived || !snapshot.Auth.LastValidatedAt.IsZero() {
		t.Fatalf("reconnect inherited old authentication: %+v", snapshot)
	}
	cli.emitCanonicalDiagnostic(events.CanonicalAuth{ConnectionID: first, MessageID: "old", Stage: "validation", Outcome: "validated"})
	if cli.ConnectionDiagnosticSnapshot().Auth.LastOutcome != "" {
		t.Fatal("late result contaminated new connection")
	}
}

func TestConnectionTraceReportsNoNonceAndInFlightAtDisconnect(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-release })
	defer close(release)
	id := cli.beginConnectionTrace()
	if cli.ConnectionDiagnosticSnapshot().Auth.NonceReceived {
		t.Fatal("invented nonce")
	}
	deliverCanonical(cli, "in-flight", "synthetic-nonce", false)
	<-entered
	disconnected := make(chan events.ConnectionDiagnostic, 2)
	cli.AddEventHandler(func(evt any) {
		if v, ok := evt.(*events.ConnectionDiagnostic); ok && v.Event == "disconnected" {
			disconnected <- *v
		}
	})
	cli.Disconnect()
	select {
	case got := <-disconnected:
		if got.ConnectionID != id || got.Origin != "local" || !got.Auth.InFlight || !got.Auth.NonceReceived {
			t.Fatalf("lost pre-cancellation context: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("missing local disconnection diagnostic")
	}
	awaitCanonical(t, observed, "in-flight", "cancelled")
}

func TestConnectionTraceFailureUsesOriginatingConnection(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	first := cli.beginConnectionTrace()
	oldContext := cli.canonicalAuthContext(context.Background())
	second := cli.beginConnectionTrace()
	cli.emitCanonicalDiagnostic(events.CanonicalAuth{ConnectionID: second, MessageID: "new-result", Stage: "validation", Outcome: "validated"})
	details := make(chan events.ConnectionFailureDetails, 2)
	cli.AddEventHandler(func(event any) {
		if value, ok := event.(*events.ConnectionFailureDetails); ok {
			details <- *value
		}
	})
	cli.handleStreamError(oldContext, &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}})
	got := <-details
	if got.ConnectionID != first || got.Auth.LastOutcome != "" || traceSummaryAvailable(t, got) {
		t.Fatalf("stale failure inherited another connection: %+v", got)
	}
	cli.handleStreamError(cli.canonicalAuthContext(context.Background()), &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}})
	got = <-details
	if got.ConnectionID != second || got.Auth.LastOutcome != "validated" || !traceSummaryAvailable(t, got) {
		t.Fatalf("current failure lost its summary: %+v", got)
	}
}

func TestConnectionTraceWithoutContextDoesNotInventConnection(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	id := cli.beginConnectionTrace()
	cli.emitCanonicalDiagnostic(events.CanonicalAuth{ConnectionID: id, Stage: "validation", Outcome: "validated"})
	details := make(chan events.ConnectionFailureDetails, 1)
	cli.AddEventHandler(func(event any) {
		if value, ok := event.(*events.ConnectionFailureDetails); ok {
			details <- *value
		}
	})
	cli.handleConnectFailure(context.Background(), &waBinary.Node{Tag: "failure", Attrs: waBinary.Attrs{"reason": "503"}})
	got := <-details
	if got.ConnectionID != "" || got.Auth.LastOutcome != "" || traceSummaryAvailable(t, got) {
		t.Fatalf("missing context was attributed to active connection: %+v", got)
	}
}

func traceSummaryAvailable(t *testing.T, event any) bool {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic struct{ AuthSummaryAvailable bool }
	if err = json.Unmarshal(data, &diagnostic); err != nil {
		t.Fatal(err)
	}
	return diagnostic.AuthSummaryAvailable
}

func TestConnectionTraceSuccessUsesOriginatingConnection(t *testing.T) {
	backing := &store.NoopStore{Error: errors.New("test store unavailable")}
	cli := NewClient(&store.Device{PreKeys: backing, PrivacyTokens: backing}, nil)
	cli.paired.Store(true)
	first := cli.beginConnectionTrace()
	oldContext := cli.canonicalAuthContext(context.Background())
	second := cli.beginConnectionTrace()
	cli.emitCanonicalDiagnostic(events.CanonicalAuth{ConnectionID: second, Stage: "validation", Outcome: "validated"})
	diagnostics := make(chan events.ConnectionDiagnostic, 1)
	completed := make(chan struct{}, 1)
	cli.AddEventHandler(func(event any) {
		switch value := event.(type) {
		case *events.ConnectionDiagnostic:
			diagnostics <- *value
		case *events.Connected:
			completed <- struct{}{}
		}
	})
	cli.handleConnectSuccess(oldContext, &waBinary.Node{Tag: "success", Attrs: waBinary.Attrs{"t": "1"}})
	got := <-diagnostics
	if got.ConnectionID != first || got.Event != "connected" || got.Auth.LastOutcome != "" || traceSummaryAvailable(t, got) {
		t.Errorf("stale success inherited another connection: %+v", got)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("connect handler did not complete")
	}
}

func TestConnectionTraceCancelledConnectContext(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	cli.InitialAutoReconnect = false
	cli.SetPreLoginHTTPClient(&http.Client{Transport: canonicalDiagnosticTransport(func(req *http.Request) (*http.Response, error) { return nil, req.Context().Err() })})
	diagnostics := make(chan events.ConnectionDiagnostic, 8)
	cli.AddEventHandler(func(event any) {
		if value, ok := event.(*events.ConnectionDiagnostic); ok {
			diagnostics <- *value
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	previous := ""
	for attempt := 0; attempt < 2; attempt++ {
		if err := cli.ConnectContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled connect returned %v", err)
		}
		seen := map[string]events.ConnectionDiagnostic{}
		for len(seen) < 2 {
			select {
			case event := <-diagnostics:
				seen[event.Event] = event
			case <-time.After(time.Second):
				t.Fatal("missing connect lifecycle diagnostics")
			}
		}
		connecting, failed := seen["connecting"], seen["connect_failed"]
		if connecting.ConnectionID == "" || connecting.ConnectionID == previous || failed.ConnectionID != connecting.ConnectionID || !traceSummaryAvailable(t, failed) || failed.Auth.NonceReceived {
			t.Fatalf("incorrect cancelled lifecycle: %+v", seen)
		}
		previous = connecting.ConnectionID
		cli.Disconnect()
		select {
		case event := <-diagnostics:
			t.Fatalf("failed attempt emitted another terminal event: %+v", event)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestConnectionTraceDuplicateDisconnectEmitsOnce(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	id := cli.beginConnectionTrace()
	diagnostics := make(chan events.ConnectionDiagnostic, 2)
	cli.AddEventHandler(func(event any) {
		if value, ok := event.(*events.ConnectionDiagnostic); ok {
			diagnostics <- *value
		}
	})
	cli.Disconnect()
	cli.Disconnect()
	var first events.ConnectionDiagnostic
	select {
	case first = <-diagnostics:
	case <-time.After(time.Second):
		t.Fatal("missing disconnect diagnostic")
	}
	if first.ConnectionID != id || first.Event != "disconnected" || !first.Expected {
		t.Fatalf("incorrect local disconnect: %+v", first)
	}
	select {
	case event := <-diagnostics:
		t.Fatalf("duplicate terminal event: %+v", event)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestConnectionTraceDisconnectDoesNotReenterEventHandler(t *testing.T) {
	cli := NewClient(&store.Device{}, nil)
	id := cli.beginConnectionTrace()
	var handlerLock sync.Mutex
	returned := make(chan struct{})
	disconnected := make(chan events.ConnectionDiagnostic, 1)
	cli.AddEventHandler(func(event any) {
		handlerLock.Lock()
		defer handlerLock.Unlock()
		switch value := event.(type) {
		case *events.Connected:
			cli.Disconnect()
			close(returned)
		case *events.ConnectionDiagnostic:
			disconnected <- *value
		}
	})
	go cli.dispatchEvent(&events.Connected{})
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Disconnect reentered its calling event handler")
	}
	select {
	case event := <-disconnected:
		if event.ConnectionID != id || event.Event != "disconnected" || !event.Expected {
			t.Fatalf("incorrect disconnect diagnostic: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("asynchronous disconnect diagnostic was lost")
	}
}
