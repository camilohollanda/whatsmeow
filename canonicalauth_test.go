// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	waE2E "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

type canonicalTestTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (rt canonicalTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	copy.URL.Scheme, copy.URL.Host = rt.target.Scheme, rt.target.Host
	return rt.transport.RoundTrip(copy)
}

func canonicalTestClient(t *testing.T, handler http.HandlerFunc) (*Client, <-chan events.CanonicalAuth) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	id := types.NewADJID("15550001111", 0, 7)
	cli := NewClient(&store.Device{ID: &id, LID: types.NewADJID("1234567", 0, 7)}, nil)
	cli.CanonicalAuth = &CanonicalAuthConfig{HTTPClient: &http.Client{Transport: canonicalTestTransport{target, http.DefaultTransport}}, Timeout: time.Second}
	observed := make(chan events.CanonicalAuth, 32)
	cli.AddEventHandler(func(evt any) {
		if diagnostic, ok := evt.(*events.CanonicalAuth); ok {
			observed <- *diagnostic
		}
	})
	return cli, observed
}

func deliverCanonical(cli *Client, id, nonce string, force bool) bool {
	return deliverCanonicalFrom(cli, &types.MessageInfo{
		ID: id, MessageSource: types.MessageSource{IsFromMe: true, Sender: types.NewJID("15550001111", types.DefaultUserServer)},
	}, nonce, force)
}

func deliverCanonicalFrom(cli *Client, info *types.MessageInfo, nonce string, force bool) bool {
	return deliverCanonicalContext(cli.canonicalAuthContext(context.Background()), cli, info, nonce, force)
}

func deliverCanonicalContext(ctx context.Context, cli *Client, info *types.MessageInfo, nonce string, force bool) bool {
	return cli.handleProtocolMessage(ctx, info, &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		PeerDataOperationRequestResponseMessage: &waE2E.PeerDataOperationRequestResponseMessage{
			PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_COMPANION_CANONICAL_USER_NONCE_FETCH.Enum(),
			PeerDataOperationResult: []*waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult{{
				CompanionCanonicalUserNonceFetchRequestResponse: &waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult_CompanionCanonicalUserNonceFetchResponse{
					Nonce: proto.String(nonce), WaFbid: proto.String("123456789"), ForceRefresh: proto.Bool(force),
				},
			}},
		},
	}})
}

func TestCanonicalAuthRejectsUntrustedMessageSources(t *testing.T) {
	for _, source := range []types.MessageSource{
		{IsFromMe: false, Sender: types.NewJID("15550002222", types.DefaultUserServer)},
		{IsFromMe: true, Sender: types.NewADJID("15550001111", 0, 4)},
		{IsFromMe: true, IsGroup: true, Sender: types.NewJID("15550001111", types.DefaultUserServer)},
	} {
		cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("untrusted source triggered HTTP") })
		deliverCanonicalFrom(cli, &types.MessageInfo{ID: "untrusted", MessageSource: source}, "synthetic-nonce", true)
		select {
		case evt := <-observed:
			t.Fatalf("untrusted source reached canonical handler: %+v", evt)
		default:
		}
	}
}

func TestCanonicalAuthAcceptsRepeatedNonceAfterDisconnect(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("pending job ran without worker") })
	cli.canonicalAuth.active = &canonicalAuthJob{digest: sha256.Sum256([]byte("123456789\x00synthetic-noncetrue"))}
	cli.Disconnect()
	deliverCanonical(cli, "reconnect", "synthetic-nonce", true)
	if cli.canonicalAuth.pending == nil || cli.canonicalAuth.pending.generation != cli.canonicalAuth.generation {
		t.Fatal("in-flight cancelled attempt swallowed the new session's nonce")
	}
	cli.cancelCanonicalAuth()
	awaitCanonical(t, observed, "reconnect", "cancelled")
}

func TestCanonicalAuthDisconnectDuringObservationRejectsOldWork(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("old message started HTTP after disconnect") })
	cli.AddEventHandler(func(evt any) {
		if diagnostic, ok := evt.(*events.CanonicalAuth); ok && diagnostic.Outcome == "observed" {
			cli.Disconnect()
		}
	})
	deliverCanonical(cli, "old", "synthetic-nonce", true)
	awaitCanonical(t, observed, "old", "cancelled")
}

func TestCanonicalAuthOldQueuedFrameCannotAuthenticateNewConnection(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("old connection's frame started HTTP") })
	cli.nodeHandlers["message"] = func(ctx context.Context, _ *waBinary.Node) {
		deliverCanonicalContext(ctx, cli, &types.MessageInfo{ID: "queued", MessageSource: types.MessageSource{
			IsFromMe: true, Sender: types.NewJID("15550001111", types.DefaultUserServer),
		}}, "synthetic-nonce", true)
	}
	frame, err := waBinary.Marshal(waBinary.Node{Tag: "message"})
	if err != nil {
		t.Fatal(err)
	}
	cli.handleFrame(cli.canonicalAuthContext(context.Background()), frame)
	if len(cli.handlerQueue) != 1 {
		t.Fatal("frame did not reach the handler queue")
	}
	cli.Disconnect()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		cli.handlerQueueLoop(cli.canonicalAuthContext(context.Background()), ctx)
		close(done)
	}()
	awaitCanonical(t, observed, "queued", "cancelled")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler queue did not stop")
	}
}

func TestCanonicalAuthReplayWithoutConnectionOnlyObserves(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("replay started authentication") })
	deliverCanonicalContext(context.Background(), cli, &types.MessageInfo{ID: "replay", MessageSource: types.MessageSource{
		IsFromMe: true, Sender: types.NewJID("15550001111", types.DefaultUserServer),
	}}, "synthetic-nonce", true)
	awaitCanonical(t, observed, "replay", "no_connection")
}

func TestCanonicalAuthRemoteDisconnectCancelsActiveAndPendingWork(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	cli.EnableAutoReconnect = false
	cli.CanonicalAuth.Timeout = time.Minute
	frame := socket.NewFrameSocket(waLog.Noop, nil)
	handshake := socket.NewNoiseHandshake()
	handshake.Start(socket.NoiseStartPattern, nil)
	ns, err := handshake.Finish(context.Background(), frame, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Stop(false, false) })
	cli.socket = ns
	deliverCanonical(cli, "active", "synthetic-nonce-1", true)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("HTTP did not start")
	}
	deliverCanonical(cli, "pending", "synthetic-nonce-2", true)
	cli.onDisconnect(context.Background(), ns, true)
	seen := map[string]bool{}
	deadline := time.After(time.Second)
	for len(seen) != 2 {
		select {
		case evt := <-observed:
			if evt.Outcome == "cancelled" {
				seen[evt.MessageID] = true
			}
		case <-deadline:
			t.Fatalf("missing cancellations: %v", seen)
		}
	}
	cli.canonicalAuth.mu.Lock()
	defer cli.canonicalAuth.mu.Unlock()
	if cli.canonicalAuth.authenticated || cli.canonicalAuth.http != nil || cli.canonicalAuth.pending != nil {
		t.Fatal("remote disconnect retained authentication state")
	}
}

func awaitCanonical(t *testing.T, observed <-chan events.CanonicalAuth, id, outcome string) events.CanonicalAuth {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case evt := <-observed:
			encoded, _ := json.Marshal(evt)
			for _, secret := range []string{"synthetic-nonce", "123456789", "synthetic-cookie", "synthetic-lsd"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("diagnostic leaked a secret: %s", encoded)
				}
			}
			if evt.MessageID == id && evt.Outcome == outcome {
				return evt
			}
		case <-deadline.C:
			t.Fatalf("missing diagnostic %s/%s", id, outcome)
		}
	}
}

func canonicalSuccessHandler(t *testing.T, posts *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script>["LSD",[],{"token":"synthetic-lsd"}]</script>`)
		case "/auth/token/":
			posts.Add(1)
			if r.Method != "POST" || r.URL.RawQuery != "" {
				t.Error("credentials must travel in a POST body")
			}
			_ = r.ParseForm()
			if !strings.HasPrefix(r.Form.Get("nonce"), "synthetic-nonce") || r.Form.Get("user_id") != "123456789" || r.Form.Get("device_id") != "7" || r.Form.Get("lsd") != "synthetic-lsd" {
				t.Error("incorrect exchange fields")
			}
			if r.Header.Get("Origin") != "https://web.whatsapp.com" || r.Header.Get("X-FB-LSD") != "synthetic-lsd" {
				t.Error("missing Web authentication headers")
			}
			http.SetCookie(w, &http.Cookie{Name: "wa_test", Value: "synthetic-cookie", Path: "/", Secure: true, HttpOnly: true})
			fmt.Fprint(w, `for (;;);{"payload":{"status":"success"}}`)
		case "/graphql/":
			_ = r.ParseForm()
			if r.Form.Get("doc_id") != "25995999653397511" || r.Form.Get("variables") != "{}" {
				t.Error("wrong canonical validation query")
			}
			if cookie, err := r.Cookie("wa_test"); err != nil || cookie.Value != "synthetic-cookie" {
				t.Error("exchange cookie did not reach validation")
			}
			fmt.Fprint(w, `{"data":{"xwa_canonical_user_valid":{"success":true}}}`)
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}
}

func TestCanonicalAuthObservesWithoutNetworkingByDefault(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("disabled experiment made a request") })
	cli.CanonicalAuth = nil
	if !deliverCanonical(cli, "disabled", "synthetic-nonce", true) {
		t.Fatal("diagnostics withheld message acknowledgement")
	}
	evt := awaitCanonical(t, observed, "disabled", "disabled")
	if !evt.ForceRefresh || !evt.HasNonce || !evt.HasUserID {
		t.Fatal("nonce metadata was lost")
	}
}

func TestCanonicalAuthRechecksEligibilityForEachNonce(t *testing.T) {
	var eligible atomic.Bool
	var posts atomic.Int32
	cli, observed := canonicalTestClient(t, canonicalSuccessHandler(t, &posts))
	cli.CanonicalAuth.ShouldAuthenticate = eligible.Load
	deliverCanonical(cli, "unknown-platform", "synthetic-nonce", false)
	awaitCanonical(t, observed, "unknown-platform", "ineligible")
	if posts.Load() != 0 {
		t.Fatal("ineligible client performed authentication")
	}
	eligible.Store(true)
	deliverCanonical(cli, "business-platform", "synthetic-nonce", false)
	awaitCanonical(t, observed, "business-platform", "validated")
	if posts.Load() != 1 {
		t.Fatalf("eligible client performed %d exchanges", posts.Load())
	}
	eligible.Store(false)
	deliverCanonical(cli, "personal-platform", "next-nonce", true)
	awaitCanonical(t, observed, "personal-platform", "ineligible")
	if posts.Load() != 1 {
		t.Fatal("ineligible forced refresh performed authentication")
	}
}

func TestCanonicalAuthRefreshesValidatedSessionOnlyWhenForced(t *testing.T) {
	var posts atomic.Int32
	cli, observed := canonicalTestClient(t, canonicalSuccessHandler(t, &posts))
	deliverCanonical(cli, "first", "synthetic-nonce-1", false)
	awaitCanonical(t, observed, "first", "validated")
	deliverCanonical(cli, "skip", "synthetic-nonce-2", false)
	awaitCanonical(t, observed, "skip", "already_authenticated")
	deliverCanonical(cli, "force", "synthetic-nonce-3", true)
	awaitCanonical(t, observed, "force", "validated")
	if posts.Load() != 2 {
		t.Fatalf("got %d exchanges, want initial plus forced refresh", posts.Load())
	}
}

func TestCanonicalAuthQueuesRefreshWithoutBlockingProtocolHandler(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var posts atomic.Int32
	success := canonicalSuccessHandler(t, &posts)
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token/" && posts.Load() == 0 {
			close(entered)
			<-release
		}
		success(w, r)
	})
	deliverCanonical(cli, "one", "synthetic-nonce-1", true)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("exchange did not start")
	}
	done := make(chan bool, 1)
	go func() { done <- deliverCanonical(cli, "two", "synthetic-nonce-2", true) }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("queued refresh withheld acknowledgement")
		}
	case <-time.After(time.Second):
		t.Error("HTTP blocked protocol handler")
	}
	close(release)
	awaitCanonical(t, observed, "one", "validated")
	awaitCanonical(t, observed, "two", "validated")
	if posts.Load() != 2 {
		t.Fatalf("queued forced refresh was lost: %d", posts.Load())
	}
}

func TestCanonicalAuthPendingForcedRefreshSurvivesUnforcedNonce(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var posts atomic.Int32
	success := canonicalSuccessHandler(t, &posts)
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token/" && posts.Load() == 0 {
			close(entered)
			<-release
		}
		success(w, r)
	})
	deliverCanonical(cli, "initial", "synthetic-nonce-1", false)
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("exchange did not start")
	}
	deliverCanonical(cli, "forced", "synthetic-nonce-2", true)
	deliverCanonical(cli, "unforced", "synthetic-nonce-3", false)
	close(release)
	awaitCanonical(t, observed, "forced", "validated")
	if posts.Load() != 2 {
		t.Fatalf("pending forced refresh was lost: %d", posts.Load())
	}
}

func TestCanonicalAuthTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	cli.CanonicalAuth.Timeout = 30 * time.Millisecond
	deliverCanonical(cli, "timeout", "synthetic-nonce", true)
	evt := awaitCanonical(t, observed, "timeout", "timeout")
	if evt.Stage != "bootstrap" || evt.Duration > time.Second {
		t.Fatalf("timeout did not bound bootstrap: %+v", evt)
	}
}

func TestCanonicalAuthFailureIsSanitizedAndDoesNotStopCapture(t *testing.T) {
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "synthetic-nonce synthetic-cookie")
	})
	if !deliverCanonical(cli, "failure", "synthetic-nonce", true) {
		t.Fatal("HTTP failure withheld acknowledgement")
	}
	evt := awaitCanonical(t, observed, "failure", "http_error")
	if evt.Stage != "bootstrap" || evt.HTTPStatus != 403 {
		t.Fatalf("wrong failure metadata: %+v", evt)
	}
}

func TestCanonicalAuthDisconnectCancelsInflightHTTP(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	cli.CanonicalAuth.Timeout = time.Minute
	deliverCanonical(cli, "cancel", "synthetic-nonce", true)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("HTTP did not start")
	}
	cli.Disconnect()
	awaitCanonical(t, observed, "cancel", "cancelled")
}

func TestCanonicalAuthDoesNotFollowRedirectWithCredentials(t *testing.T) {
	var requests atomic.Int32
	cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://untrusted.invalid/collect")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	deliverCanonical(cli, "redirect", "synthetic-nonce", true)
	evt := awaitCanonical(t, observed, "redirect", "http_error")
	if requests.Load() != 1 || evt.HTTPStatus != 307 {
		t.Fatal("redirect was followed")
	}
}

func TestCanonicalAuthRequiresValidationAfterExchange(t *testing.T) {
	for _, body := range []string{`{"data":{"xwa_canonical_user_valid":{"success":false}}}`, `{"errors":[{"message":"synthetic-nonce"}]}`, `{"data":{}}`} {
		t.Run(body, func(t *testing.T) {
			var posts atomic.Int32
			success := canonicalSuccessHandler(t, &posts)
			cli, observed := canonicalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/graphql/" {
					fmt.Fprint(w, body)
					return
				}
				success(w, r)
			})
			deliverCanonical(cli, "invalid", "synthetic-nonce-1", false)
			evt := awaitCanonical(t, observed, "invalid", "rejected")
			if evt.Stage != "validation" {
				t.Fatal("exchange was mistaken for validation")
			}
			deliverCanonical(cli, "retry", "synthetic-nonce-2", false)
			awaitCanonical(t, observed, "retry", "rejected")
			if posts.Load() != 2 {
				t.Fatal("failed validation left authentication cached")
			}
		})
	}
}
