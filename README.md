# whatsmeow
[![Go Reference](https://pkg.go.dev/badge/go.mau.fi/whatsmeow.svg)](https://pkg.go.dev/go.mau.fi/whatsmeow)

whatsmeow is a Go library for the WhatsApp web multidevice API.

## Discussion
Matrix room: [#whatsmeow:maunium.net](https://matrix.to/#/#whatsmeow:maunium.net)

For questions about the WhatsApp protocol (like how to send a specific type of
message), you can also use the [WhatsApp protocol Q&A] section on GitHub
discussions.

[WhatsApp protocol Q&A]: https://github.com/tulir/whatsmeow/discussions/categories/whatsapp-protocol-q-a

## Usage
The [godoc](https://pkg.go.dev/go.mau.fi/whatsmeow) includes docs for all methods and event types.
There's also a [simple example](https://pkg.go.dev/go.mau.fi/whatsmeow#example-package) at the top.

## Features
### Experimental canonical Web authentication

This fork observes `COMPANION_CANONICAL_USER_NONCE_FETCH` responses from the account's
primary device through `events.CanonicalAuth`. Observation is enabled by default and
does not perform HTTP requests. Before connecting, opt a client into nonce exchange:

```go
client.CanonicalAuth = &whatsmeow.CanonicalAuthConfig{}
```

The experiment obtains the Web bootstrap LSD token, posts the nonce to `/auth/token/`,
and validates the resulting private cookie session with the canonical-user GraphQL
query. `forceRefresh=true` renews an already validated session; an unforced nonce only
authenticates when needed. HTTP runs asynchronously with a 20-second total timeout,
one active attempt and at most one pending attempt, no automatic retries, no redirects,
and bounded response bodies. Disconnecting cancels work and discards cookies.
Neither HTTP failures nor validation failures reset the Signal session.

Diagnostics expose stages and outcomes, never nonces, canonical user IDs, cookies,
tokens or response bodies. `events.ConnectionFailureDetails` separately preserves
server-provided failure codes, conflict types and logout text alongside lifecycle events.

The protocol is experimental: the private bootstrap format, headers and GraphQL document
may change. The implementation follows the
[extracted Web nonce handler](https://github.com/vinikjkkj/wa-diff/blob/20a6e38b4e2397f5344258e3ed664800e58d270f/files/WAWebNonMessageDataRequestHandlerCanonicalEntNonce.js)
and [validation query](https://github.com/vinikjkkj/wa-diff/blob/20a6e38b4e2397f5344258e3ed664800e58d270f/files/WAWebCanonicalUserValidQuery_graphql.js),
with bootstrap/exchange adapted from
[Cobalt's Web bootstrap client](https://github.com/Auties00/Cobalt/blob/master/modules/lib/src/main/java/com/github/auties00/cobalt/graphql/WhatsAppWebGraphQlBootstrapClient.java).
Explicit opt-in replaces the official client's internal feature gates. This does not
implement WAM or establish that canonical authentication prevents device revocations.

### Core features
Most core features are already present:

* Sending messages to private chats and groups (both text and media)
* Receiving all messages
* Managing groups and receiving group change events
* Joining via invite messages, using and creating invite links
* Sending and receiving typing notifications
* Sending and receiving delivery and read receipts
* Reading and writing app state (contact list, chat pin/mute status, etc)
* Sending and handling retry receipts if message decryption fails
* Sending status messages (experimental, may not work for large contact lists)

Things that are not yet implemented:

* Sending broadcast list messages (this is not supported on WhatsApp web either)
* Calls
