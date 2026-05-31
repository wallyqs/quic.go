# NATS over NQUIC — end-to-end example

A self-contained demo of the [NATS](https://nats.io) client protocol running on
top of **NQUIC**, the TLS-free QUIC profile (no certificates, no TLS handshake).
See [`../../NQUIC.md`](../../NQUIC.md) for the design.

## Run it

```
go run ./example/nats-nquic/
```

Expected output:

```
broker listening on 127.0.0.1:XXXXX (NQUIC: no TLS, no certs)
INFO {"server_name":"nquic-demo","proto":1}
subscriber: SUB nats.demo
INFO {"server_name":"nquic-demo","proto":1}
publisher: PUB nats.demo "hello over NQUIC 🚀"
✅ subscriber received on "nats.demo": hello over NQUIC 🚀
```

## What it does

The program starts three things in one process:

1. a miniature **NATS-style pub/sub broker** (an NQUIC server),
2. a **subscriber** that `SUB`s the subject `nats.demo`,
3. a **publisher** that `PUB`s a message to `nats.demo`.

The broker routes the published message to the subscriber, which prints it.

All three communicate over QUIC with **no TLS and no certificates** — the only
difference from a normal quic-go program is that the listener and dialer are
given `quic.NQUICConfig()`:

```go
ln, _   := serverTr.Listen(quic.NQUICConfig(), nil)        // server
conn, _ := clientTr.Dial(ctx, addr, quic.NQUICConfig(), nil) // client
```

## The protocol on the wire

A real (small) subset of the NATS client protocol is spoken over a single
bidirectional QUIC stream per connection:

```
server -> client : INFO {json}\r\n
client -> server : CONNECT {json}\r\n
client -> server : SUB <subject> <sid>\r\n
client -> server : PUB <subject> <#bytes>\r\n<payload>\r\n
server -> client : MSG <subject> <sid> <#bytes>\r\n<payload>\r\n
both ways        : PING\r\n / PONG\r\n
```

### A note on "who speaks first"

In NATS the **server** speaks first: it greets the client with `INFO`. A QUIC
stream accepted by the server only materializes once the *client* writes to it,
so to model "server speaks first" the **broker opens the stream** and the client
**accepts** it. That is the one place this maps NATS semantics onto QUIC stream
mechanics; everything else is a direct translation.

## Security model

This uses the **null** NQUIC profile: application data travels in **cleartext**
with no transport-layer authentication. It is meant for fully trusted networks
(e.g. a NATS supercluster inside a VPC or service mesh) where NATS itself
handles authentication (nkeys / JWT / tokens). Do **not** use it on untrusted
networks. See [`../../NQUIC.md`](../../NQUIC.md) for the roadmap toward an
encrypted, still certificate-free profile.
