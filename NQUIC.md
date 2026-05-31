# NQUIC — a TLS-free QUIC profile for NATS (prototype)

> **Status:** working experimental prototype. A real QUIC connection is
> established over UDP with **no TLS and no certificates**, and data round-trips
> over a stream (`TestNQUICEndToEnd`). The "null" security model provides **no
> confidentiality** and **no authentication** at the transport layer — use only
> on fully trusted networks.

> 📊 **Illustrated design overview:** [`docs/nquic.html`](docs/nquic.html) — a
> self-contained HTML page with inline SVG diagrams of the stack, the
> `CryptoSetup` seam, the handshake sequence, the null AEAD, and the NATS demo.


## Motivation

[QUIC](https://datatracker.ietf.org/doc/html/rfc9000) mandates TLS 1.3
([RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001)): every connection
must run a TLS handshake and derive its packet-protection keys from the TLS key
schedule. That coupling brings X.509 certificates and a PKI into the picture.

NATS already has its own security model (nkeys / JWT / tokens) and operators
often run NATS inside a trusted boundary (a supercluster in a VPC or service
mesh). In those deployments the certificate machinery is pure operational
overhead, yet QUIC's transport features — stream multiplexing without
head-of-line blocking, flow control, loss recovery, and connection migration —
are still desirable.

**NQUIC** keeps the QUIC *transport* unchanged and replaces only the TLS-based
key establishment.

## What changes vs. standard QUIC

Nothing on the wire except the cryptographic protection:

| Aspect | Standard QUIC | NQUIC (null profile) |
| --- | --- | --- |
| Packet headers, frames, varints | RFC 9000 | unchanged |
| Streams, flow control, loss recovery, migration | RFC 9000/9002 | unchanged |
| Handshake | TLS 1.3 (certs, key exchange) | transport-parameter exchange only |
| Initial packets | connection-ID–derived AES-GCM | connection-ID–derived AES-GCM (unchanged) |
| 1-RTT (application data) | TLS-derived AEAD | **null AEAD (cleartext)** |
| Handshake encryption level | used | skipped (Initial → 1-RTT) |

The Initial encryption level already derives its keys deterministically from the
Destination Connection ID (RFC 9001 §5.2) and never needed TLS, so it is reused
as-is to protect the transport-parameter exchange.

## The seam

quic-go hides all TLS coupling behind a single interface,
`handshake.CryptoSetup` (`internal/handshake/interface.go`). The connection run
loop only ever talks to that interface; packet protection, HKDF, the CRYPTO-frame
plumbing and transport-parameter handling are all decoupled from TLS.

NQUIC is therefore implemented as an alternative `CryptoSetup`:

- `internal/handshake/nquic_aead.go` — null packet protection: identity AEAD
  (zero overhead, no auth tag) and no-op header protection. Packet-number
  decoding is preserved.
- `internal/handshake/nquic_crypto_setup.go` — `nquicSetup`, a TLS-free
  `CryptoSetup`. Its "handshake" is a one-round-trip exchange of QUIC transport
  parameters:

  ```
  client                                       server
  ----- Initial   [CRYPTO: client TPs] ------>
  <----- Initial  [CRYPTO: server TPs] -------
  ----- Handshake [CRYPTO: "finished"] ------>
  <----- 1-RTT    [HANDSHAKE_DONE, ...] ------
  ```

  The Handshake "finished" round trip mirrors TLS ordering so the server only
  completes after its Initial reply has been sent. There is no key exchange to
  perform; keys are the null AEAD (see "How it completes over the wire").

## Selecting NQUIC

To avoid adding new public surface, NQUIC is opted into via an ALPN sentinel in
an otherwise empty, **certificate-less** `tls.Config`. The helper
`quic.NQUICConfig()` builds it:

```go
ln, _   := quic.ListenAddr("127.0.0.1:4222", quic.NQUICConfig(), nil)
conn, _ := quic.DialAddr(ctx, "127.0.0.1:4222", quic.NQUICConfig(), nil)
```

When `tls.Config.NextProtos` contains `quic.NQUICNextProto` (`"nquic-null/v1"`),
the connection constructors in `connection.go` route to the NQUIC crypto setup
instead of the TLS one. No TLS handshake runs and no certificate is required;
the `tls.Config` is only a carrier for the toggle.

## Status & tests

- **Crypto core.** `internal/handshake/nquic_crypto_setup_test.go`
  (`TestNQUICHandshake`) drives a client and a server `nquicSetup` through the
  full event/message loop with **no TLS and no certificates**, exercises the
  Initial -> Handshake -> 1-RTT key progression, and round-trips application
  data through the null AEAD.

- **Socket end-to-end.** `nquic_test.go` (`TestNQUICEndToEnd`) stands up a real
  connection over a loopback UDP socket with `quic.NQUICConfig()` (no certs),
  opens a stream, and verifies an echo. **This passes.**

```
go test ./internal/handshake/ -run NQUIC   # passes
go test . -run TestNQUICEndToEnd           # passes
```

## How it completes over the wire

Three integration points beyond the `CryptoSetup` make the real handshake work:

1. **ClientHello scrambling disabled** (`crypto_stream.go`,
   `initialCryptoStream.disableScrambling`, wired in `connection.go`). The
   client otherwise runs `findSNIAndECH` over its outgoing Initial CRYPTO bytes,
   which are transport parameters in NQUIC, not a ClientHello.

2. **A Handshake-level "finished" round trip** (`nquic_crypto_setup.go`). The
   handshake is Initial(params) both ways, then a client Handshake "finished",
   then completion. This mirrors TLS ordering so the server only completes after
   its Initial reply has been sent (otherwise it would drop Initial keys before
   replying and the client would hang).

3. **16-byte dummy AEAD tag** (`nquic_aead.go`). QUIC header protection samples
   16 bytes starting 4 bytes into the packet-number field, so the receiver needs
   >= 4+16 bytes of protected payload. Real AEADs satisfy this via their auth
   tag; the null AEAD appends 16 zero bytes (no real authentication) so small
   packets (ACKs, the "finished") are not dropped as "packet too small".

A nil-guard was also added to the Initial packet-number space in
`internal/ackhandler/received_packet_handler.go`: NQUIC can confirm the
handshake (dropping the Initial space) while still processing an Initial packet,
a sequencing that standard QUIC never produces.

## Limitations & next steps

- **Null profile only.** No confidentiality/authentication at the transport
  layer; suitable for trusted networks where NATS handles auth. An obvious next
  step is an `ephemeral-ECDH, no-PKI` profile (X25519 in the Initial exchange ->
  HKDF -> real AEAD) that keeps confidentiality and forward secrecy while still
  dropping certificates — it slots into the same `CryptoSetup` seam.
- **ALPN-gated toggle.** A first-class `Config` option (e.g. `EnableNQUIC`) and
  relaxing the `tls.Config != nil` requirement in `transport.go` / `client.go`
  would make the opt-in cleaner; the ALPN approach keeps the prototype's blast
  radius small.
- **No 0-RTT, no session resumption, no key update** in the null profile.
