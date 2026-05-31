# NQUIC — a TLS-free QUIC profile for NATS (prototype)

> **Status:** experimental prototype. The "null" security model implemented here
> provides **no confidentiality** and **no authentication** at the transport
> layer. Use only on fully trusted networks.

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
  client                                   server
  ----- Initial[CRYPTO: client TPs] ----->
  <---- Initial[CRYPTO: server TPs] -------
  <---- 1-RTT[HANDSHAKE_DONE, ...] --------
  ```

  Both sides install null 1-RTT keys as soon as parameters are exchanged and
  emit `EventHandshakeComplete`; there is no key exchange to perform.

A few small changes in the connection layer were needed to support a profile
that skips the Handshake encryption level (see "End-to-end wiring" below).

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

## End-to-end wiring

Beyond the `CryptoSetup` implementation, three small integration points were
required because NQUIC sends no ClientHello and skips the Handshake space:

1. **ClientHello scrambling** (`crypto_stream.go`,
   `initialCryptoStream.disableScrambling`). The client normally scrambles its
   ClientHello, which runs `findSNIAndECH` (`sni.go`) over the outgoing Initial
   CRYPTO bytes. NQUIC writes transport parameters there, not a ClientHello, so
   scrambling is disabled for NQUIC clients in `connection.go`.

2. **NQUIC routing** (`connection.go`). The client/server connection
   constructors select `handshake.NewNQUICCryptoSetup{Client,Server}` when
   `handshake.IsNQUIC(tlsConf)`.

3. **Handshake packet-number space** (`internal/ackhandler/received_packet_handler.go`).
   The `EncryptionHandshake` case is guarded with a `nil` check, mirroring the
   existing `initialPackets` guard. NQUIC transitions Initial → 1-RTT and never
   installs Handshake keys, so the Handshake space is dropped and the
   previously-"impossible" case becomes reachable.

## Tests

- `internal/handshake/nquic_crypto_setup_test.go` (`TestNQUICHandshake`) drives
  two `nquicSetup` instances through the full event/message loop and verifies
  the null 1-RTT AEAD round-trips application data.
- `nquic_test.go` (`TestNQUICEndToEnd`) opens a **real** QUIC connection over a
  loopback UDP socket with **no TLS config and no certificates**, opens a
  stream, and verifies an echo. **This passes.**

```
go test ./internal/handshake/ -run NQUIC   # passes
go test . -run TestNQUICEndToEnd           # passes
```

## Limitations & next steps

- **Null profile only.** No confidentiality/authentication at the transport
  layer; suitable for trusted networks where NATS handles auth. An obvious next
  step is an `ephemeral-ECDH, no-PKI` profile (X25519 in the Initial exchange →
  HKDF → real AEAD) that keeps confidentiality and forward secrecy while still
  dropping certificates — it slots into the same `CryptoSetup` seam.
- **ALPN-gated toggle.** A first-class `Config` option (e.g. `EnableNQUIC`) and
  relaxing the `tls.Config != nil` requirement in `transport.go` / `client.go`
  would make the opt-in cleaner; the ALPN approach was chosen here to keep the
  prototype's blast radius small.
- **No 0-RTT, no session resumption, no key update** in the null profile.
- **qlog / ConnectionState** are minimal for NQUIC connections (no TLS state to
  report).
