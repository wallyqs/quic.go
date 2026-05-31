package quic

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/handshake"
)

// NQUIC is an experimental, NATS-oriented profile of QUIC that removes the
// mandatory TLS 1.3 handshake.
//
// Standard QUIC (RFC 9001) couples the transport to TLS: every connection must
// run a TLS 1.3 handshake and derive its packet-protection keys from the TLS
// key schedule. NQUIC keeps the QUIC transport unchanged — long/short headers,
// streams, flow control, loss recovery and connection migration all behave
// exactly as in RFC 9000 — but swaps the TLS-based key establishment for a
// minimal exchange that only carries QUIC transport parameters.
//
// This prototype implements the "null" security model: application data
// (1-RTT) travels in cleartext with no authentication tag. It is therefore NOT
// confidential and MUST only be used on trusted network segments (for example
// inside a NATS supercluster running in a private VPC or service mesh), where
// the operator wants QUIC's multiplexing without the operational cost of
// certificates, and where authentication is handled by NATS itself (nkeys/JWT).
//
// NQUIC is selected via the ALPN of an otherwise empty, certificate-less
// tls.Config; see NQUICConfig.
const NQUICNextProto = handshake.NQUICNextProto

// NQUICConfig returns a tls.Config that selects the TLS-free NQUIC profile.
//
// It carries no certificate and triggers no TLS handshake — the tls.Config is
// used purely as the carrier for the NQUIC opt-in ALPN. Pass it to ListenAddr,
// Listen, DialAddr or Dial in place of a real TLS configuration:
//
//	ln, _ := quic.ListenAddr("127.0.0.1:4222", quic.NQUICConfig(), nil)
//	conn, _ := quic.DialAddr(ctx, "127.0.0.1:4222", quic.NQUICConfig(), nil)
//
// Additional ALPNs may be appended to the returned config's NextProtos.
func NQUICConfig() *tls.Config {
	return &tls.Config{NextProtos: []string{NQUICNextProto}}
}
