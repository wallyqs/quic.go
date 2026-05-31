package handshake

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// This file implements the "null" packet protection used by the NQUIC variant.
//
// NQUIC is an experimental, NATS-specific profile of QUIC that removes the
// mandatory TLS 1.3 handshake. In the "null" security model selected for this
// prototype the AEAD performs no encryption and no authentication: the payload
// is copied verbatim and the "tag" is 16 zero bytes. Header protection is a
// no-op.
//
// This is deliberately NOT confidential. It is intended for fully trusted
// network segments (e.g. a NATS supercluster inside a VPC / service mesh)
// where the operator wants QUIC's stream multiplexing, flow control and
// connection migration without the operational cost of certificates, and
// where authentication/authorization is handled by NATS itself (nkeys/JWT).
//
// Why a 16-byte tag instead of zero overhead: QUIC header protection samples
// 16 bytes starting 4 bytes into the packet number field (RFC 9001 §5.4.2), so
// the receiver requires at least 4+16 bytes of protected payload. Real AEADs
// satisfy this for free via their authentication tag. A zero-overhead AEAD
// makes small packets (ACKs, the tiny handshake "finished") fall below that
// minimum and the peer drops them as "packet too small". Emitting a 16-byte
// (all-zero) dummy tag keeps NQUIC packets size-compatible with vanilla QUIC
// while still carrying the payload in cleartext.
//
// The wire format is otherwise unchanged: long/short headers, packet numbers
// and frames are encoded exactly as in RFC 9000.

// nullTagLen is the size of the dummy authentication tag appended to every
// NQUIC packet. It matches the 16-byte tag of the TLS 1.3 AEADs.
const nullTagLen = 16

var nullTag [nullTagLen]byte

// nullSealer is a pass-through sealer. It satisfies both LongHeaderSealer and
// ShortHeaderSealer: the application data is copied verbatim and followed by a
// 16-byte all-zero "tag". There is no real authentication, and header
// protection is disabled.
type nullSealer struct{}

var (
	_ LongHeaderSealer  = &nullSealer{}
	_ ShortHeaderSealer = &nullSealer{}
)

func (s *nullSealer) Seal(dst, src []byte, _ protocol.PacketNumber, _ []byte) []byte {
	dst = append(dst, src...)
	return append(dst, nullTag[:]...)
}

func (s *nullSealer) Overhead() int { return nullTagLen }

// EncryptHeader is a no-op: NQUIC null mode does not apply header protection.
func (s *nullSealer) EncryptHeader(_ []byte, _ *byte, _ []byte) {}

func (s *nullSealer) KeyPhase() protocol.KeyPhaseBit { return protocol.KeyPhaseZero }

// nullOpener is the shared base for the long- and short-header null openers.
// It tracks the highest received packet number so that truncated packet
// numbers on the wire can be expanded, exactly as a real AEAD opener would.
type nullOpener struct {
	highestRcvd protocol.PacketNumber
}

// DecryptHeader is a no-op: NQUIC null mode does not apply header protection.
func (o *nullOpener) DecryptHeader(_ []byte, _ *byte, _ []byte) {}

func (o *nullOpener) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvd, wirePN)
}

func (o *nullOpener) open(dst, src []byte, pn protocol.PacketNumber) ([]byte, error) {
	if len(src) < nullTagLen {
		return nil, ErrDecryptionFailed
	}
	// Strip the dummy tag. Its contents are not checked: NQUIC null mode
	// provides no authentication.
	payload := src[:len(src)-nullTagLen]
	if pn > o.highestRcvd {
		o.highestRcvd = pn
	}
	return append(dst, payload...), nil
}

// nullLongHeaderOpener opens long-header (Initial/Handshake) packets.
type nullLongHeaderOpener struct {
	nullOpener
}

var _ LongHeaderOpener = &nullLongHeaderOpener{}

func (o *nullLongHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, _ []byte) ([]byte, error) {
	return o.open(dst, src, pn)
}

// nullShortHeaderOpener opens short-header (1-RTT) packets.
type nullShortHeaderOpener struct {
	nullOpener
}

var _ ShortHeaderOpener = &nullShortHeaderOpener{}

func (o *nullShortHeaderOpener) Open(dst, src []byte, _ monotime.Time, pn protocol.PacketNumber, _ protocol.KeyPhaseBit, _ []byte) ([]byte, error) {
	return o.open(dst, src, pn)
}
