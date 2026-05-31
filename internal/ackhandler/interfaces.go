package ackhandler

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket, isPathProbePacket bool)
	// SentPacketForPath records a 1-RTT packet sent on a specific path (multipath).
	// For PathID InitialPathID it is equivalent to SentPacket at the 1-RTT level.
	SentPacketForPath(id PathID, t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket bool)
	// ReceivedAck processes an ACK frame.
	// It does not store a copy of the frame.
	ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
	// ReceivedAckForPath processes a 1-RTT ACK frame received for a specific path
	// (multipath). For PathID InitialPathID it is equivalent to ReceivedAck.
	ReceivedAckForPath(f *wire.AckFrame, id PathID, rcvTime monotime.Time) (bool /* packet acked */, error)
	ReceivedPacket(protocol.EncryptionLevel, monotime.Time)
	ReceivedBytes(_ protocol.ByteCount, rcvTime monotime.Time)
	DropPackets(_ protocol.EncryptionLevel, rcvTime monotime.Time)
	ResetForRetry(rcvTime monotime.Time)

	// The SendMode determines if and what kind of packets can be sent.
	SendMode(now monotime.Time) SendMode
	// SendModeForPath determines the send mode for a specific path (multipath).
	// For PathID InitialPathID it is equivalent to SendMode.
	SendModeForPath(id PathID, now monotime.Time) SendMode
	// TimeUntilSend is the time when the next packet should be sent.
	// It is used for pacing packets.
	TimeUntilSend() monotime.Time
	SetMaxDatagramSize(count protocol.ByteCount)

	// only to be called once the handshake is complete
	QueueProbePacket(protocol.EncryptionLevel) bool /* was a packet queued */

	ECNMode(isShortHeaderPacket bool) protocol.ECN // isShortHeaderPacket should only be true for non-coalesced 1-RTT packets
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber

	// PeekPacketNumberForPath and PopPacketNumberForPath operate on a specific
	// path's application-data (1-RTT) packet number space, for multipath QUIC.
	// PathID InitialPathID is the default path; for it these are equivalent to
	// PeekPacketNumber/PopPacketNumber at the 1-RTT encryption level.
	// An unknown path ID falls back to the initial path.
	PeekPacketNumberForPath(PathID) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumberForPath(PathID) protocol.PacketNumber

	GetLossDetectionTimeout() monotime.Time
	OnLossDetectionTimeout(now monotime.Time) error

	MigratedPath(now monotime.Time, initialMaxPacketSize protocol.ByteCount)

	// AddPath creates independent per-path state (packet number space, congestion
	// controller and RTT estimator) for an additional multipath path.
	// RemovePath drops it; the initial path cannot be removed.
	AddPath(id PathID)
	RemovePath(id PathID)
}
