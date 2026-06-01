package ackhandler

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// This file adds per-path received-packet tracking for multipath QUIC. Each
// path has its own application-data packet number space, so received packets
// and the ACKs we generate for them must be tracked per path. The initial path
// continues to use the existing single-path code; these methods only ever touch
// an additional path's own tracker.

// AddPath creates a received-packet tracker for an additional path.
// It is a no-op if the path already exists.
func (h *ReceivedPacketHandler) AddPath(id PathID) {
	if _, ok := h.appDataPaths[id]; ok {
		return
	}
	h.appDataPaths[id] = newAppDataReceivedPacketTracker(h.logger)
}

// RemovePath drops the received-packet tracker for an abandoned path.
// The initial path cannot be removed.
func (h *ReceivedPacketHandler) RemovePath(id PathID) {
	if id == InitialPathID {
		return
	}
	delete(h.appDataPaths, id)
}

func (h *ReceivedPacketHandler) trackerForPath(id PathID) *appDataReceivedPacketTracker {
	if t, ok := h.appDataPaths[id]; ok {
		return t
	}
	return &h.appDataPackets
}

// ReceivedPacketOnPath records a 1-RTT packet received on a specific path.
// For the initial path it is equivalent to ReceivedPacket at the 1-RTT level.
func (h *ReceivedPacketHandler) ReceivedPacketOnPath(
	id PathID,
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	if id == InitialPathID {
		return h.ReceivedPacket(pn, ecn, protocol.Encryption1RTT, rcvTime, ackEliciting)
	}
	return h.trackerForPath(id).ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
}

// GetAckFrameForPath returns an ACK frame for a specific path's packet number
// space, or nil if none is queued.
func (h *ReceivedPacketHandler) GetAckFrameForPath(id PathID, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	if id == InitialPathID {
		return h.appDataPackets.GetAckFrame(now, onlyIfQueued)
	}
	t, ok := h.appDataPaths[id]
	if !ok {
		return nil
	}
	return t.GetAckFrame(now, onlyIfQueued)
}

// IsPotentiallyDuplicateOnPath reports whether a 1-RTT packet number may be a
// duplicate on the given path.
func (h *ReceivedPacketHandler) IsPotentiallyDuplicateOnPath(id PathID, pn protocol.PacketNumber) bool {
	if id == InitialPathID {
		return h.appDataPackets.IsPotentiallyDuplicate(pn)
	}
	t, ok := h.appDataPaths[id]
	if !ok {
		return false
	}
	return t.IsPotentiallyDuplicate(pn)
}

// GetAlarmTimeoutForAnyPath returns the earliest ACK alarm across all paths.
func (h *ReceivedPacketHandler) GetAlarmTimeoutForAnyPath() monotime.Time {
	t := h.appDataPackets.GetAlarmTimeout()
	for id, tracker := range h.appDataPaths {
		if id == InitialPathID {
			continue
		}
		at := tracker.GetAlarmTimeout()
		if at.IsZero() {
			continue
		}
		if t.IsZero() || at.Before(t) {
			t = at
		}
	}
	return t
}
