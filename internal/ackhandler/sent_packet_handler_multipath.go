package ackhandler

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// This file implements ACK processing and loss detection for additional
// (non-initial) multipath paths. It deliberately operates only on a path's own
// pathState (its packet number space, congestion controller, RTT estimator and
// bytes-in-flight), so it never touches the single-path code that handles the
// initial path. ACKs for the initial path continue to flow through ReceivedAck.

// ReceivedAckForPath processes an ACK frame received for a specific path.
// For the initial path it is equivalent to ReceivedAck at the 1-RTT level.
func (h *sentPacketHandler) ReceivedAckForPath(ack *wire.AckFrame, id PathID, rcvTime monotime.Time) (bool /* acked a packet */, error) {
	if id == InitialPathID {
		return h.ReceivedAck(ack, protocol.Encryption1RTT, rcvTime)
	}
	ps := h.appDataPaths[id]
	if ps == nil {
		return false, nil
	}
	pnSpace := ps.space
	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet on a path",
		}
	}

	priorInFlight := ps.bytesInFlight
	acked, hasAckEliciting, err := h.detectAckedOnPath(ack, pnSpace)
	if err != nil {
		return false, err
	}
	if len(acked) == 0 {
		return false, nil
	}

	// Update the RTT if the largest acked is newly acknowledged and at least one
	// ack-eliciting packet was acked.
	if last := acked[len(acked)-1]; last.PacketNumber == largestAcked && hasAckEliciting {
		ackDelay := min(ack.DelayTime, ps.rttStats.MaxAckDelay())
		ps.rttStats.UpdateRTT(rcvTime.Sub(last.SendTime), ackDelay)
		ps.congestion.MaybeExitSlowStart()
	}

	pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)
	h.detectLostPacketsOnPath(ps, rcvTime)

	for _, p := range acked {
		if p.includedInBytesInFlight {
			ps.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
			if p.Length > ps.bytesInFlight {
				ps.bytesInFlight = 0
			} else {
				ps.bytesInFlight -= p.Length
			}
		}
		putPacket(p.packet)
	}
	return true, nil
}

// detectAckedOnPath returns the newly acknowledged packets for a path's packet
// number space, removing them from the history. It is a self-contained variant
// of detectAndRemoveAckedPackets that uses a local slice (no shared scratch).
func (h *sentPacketHandler) detectAckedOnPath(ack *wire.AckFrame, pnSpace *packetNumberSpace) ([]packetWithPacketNumber, bool, error) {
	for p := range pnSpace.history.SkippedPackets() {
		if ack.AcksPacket(p) {
			return nil, false, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received an ACK for a skipped packet number on a path",
			}
		}
	}

	var acked []packetWithPacketNumber
	var hasAckEliciting bool
	var ackRangeIndex int
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for pn, p := range pnSpace.history.Packets() {
		if pn < lowestAcked {
			continue
		}
		if pn > largestAcked {
			break
		}
		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			for pn > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}
			if pn < ackRange.Smallest {
				continue
			}
		}
		if p.IsAckEliciting() {
			hasAckEliciting = true
		}
		acked = append(acked, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	for _, p := range acked {
		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		for _, f := range p.StreamFrames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if err := pnSpace.history.Remove(p.PacketNumber); err != nil {
			return nil, false, err
		}
	}
	return acked, hasAckEliciting, nil
}

// detectLostPacketsOnPath performs time- and reordering-threshold loss detection
// for a single additional path, using that path's own RTT, congestion controller
// and bytes-in-flight. Lost packets' frames are queued for retransmission on the
// connection's (shared) retransmission queue.
func (h *sentPacketHandler) detectLostPacketsOnPath(ps *pathState, now monotime.Time) {
	pnSpace := ps.space
	pnSpace.lossTime = 0

	maxRTT := float64(max(ps.rttStats.LatestRTT(), ps.rttStats.SmoothedRTT()))
	lossDelay := max(time.Duration(timeThreshold*maxRTT), protocol.TimerGranularity)
	lostSendTime := now.Add(-lossDelay)
	priorInFlight := ps.bytesInFlight

	for pn, p := range pnSpace.history.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}
		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
		} else if pnSpace.history.Difference(pnSpace.largestAcked, pn) >= packetThreshold {
			packetLost = true
		} else if pnSpace.lossTime.IsZero() {
			pnSpace.lossTime = p.SendTime.Add(lossDelay)
		}
		if !packetLost {
			continue
		}
		pnSpace.history.DeclareLost(pn)
		if p.IsAckEliciting() {
			if p.includedInBytesInFlight {
				if p.Length > ps.bytesInFlight {
					ps.bytesInFlight = 0
				} else {
					ps.bytesInFlight -= p.Length
				}
				p.includedInBytesInFlight = false
			}
			h.queueFramesForRetransmission(p)
			if !p.IsPathMTUProbePacket {
				ps.congestion.OnCongestionEvent(pn, p.Length, priorInFlight)
			}
		}
	}
}
