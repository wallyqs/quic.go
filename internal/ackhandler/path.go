package ackhandler

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// PathID identifies a path within a (multipath) QUIC connection.
// The initial path always has ID 0. Additional paths are only created when the
// multipath extension has been negotiated.
type PathID int64

// InitialPathID is the path ID of the connection's initial path.
const InitialPathID PathID = 0

// pathState bundles the per-path state of the application-data packet number space.
//
// In multipath QUIC each path performs loss recovery and congestion control
// independently, because paths have independent bandwidth, RTT and loss. This
// type groups the state that must therefore be kept per path: its packet number
// space (which also carries the loss-detection timers), its congestion
// controller, its RTT estimator, and the bytes in flight on that path.
type pathState struct {
	space         *packetNumberSpace
	congestion    congestion.SendAlgorithmWithDebugInfos
	rttStats      *utils.RTTStats
	bytesInFlight protocol.ByteCount
}

// newInitialPathState wraps the connection's shared packet number space,
// congestion controller and RTT estimator for the initial path. These are
// shared with the sentPacketHandler so that single-path behavior is unchanged.
func newInitialPathState(space *packetNumberSpace, cong congestion.SendAlgorithmWithDebugInfos, rttStats *utils.RTTStats) *pathState {
	return &pathState{space: space, congestion: cong, rttStats: rttStats}
}

// newPathState creates independent state for an additional path: a fresh packet
// number space, a fresh RTT estimator and a fresh congestion controller.
func newPathState(connStats *utils.ConnectionStats, initialMaxDatagramSize protocol.ByteCount, qlogger qlogwriter.Recorder) *pathState {
	rttStats := utils.NewRTTStats()
	cong := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)
	return &pathState{
		space:      newPacketNumberSpace(0, true),
		congestion: cong,
		rttStats:   rttStats,
	}
}
