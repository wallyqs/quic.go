package quic

import "slices"

// pathStatus is the multipath status of a path, as signaled by the
// PATH_AVAILABLE / PATH_BACKUP frames.
type pathStatus uint8

const (
	// pathStatusAvailable means the path should be used actively.
	pathStatusAvailable pathStatus = iota
	// pathStatusBackup means the path should only be used when no available
	// path can carry traffic.
	pathStatusBackup
)

// schedulablePath is the scheduler's view of a path: its ID, whether it is a
// backup path, and whether its congestion controller currently allows sending.
type schedulablePath struct {
	id        pathID
	status    pathStatus
	canSend   bool // the path's congestion window has room for another packet
	validated bool // path validation (PATH_CHALLENGE/RESPONSE) has completed
}

// selectSendablePaths implements the multipath send scheduler.
//
// The goal is aggregate throughput: a single connection should fan out across
// every usable path so it can exceed a single network flow's bandwidth limit.
// The policy is therefore:
//
//   - Only validated paths whose congestion window has room are eligible.
//   - Prefer "available" paths: if any available path can send, return all of
//     them (so we stripe across every available path).
//   - Otherwise fall back to "backup" paths that can send.
//
// The returned slice is ordered by path ID for determinism, and is empty if no
// path can currently send (the caller should then wait for an ACK or the
// congestion window to open up).
func selectSendablePaths(paths []schedulablePath) []pathID {
	var available, backup []pathID
	for _, p := range paths {
		if !p.validated || !p.canSend {
			continue
		}
		switch p.status {
		case pathStatusBackup:
			backup = append(backup, p.id)
		default:
			available = append(available, p.id)
		}
	}
	result := available
	if len(result) == 0 {
		result = backup
	}
	slices.Sort(result)
	return result
}
