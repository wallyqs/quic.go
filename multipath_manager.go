package quic

import (
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
)

// multipathPath is a path that the connection actively sends on (in addition to
// the initial path) when the multipath extension has been negotiated.
type multipathPath struct {
	id        ackhandler.PathID
	connID    protocol.ConnectionID
	transport *Transport
	status    pathStatus
	validated bool
}

// multipathManager tracks the set of paths a connection sends on simultaneously.
// It is only used when multipath has been negotiated. Path 0 (the initial path)
// is handled by the normal send loop and is not stored here; this manager only
// tracks the additional paths.
type multipathManager struct {
	mu        sync.Mutex
	paths     map[ackhandler.PathID]*multipathPath
	nextID    ackhandler.PathID
	maxPathID uint64 // negotiated maximum path ID (initial_max_path_id)
}

func newMultipathManager(maxPathID uint64) *multipathManager {
	return &multipathManager{
		paths:     make(map[ackhandler.PathID]*multipathPath),
		nextID:    1, // path 0 is the initial path
		maxPathID: maxPathID,
	}
}

// addPath registers a new additional path with the given connection ID and
// transport. It returns the assigned path ID and false if the negotiated path
// limit has been reached.
func (m *multipathManager) addPath(connID protocol.ConnectionID, tr *Transport) (ackhandler.PathID, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(m.nextID) > m.maxPathID {
		return 0, false
	}
	id := m.nextID
	m.nextID++
	m.paths[id] = &multipathPath{
		id:        id,
		connID:    connID,
		transport: tr,
		status:    pathStatusAvailable,
	}
	return id, true
}

// removePath drops a path from the manager.
func (m *multipathManager) removePath(id ackhandler.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.paths, id)
}

// setValidated marks a path as validated (PATH_CHALLENGE/RESPONSE completed).
func (m *multipathManager) setValidated(id ackhandler.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.paths[id]; ok {
		p.validated = true
	}
}

// setStatus updates a path's available/backup status, as signaled by a
// PATH_AVAILABLE / PATH_BACKUP frame.
func (m *multipathManager) setStatus(id ackhandler.PathID, status pathStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.paths[id]; ok {
		p.status = status
	}
}

func (m *multipathManager) path(id ackhandler.PathID) (*multipathPath, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.paths[id]
	return p, ok
}

func (m *multipathManager) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.paths)
}

// schedulablePaths builds the scheduler's view of the additional paths.
// canSend reports whether a given path's congestion controller currently allows
// sending (typically backed by SentPacketHandler.SendModeForPath).
func (m *multipathManager) schedulablePaths(canSend func(ackhandler.PathID) bool) []schedulablePath {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths := make([]schedulablePath, 0, len(m.paths))
	for id, p := range m.paths {
		paths = append(paths, schedulablePath{
			id:        id,
			status:    p.status,
			canSend:   canSend(id),
			validated: p.validated,
		})
	}
	return paths
}
