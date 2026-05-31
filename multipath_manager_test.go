package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestMultipathManagerAddRespectsLimit(t *testing.T) {
	// maxPathID = 2 allows path IDs 1 and 2 (path 0 is the initial path)
	m := newMultipathManager(2)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})

	id1, ok := m.addPath(connID, nil)
	require.True(t, ok)
	require.Equal(t, ackhandler.PathID(1), id1)
	id2, ok := m.addPath(connID, nil)
	require.True(t, ok)
	require.Equal(t, ackhandler.PathID(2), id2)
	// the third path exceeds the negotiated limit
	_, ok = m.addPath(connID, nil)
	require.False(t, ok)
	require.Equal(t, 2, m.len())
}

func TestMultipathManagerStatusAndValidation(t *testing.T) {
	m := newMultipathManager(4)
	id, ok := m.addPath(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), nil)
	require.True(t, ok)

	p, ok := m.path(id)
	require.True(t, ok)
	require.False(t, p.validated)
	require.Equal(t, pathStatusAvailable, p.status)

	m.setValidated(id)
	m.setStatus(id, pathStatusBackup)
	p, _ = m.path(id)
	require.True(t, p.validated)
	require.Equal(t, pathStatusBackup, p.status)

	m.removePath(id)
	_, ok = m.path(id)
	require.False(t, ok)
	require.Zero(t, m.len())
}

func TestMultipathManagerSchedulablePaths(t *testing.T) {
	m := newMultipathManager(4)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	id1, _ := m.addPath(connID, nil)
	id2, _ := m.addPath(connID, nil)
	m.setValidated(id1)
	m.setValidated(id2)

	// only path id1 can send according to the congestion callback
	canSend := func(id ackhandler.PathID) bool { return id == id1 }
	sps := m.schedulablePaths(canSend)
	require.Len(t, sps, 2)

	// feed into the scheduler: only id1 is selected
	require.Equal(t, []ackhandler.PathID{id1}, selectSendablePaths(sps))
}
