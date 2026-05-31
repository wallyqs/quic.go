package quic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectSendablePathsStripesAcrossAvailablePaths(t *testing.T) {
	// all available paths that can send are returned, so the connection fans
	// out across every usable path
	paths := []schedulablePath{
		{id: 0, status: pathStatusAvailable, canSend: true, validated: true},
		{id: 1, status: pathStatusAvailable, canSend: true, validated: true},
		{id: 2, status: pathStatusAvailable, canSend: true, validated: true},
	}
	require.Equal(t, []pathID{0, 1, 2}, selectSendablePaths(paths))
}

func TestSelectSendablePathsSkipsBlockedAndUnvalidated(t *testing.T) {
	paths := []schedulablePath{
		{id: 0, status: pathStatusAvailable, canSend: true, validated: true},
		{id: 1, status: pathStatusAvailable, canSend: false, validated: true}, // congestion-limited
		{id: 2, status: pathStatusAvailable, canSend: true, validated: false}, // not yet validated
	}
	require.Equal(t, []pathID{0}, selectSendablePaths(paths))
}

func TestSelectSendablePathsFallsBackToBackup(t *testing.T) {
	// when no available path can send, backup paths are used
	paths := []schedulablePath{
		{id: 0, status: pathStatusAvailable, canSend: false, validated: true},
		{id: 1, status: pathStatusBackup, canSend: true, validated: true},
		{id: 2, status: pathStatusBackup, canSend: true, validated: true},
	}
	require.Equal(t, []pathID{1, 2}, selectSendablePaths(paths))
}

func TestSelectSendablePathsPrefersAvailableOverBackup(t *testing.T) {
	// available paths take precedence; backup paths are not used while an
	// available path can still send
	paths := []schedulablePath{
		{id: 0, status: pathStatusAvailable, canSend: true, validated: true},
		{id: 1, status: pathStatusBackup, canSend: true, validated: true},
	}
	require.Equal(t, []pathID{0}, selectSendablePaths(paths))
}

func TestSelectSendablePathsNoneAvailable(t *testing.T) {
	paths := []schedulablePath{
		{id: 0, status: pathStatusAvailable, canSend: false, validated: true},
		{id: 1, status: pathStatusBackup, canSend: false, validated: true},
	}
	require.Empty(t, selectSendablePaths(paths))
	require.Empty(t, selectSendablePaths(nil))
}
