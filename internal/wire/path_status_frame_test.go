package wire

import (
	"io"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParsePathStatus(t *testing.T) {
	for _, available := range []bool{true, false} {
		data := encodeVarInt(0xdeadbeef)               // path ID
		data = append(data, encodeVarInt(0xc0ffee)...) // sequence number
		frame, l, err := parsePathStatusFrame(data, available, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, uint64(0xdeadbeef), frame.PathID)
		require.Equal(t, uint64(0xc0ffee), frame.SequenceNumber)
		require.Equal(t, available, frame.Available)
		require.Equal(t, len(data), l)
	}
}

func TestParsePathStatusErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)               // path ID
	data = append(data, encodeVarInt(0xc0ffee)...) // sequence number
	_, l, err := parsePathStatusFrame(data, true, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathStatusFrame(data[:i], true, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWritePathStatusFrame(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		frame := &PathStatusFrame{PathID: 0xdecafbad, SequenceNumber: 0x1337, Available: true}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := encodeVarInt(uint64(FrameTypePathAvailable))
		expected = append(expected, encodeVarInt(0xdecafbad)...)
		expected = append(expected, encodeVarInt(0x1337)...)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})

	t.Run("backup", func(t *testing.T) {
		frame := &PathStatusFrame{PathID: 0xdecafbad, SequenceNumber: 0x1337, Available: false}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := encodeVarInt(uint64(FrameTypePathBackup))
		expected = append(expected, encodeVarInt(0xdecafbad)...)
		expected = append(expected, encodeVarInt(0x1337)...)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})
}
