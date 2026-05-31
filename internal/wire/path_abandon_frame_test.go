package wire

import (
	"io"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParsePathAbandon(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)           // path ID
	data = append(data, encodeVarInt(0x42)...) // error code
	frame, l, err := parsePathAbandonFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, uint64(0xdeadbeef), frame.PathID)
	require.Equal(t, uint64(0x42), frame.ErrorCode)
	require.Equal(t, len(data), l)
}

func TestParsePathAbandonErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)           // path ID
	data = append(data, encodeVarInt(0x42)...) // error code
	_, l, err := parsePathAbandonFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathAbandonFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWritePathAbandonFrame(t *testing.T) {
	frame := &PathAbandonFrame{PathID: 0xdecafbad, ErrorCode: 0x1337}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := encodeVarInt(uint64(FrameTypePathAbandon))
	expected = append(expected, encodeVarInt(0xdecafbad)...)
	expected = append(expected, encodeVarInt(0x1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
