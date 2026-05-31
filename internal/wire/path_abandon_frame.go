package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathAbandonFrame is a PATH_ABANDON frame.
//
// It signals to the peer that the sender will no longer send packets on the
// identified path. This is part of the (non-interoperable) multipath extension;
// see internal/wire/frame_type.go.
type PathAbandonFrame struct {
	PathID    uint64
	ErrorCode uint64
}

func parsePathAbandonFrame(b []byte, _ protocol.Version) (*PathAbandonFrame, int, error) {
	startLen := len(b)
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	errorCode, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return &PathAbandonFrame{PathID: pathID, ErrorCode: errorCode}, startLen - len(b), nil
}

func (f *PathAbandonFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathAbandon))
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.ErrorCode)
	return b, nil
}

// Length of a written frame
func (f *PathAbandonFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathAbandon)) +
		quicvarint.Len(f.PathID) + quicvarint.Len(f.ErrorCode))
}
