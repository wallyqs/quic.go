package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathStatusFrame is a PATH_AVAILABLE or PATH_BACKUP frame.
//
// It tells the peer whether the identified path should be used actively
// (Available) or only as a backup (Backup). The SequenceNumber allows the
// receiver to ignore reordered status updates. This is part of the
// (non-interoperable) multipath extension; see internal/wire/frame_type.go.
type PathStatusFrame struct {
	PathID         uint64
	SequenceNumber uint64
	// Available reports whether the path should be used actively.
	// It maps to the PATH_AVAILABLE (true) and PATH_BACKUP (false) frame types.
	Available bool
}

func parsePathStatusFrame(b []byte, available bool, _ protocol.Version) (*PathStatusFrame, int, error) {
	startLen := len(b)
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return &PathStatusFrame{PathID: pathID, SequenceNumber: seq, Available: available}, startLen - len(b), nil
}

func (f *PathStatusFrame) frameType() FrameType {
	if f.Available {
		return FrameTypePathAvailable
	}
	return FrameTypePathBackup
}

func (f *PathStatusFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.frameType()))
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *PathStatusFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.frameType())) +
		quicvarint.Len(f.PathID) + quicvarint.Len(f.SequenceNumber))
}
