package ackhandler

// PathID identifies a path within a (multipath) QUIC connection.
// The initial path always has ID 0. Additional paths are only created when the
// multipath extension has been negotiated.
type PathID int64

// InitialPathID is the path ID of the connection's initial path.
const InitialPathID PathID = 0
