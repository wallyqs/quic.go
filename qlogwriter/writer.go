package qlogwriter

import (
	"io"
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Trace represents a qlog trace that can have multiple event producers.
// Each producer can record events to the trace independently.
// When the last producer is closed, the underlying trace is closed as well.
//
// This package only defines the tracing interfaces. The bundled JSON-SEQ file
// writer was removed in this trimmed-down fork; provide your own Trace
// implementation to consume qlog events.
type Trace interface {
	// AddProducer creates a new Recorder for this trace.
	// Each Recorder can record events independently.
	AddProducer() Recorder

	// SupportsSchemas returns true if the trace supports the given schema.
	SupportsSchemas(schema string) bool
}

// Recorder is used to record events to a qlog trace.
// It is safe for concurrent use by multiple goroutines.
type Recorder interface {
	// RecordEvent records a single Event to the trace.
	// It must not be called after Close.
	RecordEvent(Event)
	// Close signals that this producer is done recording events.
	// When all producers are closed, the underlying trace is closed.
	// It must not be called concurrently with RecordEvent.
	io.Closer
}

// Event represents a qlog event that can be encoded to JSON.
// Each event must provide its name and a method to encode itself using a jsontext.Encoder.
type Event interface {
	// Name returns the name of the event, as it should appear in the qlog output
	Name() string
	// Encode writes the event's data to the provided jsontext.Encoder
	Encode(encoder *jsontext.Encoder, eventTime time.Time) error
}
