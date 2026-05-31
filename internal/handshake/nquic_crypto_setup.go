package handshake

import (
	"context"
	"crypto/tls"
	"slices"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// NQUICNextProto is the ALPN sentinel that selects the TLS-free NQUIC profile.
//
// NQUIC is gated on the application protocol name rather than introducing a
// brand-new public option: an application opts in by handing quic-go a
// certificate-less *tls.Config whose NextProtos contains this value. When it
// is present, quic-go runs the NQUIC handshake (no TLS, no certificates) and
// uses the null packet protection from nquic_aead.go instead of TLS-derived
// keys. The tls.Config is otherwise ignored.
const NQUICNextProto = "nquic-null/v1"

// nquicFinished is the (fixed) payload of the NQUIC "finished" message, sent at
// the Handshake encryption level. Its only job is to occupy the Handshake
// packet-number space so the standard key-drop machinery fires at the right
// time (see the flow description on nquicSetup).
var nquicFinished = []byte("NQUIC-FIN/1")

// IsNQUIC reports whether the given tls.Config selects the NQUIC profile.
func IsNQUIC(tlsConf *tls.Config) bool {
	return tlsConf != nil && slices.Contains(tlsConf.NextProtos, NQUICNextProto)
}

// nquicSetup is a TLS-free CryptoSetup implementation for the NQUIC variant. It
// satisfies the same handshake.CryptoSetup interface the connection drives, but
// instead of running a TLS 1.3 handshake it performs a minimal exchange whose
// only job is to carry QUIC transport parameters and to drive the connection's
// key-drop / handshake-confirmation machinery in the same order TLS would.
//
// Message flow (null security model):
//
//	client                                       server
//	------ Initial   [CRYPTO: client TPs] ------>
//	<----- Initial   [CRYPTO: server TPs] -------
//	------ Handshake [CRYPTO: "finished"] ------>
//	<----- 1-RTT     [HANDSHAKE_DONE, ...] ------   (queued by the connection)
//
// Why the Handshake round trip matters: the connection confirms the handshake
// (and drops Initial keys) the moment EventHandshakeComplete fires. If the
// server completed while processing the client's *Initial*, it would drop its
// Initial keys before its Initial reply (server TPs) was ever transmitted, and
// the client would hang. By deferring the server's completion until it receives
// the client's Handshake "finished", the server's Initial flight is guaranteed
// to have been sent first — exactly mirroring TLS, where the server completes
// only after the client's Finished.
//
// Key schedule:
//   - Initial:   standard connection-ID-derived AES-GCM (NewInitialAEAD); no
//     TLS required, protects the transport-parameter exchange as in vanilla QUIC.
//   - Handshake: null long-header AEAD (cleartext); carries only the "finished"
//     marker and the ACKs for it.
//   - 1-RTT:     null short-header AEAD (cleartext); application data.
type nquicSetup struct {
	perspective protocol.Perspective
	version     protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	events []Event

	initialSealer LongHeaderSealer
	initialOpener LongHeaderOpener

	handshakeSealer LongHeaderSealer
	handshakeOpener LongHeaderOpener

	has1RTTSealer bool
	has1RTTOpener bool
	oneRTTSealer  *nullSealer
	oneRTTOpener  *nullShortHeaderOpener

	handshakeConfirmed bool
}

var _ CryptoSetup = &nquicSetup{}

// NewNQUICCryptoSetupClient creates a TLS-free crypto setup for an NQUIC client.
func NewNQUICCryptoSetupClient(connID protocol.ConnectionID, tp *wire.TransportParameters, version protocol.Version) CryptoSetup {
	return newNQUICSetup(connID, tp, protocol.PerspectiveClient, version)
}

// NewNQUICCryptoSetupServer creates a TLS-free crypto setup for an NQUIC server.
func NewNQUICCryptoSetupServer(connID protocol.ConnectionID, tp *wire.TransportParameters, version protocol.Version) CryptoSetup {
	return newNQUICSetup(connID, tp, protocol.PerspectiveServer, version)
}

func newNQUICSetup(connID protocol.ConnectionID, tp *wire.TransportParameters, perspective protocol.Perspective, version protocol.Version) *nquicSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	return &nquicSetup{
		perspective:   perspective,
		version:       version,
		ourParams:     tp,
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		oneRTTSealer:  &nullSealer{},
		oneRTTOpener:  &nullShortHeaderOpener{},
	}
}

func (h *nquicSetup) StartHandshake(context.Context) error {
	if h.perspective == protocol.PerspectiveClient {
		// Send the client "hello": just our transport parameters.
		h.events = append(h.events, Event{
			Kind: EventWriteInitialData,
			Data: h.ourParams.Marshal(protocol.PerspectiveClient),
		})
	}
	// The server stays silent until it receives the client's Initial.
	return nil
}

func (h *nquicSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.handleInitial(data)
	case protocol.EncryptionHandshake:
		return h.handleHandshake(data)
	default:
		return nil
	}
}

// handleInitial processes the peer's transport parameters carried in the
// Initial CRYPTO stream.
func (h *nquicSetup) handleInitial(data []byte) error {
	sentBy := protocol.PerspectiveServer
	if h.perspective == protocol.PerspectiveServer {
		sentBy = protocol.PerspectiveClient
	}
	peerParams := &wire.TransportParameters{}
	if err := peerParams.Unmarshal(data, sentBy); err != nil {
		return err
	}
	h.peerParams = peerParams
	h.events = append(h.events, Event{
		Kind:                EventReceivedTransportParameters,
		TransportParameters: peerParams,
	})

	// Both Handshake and 1-RTT keys can be installed now: there is no key
	// exchange to perform.
	h.installKeys()

	if h.perspective == protocol.PerspectiveServer {
		// Reply with the server "hello" (our transport parameters). The server
		// does NOT complete yet: it waits for the client's Handshake "finished"
		// so that this Initial reply is sent before Initial keys are dropped.
		h.events = append(h.events, Event{
			Kind: EventWriteInitialData,
			Data: h.ourParams.Marshal(protocol.PerspectiveServer),
		})
		return nil
	}

	// Client: send the Handshake "finished" and declare completion. Sending a
	// Handshake packet causes the connection to drop Initial keys (RFC 9001
	// §4.9.1), after the client's Initial has already been sent.
	h.events = append(h.events,
		Event{Kind: EventWriteHandshakeData, Data: nquicFinished},
		Event{Kind: EventHandshakeComplete},
	)
	return nil
}

// handleHandshake processes the peer's Handshake CRYPTO data. Only the server
// acts on it: the client's "finished" completes the server's handshake.
func (h *nquicSetup) handleHandshake([]byte) error {
	if h.perspective == protocol.PerspectiveServer {
		h.events = append(h.events, Event{Kind: EventHandshakeComplete})
	}
	return nil
}

// installKeys installs the null Handshake and 1-RTT keys and signals the
// connection that new read keys are available (so it can reprocess any packets
// that arrived before the keys were ready).
func (h *nquicSetup) installKeys() {
	if h.handshakeSealer == nil {
		h.handshakeSealer = &nullSealer{}
		h.handshakeOpener = &nullLongHeaderOpener{}
	}
	h.has1RTTSealer = true
	h.has1RTTOpener = true
	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})
}

func (h *nquicSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *nquicSetup) Close() error { return nil }

func (h *nquicSetup) ChangeConnectionID(protocol.ConnectionID) {}

func (h *nquicSetup) GetSessionTicket() ([]byte, error) { return nil, nil }

func (h *nquicSetup) SetLargest1RTTAcked(protocol.PacketNumber) error { return nil }

func (h *nquicSetup) DiscardInitialKeys() {
	h.initialOpener = nil
	h.initialSealer = nil
}

func (h *nquicSetup) SetHandshakeConfirmed() {
	h.handshakeConfirmed = true
	// Drop Handshake keys, mirroring the TLS crypto setup.
	h.handshakeSealer = nil
	h.handshakeOpener = nil
}

func (h *nquicSetup) ConnectionState() ConnectionState {
	return ConnectionState{}
}

func (h *nquicSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *nquicSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *nquicSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	return nil, ErrKeysDropped
}

func (h *nquicSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.oneRTTSealer, nil
}

func (h *nquicSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *nquicSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeOpener, nil
}

func (h *nquicSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	return nil, ErrKeysDropped
}

func (h *nquicSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.oneRTTOpener, nil
}
