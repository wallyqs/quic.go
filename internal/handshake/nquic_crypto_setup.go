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

// IsNQUIC reports whether the given tls.Config selects the NQUIC profile.
func IsNQUIC(tlsConf *tls.Config) bool {
	return tlsConf != nil && slices.Contains(tlsConf.NextProtos, NQUICNextProto)
}

// nquicCryptoSetup is a TLS-free CryptoSetup implementation for the NQUIC
// variant. It satisfies the same handshake.CryptoSetup interface that the
// connection drives, but instead of running a TLS 1.3 handshake it performs a
// minimal exchange whose only job is to carry QUIC transport parameters.
//
// Handshake message flow (null security model):
//
//	client                                  server
//	------ Initial[CRYPTO: client TPs] ---->
//	<----- Initial[CRYPTO: server TPs] ------
//	<----- 1-RTT[HANDSHAKE_DONE, ...] -------   (queued by the connection)
//
// The Initial encryption level keeps using the standard connection-ID-derived
// AEAD (NewInitialAEAD) — it requires no TLS and protects the parameter
// exchange exactly like vanilla QUIC. The 1-RTT (application) level uses the
// null AEAD, i.e. application data travels in cleartext.
//
// The Handshake encryption level is never used: NQUIC transitions straight
// from Initial to 1-RTT. The connection / packet packer tolerate the
// Handshake keys never becoming available (GetHandshakeSealer simply keeps
// returning ErrKeysNotYetAvailable / ErrKeysDropped).
type nquicSetup struct {
	perspective protocol.Perspective
	version     protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	events []Event

	initialSealer LongHeaderSealer
	initialOpener LongHeaderOpener

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
	// All NQUIC handshake data is exchanged at the Initial level.
	if encLevel != protocol.EncryptionInitial {
		return nil
	}

	peerParams := &wire.TransportParameters{}
	sentBy := protocol.PerspectiveServer
	if h.perspective == protocol.PerspectiveServer {
		sentBy = protocol.PerspectiveClient
	}
	if err := peerParams.Unmarshal(data, sentBy); err != nil {
		return err
	}
	h.peerParams = peerParams
	h.events = append(h.events, Event{
		Kind:                EventReceivedTransportParameters,
		TransportParameters: peerParams,
	})

	if h.perspective == protocol.PerspectiveServer {
		// Reply with the server "hello": our transport parameters.
		h.events = append(h.events, Event{
			Kind: EventWriteInitialData,
			Data: h.ourParams.Marshal(protocol.PerspectiveServer),
		})
	}

	// Both sides now have everything they need: install 1-RTT keys and
	// declare the handshake complete. There is no key exchange to perform.
	h.install1RTTKeys()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
	return nil
}

func (h *nquicSetup) install1RTTKeys() {
	h.has1RTTSealer = true
	h.has1RTTOpener = true
	// Signal that new read keys are available so the connection reprocesses
	// any packets that arrived before the keys were ready.
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
	// NQUIC never installs Handshake keys, so there is nothing to drop here.
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
	// NQUIC skips the Handshake encryption level entirely.
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return nil, ErrKeysNotYetAvailable
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
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return nil, ErrKeysNotYetAvailable
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
