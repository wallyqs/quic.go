package handshake

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// drain collects all pending events from a CryptoSetup until EventNoEvent.
func drain(cs CryptoSetup) []Event {
	var evs []Event
	for {
		ev := cs.NextEvent()
		if ev.Kind == EventNoEvent {
			return evs
		}
		evs = append(evs, ev)
	}
}

func findEvent(evs []Event, kind EventKind) (Event, bool) {
	for _, ev := range evs {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return Event{}, false
}

func nquicTestParams(connID protocol.ConnectionID, pers protocol.Perspective) *wire.TransportParameters {
	tp := &wire.TransportParameters{
		InitialMaxData:                 0x4000,
		InitialMaxStreamDataBidiLocal:  0x2000,
		InitialMaxStreamDataBidiRemote: 0x2000,
		InitialMaxStreamDataUni:        0x2000,
		MaxBidiStreamNum:               100,
		MaxUniStreamNum:                100,
		MaxUDPPayloadSize:              1452,
		ActiveConnectionIDLimit:        2,
		InitialSourceConnectionID:      connID,
	}
	if pers == protocol.PerspectiveServer {
		tp.OriginalDestinationConnectionID = connID
	}
	return tp
}

// TestNQUICHandshake exercises the full NQUIC (TLS-free) handshake between a
// client and a server, mirroring the event/message loop that the connection
// run loop drives, and then verifies that application data round-trips through
// the null 1-RTT AEAD.
func TestNQUICHandshake(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3})
	clientTP := nquicTestParams(connID, protocol.PerspectiveClient)
	serverTP := nquicTestParams(connID, protocol.PerspectiveServer)

	client := NewNQUICCryptoSetupClient(connID, clientTP, protocol.Version1)
	server := NewNQUICCryptoSetupServer(connID, serverTP, protocol.Version1)

	// 1. Client starts the handshake and emits its "hello" (transport params).
	require.NoError(t, client.StartHandshake(context.Background()))
	clientEvents := drain(client)
	clientHello, ok := findEvent(clientEvents, EventWriteInitialData)
	require.True(t, ok, "client should write Initial data")
	require.NotEmpty(t, clientHello.Data)

	// The server emits nothing until it hears from the client.
	require.NoError(t, server.StartHandshake(context.Background()))
	require.Empty(t, drain(server))

	// 2. Server handles the client hello. It replies with its own transport
	// parameters but does NOT complete yet: it waits for the client's
	// Handshake "finished".
	require.NoError(t, server.HandleMessage(clientHello.Data, protocol.EncryptionInitial))
	serverEvents := drain(server)

	tpEvent, ok := findEvent(serverEvents, EventReceivedTransportParameters)
	require.True(t, ok, "server should receive transport parameters")
	require.Equal(t, clientTP.InitialMaxData, tpEvent.TransportParameters.InitialMaxData)

	serverHello, ok := findEvent(serverEvents, EventWriteInitialData)
	require.True(t, ok, "server should write its Initial hello")
	require.NotEmpty(t, serverHello.Data)

	_, ok = findEvent(serverEvents, EventReceivedReadKeys)
	require.True(t, ok, "server should install read keys")
	_, ok = findEvent(serverEvents, EventHandshakeComplete)
	require.False(t, ok, "server must NOT complete before the client's finished")

	// Server now has 1-RTT keys available.
	serverSealer, err := server.Get1RTTSealer()
	require.NoError(t, err)
	serverOpener, err := server.Get1RTTOpener()
	require.NoError(t, err)

	// 3. Client handles the server hello: it installs keys, sends its Handshake
	// "finished", and completes.
	require.NoError(t, client.HandleMessage(serverHello.Data, protocol.EncryptionInitial))
	clientEvents = drain(client)

	tpEvent, ok = findEvent(clientEvents, EventReceivedTransportParameters)
	require.True(t, ok, "client should receive transport parameters")
	require.Equal(t, serverTP.InitialMaxData, tpEvent.TransportParameters.InitialMaxData)

	clientFin, ok := findEvent(clientEvents, EventWriteHandshakeData)
	require.True(t, ok, "client should write a Handshake finished")
	require.NotEmpty(t, clientFin.Data)
	_, ok = findEvent(clientEvents, EventHandshakeComplete)
	require.True(t, ok, "client handshake should complete")

	clientSealer, err := client.Get1RTTSealer()
	require.NoError(t, err)
	clientOpener, err := client.Get1RTTOpener()
	require.NoError(t, err)

	// 4. Server handles the client's Handshake finished and now completes.
	require.NoError(t, server.HandleMessage(clientFin.Data, protocol.EncryptionHandshake))
	serverEvents = drain(server)
	_, ok = findEvent(serverEvents, EventHandshakeComplete)
	require.True(t, ok, "server handshake should complete after the client's finished")

	// 5. Null AEAD: application data travels in cleartext with zero overhead.
	require.Equal(t, 0, clientSealer.Overhead())
	require.Equal(t, 0, serverSealer.Overhead())

	const pn = protocol.PacketNumber(42)
	ad := []byte("associated-data")

	// client -> server
	plaintext := []byte("hello from a NATS client over NQUIC")
	sealed := clientSealer.Seal(nil, plaintext, pn, ad)
	require.Equal(t, plaintext, sealed, "null AEAD must not transform the payload")
	opened, err := serverOpener.Open(nil, sealed, monotime.Now(), pn, protocol.KeyPhaseZero, ad)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	// server -> client
	reply := []byte("PONG")
	sealed = serverSealer.Seal(nil, reply, pn, ad)
	opened, err = clientOpener.Open(nil, sealed, monotime.Now(), pn, protocol.KeyPhaseZero, ad)
	require.NoError(t, err)
	require.Equal(t, reply, opened)
}

// TestNQUICInitialKeysAreStandard confirms that NQUIC keeps the standard,
// connection-ID-derived Initial AEAD (no TLS required), and only the 1-RTT
// level uses the null AEAD.
func TestNQUICInitialKeysAreStandard(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	cs := NewNQUICCryptoSetupClient(connID, nquicTestParams(connID, protocol.PerspectiveClient), protocol.Version1)

	sealer, err := cs.GetInitialSealer()
	require.NoError(t, err)
	// The standard Initial AEAD (AES-128-GCM) adds a 16-byte auth tag.
	require.Equal(t, 16, sealer.Overhead())

	// Handshake and 1-RTT keys are not available until the parameter exchange
	// has happened.
	_, err = cs.GetHandshakeSealer()
	require.ErrorIs(t, err, ErrKeysNotYetAvailable)
	_, err = cs.Get1RTTSealer()
	require.ErrorIs(t, err, ErrKeysNotYetAvailable)
}
