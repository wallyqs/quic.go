package quic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNQUICEndToEnd establishes a real QUIC connection over a loopback UDP
// socket with NO TLS configuration and NO certificates, using the experimental
// TLS-free NQUIC profile, and exchanges data over a stream.
//
// It manages the Transports explicitly (rather than via ListenAddr/DialAddr) so
// they can be closed before the package's stray-goroutine check in TestMain.
func TestNQUICEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Server transport + listener. A certificate-less NQUIC config is all that's
	// required — no TLS handshake runs.
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(NQUICConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()

	const msg = "SUB foo 1\r\nPING\r\n" // looks like NATS protocol traffic
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- func() error {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return err
			}
			str, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(str, buf); err != nil {
				return err
			}
			// Echo it back.
			if _, err := str.Write(buf); err != nil {
				return err
			}
			return str.Close()
		}()
	}()

	// Client transport. Dial with the same TLS-free NQUIC config.
	clientTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer clientTr.Close()
	conn, err := clientTr.Dial(ctx, ln.Addr(), NQUICConfig(), nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "done")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte(msg))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	got, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, msg, string(got))

	require.NoError(t, <-serverErr)
}
