package quic_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

// TestNQUICEndToEnd establishes a real QUIC connection over a loopback UDP
// socket with NO TLS configuration and NO certificates, using the experimental
// TLS-free NQUIC profile, and exchanges data over a stream.
func TestNQUICEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Server: a certificate-less NQUIC config is all that's required.
	ln, err := quic.ListenAddr("127.0.0.1:0", quic.NQUICConfig(), nil)
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

	// Client: dial with the same TLS-free NQUIC config.
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), quic.NQUICConfig(), nil)
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
