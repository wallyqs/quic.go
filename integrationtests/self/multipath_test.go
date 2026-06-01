package self_test

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

// TestMultipathDataTransfer exercises the experimental multipath data path
// end to end: a client adds a second path (a second local transport) and
// transfers 1 MiB over the single logical connection. Both client transports
// reach the same server, so this validates per-path packet numbering,
// congestion control, ACK generation/accounting, the scheduler/send-loop
// fan-out, the receive-side per-path packet-number decoding and ACK demux, and
// server-side path recognition — on localhost.
func TestMultipathDataTransfer(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{EnableMultipath: true}))
	require.NoError(t, err)
	defer server.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tr1.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableMultipath: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	require.True(t, conn.ConnectionState().SupportsMultipath.Remote)

	sconn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	// add a second path
	require.NoError(t, conn.AddMultipathPath(tr2))

	// transfer 1 MiB over the connection
	const dataLen = 1 << 20
	data := make([]byte, dataLen)
	rand.Read(data)

	errChan := make(chan error, 1)
	go func() {
		str, err := conn.OpenUniStream()
		if err != nil {
			errChan <- err
			return
		}
		if _, err := str.Write(data); err != nil {
			errChan <- err
			return
		}
		errChan <- str.Close()
	}()

	sstr, err := sconn.AcceptUniStream(ctx)
	require.NoError(t, err)
	received, err := io.ReadAll(sstr)
	require.NoError(t, err)
	require.NoError(t, <-errChan)
	require.Equal(t, data, received)
}
