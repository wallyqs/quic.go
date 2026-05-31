package main

// This example runs a miniature NATS-style publish/subscribe broker and two
// clients on top of NQUIC — the TLS-free QUIC profile (no certificates, no TLS
// handshake). See ../../NQUIC.md.
//
// It speaks a small but real subset of the NATS client protocol over a single
// bidirectional QUIC stream per connection:
//
//	server -> client : INFO {json}\r\n
//	client -> server : CONNECT {json}\r\n
//	client -> server : SUB <subject> <sid>\r\n
//	client -> server : PUB <subject> <#bytes>\r\n<payload>\r\n
//	server -> client : MSG <subject> <sid> <#bytes>\r\n<payload>\r\n
//	both ways        : PING\r\n / PONG\r\n
//
// Flow demonstrated in main():
//   1. start the broker (NQUIC server)
//   2. a subscriber connects and SUBs "nats.demo"
//   3. a publisher connects and PUBs a message to "nats.demo"
//   4. the broker routes it; the subscriber receives the MSG and prints it
//
// Everything runs over loopback UDP with quic.NQUICConfig() — no TLS anywhere.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const subject = "nats.demo"

func main() {
	log.SetFlags(0)

	// A UDP socket for the broker. We use an explicit quic.Transport so we can
	// shut it down cleanly at the end.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		log.Fatal(err)
	}
	serverTr := &quic.Transport{Conn: udpConn}
	defer serverTr.Close()

	// NQUICConfig() carries no certificate and triggers no TLS handshake — it
	// just selects the NQUIC profile via its ALPN.
	ln, err := serverTr.Listen(quic.NQUICConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	b := newBroker()
	go b.run(ln)

	addr := ln.Addr()
	log.Printf("broker listening on %s (NQUIC: no TLS, no certs)\n", addr)

	// Coordinate so the subscriber is ready before the publisher sends.
	subReady := make(chan struct{})
	received := make(chan string, 1)
	var wg sync.WaitGroup

	// Subscriber.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := runSubscriber(addr, subReady, received); err != nil {
			log.Printf("subscriber: %v", err)
		}
	}()

	// Publisher (waits for the subscriber to be subscribed first).
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-subReady
		if err := runPublisher(addr, "hello over NQUIC \xf0\x9f\x9a\x80"); err != nil {
			log.Printf("publisher: %v", err)
		}
	}()

	select {
	case msg := <-received:
		log.Printf("✅ subscriber received on %q: %s", subject, msg)
	case <-time.After(10 * time.Second):
		log.Fatal("timed out waiting for message")
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Broker (NQUIC server)
// ---------------------------------------------------------------------------

// subscription is one client's interest in a subject.
type subscription struct {
	sid string
	out *client // where to deliver matching messages
}

type broker struct {
	mu   sync.Mutex
	subs map[string][]subscription // subject -> subscribers
}

func newBroker() *broker {
	return &broker{subs: make(map[string][]subscription)}
}

func (b *broker) run(ln *quic.Listener) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		go b.serve(conn)
	}
}

func (b *broker) serve(conn *quic.Conn) {
	// In NATS the server speaks first (it sends INFO). A QUIC stream accepted by
	// the server only materializes once the *client* writes to it, so to model
	// "server speaks first" the server opens the stream and the client accepts
	// it. Each NATS connection uses a single bidirectional stream.
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	c := &client{stream: stream, r: bufio.NewReader(stream)}

	// NATS servers greet the client with an INFO line.
	c.writeLine(`INFO {"server_name":"nquic-demo","proto":1}`)

	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			// io.EOF or an application close (the client said "bye") is a normal
			// end of connection, not an error worth logging.
			if err != io.EOF && !isClientClose(err) {
				log.Printf("broker read: %v", err)
			}
			return
		}
		if err := b.handleCommand(c, strings.TrimRight(line, "\r\n")); err != nil {
			log.Printf("broker handle: %v", err)
			return
		}
	}
}

func (b *broker) handleCommand(c *client, line string) error {
	if line == "" {
		return nil
	}
	verb, args, _ := strings.Cut(line, " ")
	switch strings.ToUpper(verb) {
	case "CONNECT":
		// Options are ignored in this minimal broker.
		c.writeLine("+OK")
	case "PING":
		c.writeLine("PONG")
	case "PONG":
		// keepalive reply; nothing to do
	case "SUB":
		// SUB <subject> <sid>
		fields := strings.Fields(args)
		if len(fields) != 2 {
			c.writeLine("-ERR 'invalid SUB'")
			return nil
		}
		subj, sid := fields[0], fields[1]
		b.mu.Lock()
		b.subs[subj] = append(b.subs[subj], subscription{sid: sid, out: c})
		b.mu.Unlock()
		c.writeLine("+OK")
	case "PUB":
		// PUB <subject> <#bytes>\r\n<payload>\r\n
		fields := strings.Fields(args)
		if len(fields) != 2 {
			c.writeLine("-ERR 'invalid PUB'")
			return nil
		}
		subj := fields[0]
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			c.writeLine("-ERR 'invalid payload size'")
			return nil
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return err
		}
		// consume trailing CRLF after the payload
		if _, err := c.r.Discard(2); err != nil {
			return err
		}
		b.deliver(subj, payload)
		c.writeLine("+OK")
	default:
		c.writeLine("-ERR 'unknown protocol operation'")
	}
	return nil
}

func (b *broker) deliver(subj string, payload []byte) {
	b.mu.Lock()
	subs := append([]subscription(nil), b.subs[subj]...)
	b.mu.Unlock()
	for _, s := range subs {
		// MSG <subject> <sid> <#bytes>\r\n<payload>\r\n
		s.out.writeLine(fmt.Sprintf("MSG %s %s %d", subj, s.sid, len(payload)))
		s.out.writeRaw(payload)
		s.out.writeRaw([]byte("\r\n"))
	}
}

// isClientClose reports whether err is the peer cleanly closing the connection
// (an application-level close), as opposed to a real I/O error.
func isClientClose(err error) bool {
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr)
}

// client is the broker's view of a connected NATS client.
type client struct {
	mu     sync.Mutex
	stream *quic.Stream
	r      *bufio.Reader
}

func (c *client) writeLine(s string) {
	c.writeRaw([]byte(s + "\r\n"))
}

func (c *client) writeRaw(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.stream.Write(b); err != nil {
		log.Printf("broker write: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// natsConn is a tiny NATS client over an NQUIC stream.
type natsConn struct {
	conn   *quic.Conn
	stream *quic.Stream
	r      *bufio.Reader
}

func dialNATS(addr net.Addr) (*natsConn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udpConn}

	// Dial with the TLS-free NQUIC config. No certificate is verified because
	// no TLS handshake runs.
	conn, err := tr.Dial(context.Background(), addr, quic.NQUICConfig(), nil)
	if err != nil {
		tr.Close()
		return nil, err
	}
	// The broker opens the stream and greets us first (see broker.serve), so we
	// accept it rather than opening one.
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		tr.Close()
		return nil, err
	}
	nc := &natsConn{conn: conn, stream: stream, r: bufio.NewReader(stream)}

	// Read the server's INFO greeting and send CONNECT.
	info, err := nc.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	log.Printf("%s", strings.TrimRight(info, "\r\n"))
	nc.writeLine(`CONNECT {"verbose":false,"name":"nquic-client"}`)
	return nc, nil
}

func (nc *natsConn) writeLine(s string) error {
	_, err := nc.stream.Write([]byte(s + "\r\n"))
	return err
}

func (nc *natsConn) subscribe(subj, sid string) error {
	return nc.writeLine(fmt.Sprintf("SUB %s %s", subj, sid))
}

func (nc *natsConn) publish(subj string, data []byte) error {
	if err := nc.writeLine(fmt.Sprintf("PUB %s %d", subj, len(data))); err != nil {
		return err
	}
	_, err := nc.stream.Write(append(data, '\r', '\n'))
	return err
}

func (nc *natsConn) close() {
	nc.conn.CloseWithError(0, "bye")
}

func runSubscriber(addr net.Addr, ready chan<- struct{}, out chan<- string) error {
	nc, err := dialNATS(addr)
	if err != nil {
		return err
	}
	defer nc.close()

	if err := nc.subscribe(subject, "1"); err != nil {
		return err
	}
	log.Printf("subscriber: SUB %s", subject)
	close(ready) // tell the publisher we're listening

	// Read protocol lines until we get the MSG we're waiting for.
	for {
		line, err := nc.r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		verb, args, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "MSG":
			// MSG <subject> <sid> <#bytes>\r\n<payload>\r\n
			fields := strings.Fields(args)
			n, _ := strconv.Atoi(fields[len(fields)-1])
			payload := make([]byte, n)
			if _, err := io.ReadFull(nc.r, payload); err != nil {
				return err
			}
			nc.r.Discard(2) // trailing CRLF
			out <- string(payload)
			return nil
		case "PING":
			nc.writeLine("PONG")
		}
	}
}

func runPublisher(addr net.Addr, msg string) error {
	nc, err := dialNATS(addr)
	if err != nil {
		return err
	}
	defer nc.close()

	log.Printf("publisher: PUB %s %q", subject, msg)
	if err := nc.publish(subject, []byte(msg)); err != nil {
		return err
	}
	// Give the broker a moment to route before we tear down the connection.
	time.Sleep(200 * time.Millisecond)
	return nil
}
