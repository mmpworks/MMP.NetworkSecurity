// Command tlspeer is a TLS 1.3 referee on Go's crypto/tls. The group it reports
// comes from the library's ConnectionState, so a suite can believe it.
//
// As a server it prints the listening port on the first line. In both modes it
// prints one JSON line per handshake. A server then echoes, a client then joins
// the session to stdin and stdout, and -relay sends the session to a TCP
// address instead.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/tlsconf"
	"mmpworks.local/netsec/referees/internal/wire"
)

const handshakeLimit = 30 * time.Second

type peer struct {
	tlsconf.Options
	mode              string
	listen            string
	connect           string
	relay             string
	requireClientCert bool
	naccept           int
}

func main() {
	p := parseFlags()
	var err error
	switch p.mode {
	case "server":
		err = p.runServer()
	case "client":
		err = p.runClient()
	default:
		err = fmt.Errorf("unknown -mode %q", p.mode)
	}
	if err != nil {
		report.Usage(err)
	}
}

func parseFlags() *peer {
	p := &peer{}
	p.Options.Register(flag.CommandLine, "x25519mlkem768")
	flag.StringVar(&p.mode, "mode", "server", "client or server")
	flag.StringVar(&p.listen, "listen", "127.0.0.1:0", "server: address to listen on")
	flag.StringVar(&p.connect, "connect", "", "client: host:port to dial")
	flag.StringVar(&p.relay, "relay", "", "send session bytes to this TCP host:port instead of echo or stdio")
	flag.BoolVar(&p.requireClientCert, "require-client-cert", false, "server: require a client certificate signed by -ca")
	flag.IntVar(&p.naccept, "naccept", 0, "server: exit after this many connections (0: run until killed)")
	flag.Parse()
	return p
}

func (p *peer) runServer() error {
	cfg, err := p.Server(p.requireClientCert)
	if err != nil {
		return err
	}
	ln, err := wire.Listen(p.listen)
	if err != nil {
		return err
	}
	return wire.Serve(ln, p.naccept, func(raw net.Conn) {
		conn := tls.Server(raw, cfg)
		if handshake(conn, "server") == nil {
			p.stream(conn, echo)
		}
	})
}

func (p *peer) runClient() error {
	host, _, err := net.SplitHostPort(p.connect)
	if err != nil {
		return fmt.Errorf("-connect: %w", err)
	}
	cfg, err := p.Client(host)
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", p.connect)
	if err != nil {
		report.Reject("TCP_CONNECT_FAILED", err)
	}
	conn := tls.Client(raw, cfg)
	defer conn.Close()
	if err := handshake(conn, "client"); err != nil {
		os.Exit(report.ExitRejected)
	}
	p.stream(conn, func(c *tls.Conn) { wire.Stdio(c) })
	return nil
}

func handshake(conn *tls.Conn, role string) error {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeLimit)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		report.Error(tlsconf.FailureCode(err), err)
		return err
	}
	report.Event(tlsconf.Describe(role, conn.ConnectionState()))
	return nil
}

func (p *peer) stream(conn *tls.Conn, fallback func(*tls.Conn)) {
	if p.relay == "" {
		fallback(conn)
		return
	}
	target, err := net.Dial("tcp", p.relay)
	if err != nil {
		report.Error("RELAY_CONNECT_FAILED", err)
		return
	}
	defer target.Close()
	wire.Join(conn, target)
}

// echo returns every byte the client sends. A client that closes without a
// close_notify counts as an ordinary end of session for a referee.
func echo(conn *tls.Conn) {
	if _, err := io.Copy(conn, conn); err != nil && !errors.Is(err, io.EOF) {
		report.Error("TLS_RECORD_FAILED", err)
	}
	_ = conn.CloseWrite()
}
