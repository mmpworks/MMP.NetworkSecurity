// Package wire holds the socket plumbing the referees share: the listening
// port line, the accept loop, and byte relays that keep half-close.
package wire

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// closeWriter is the half-close shape of net.TCPConn, tls.Conn, and ssh.Channel.
type closeWriter interface {
	CloseWrite() error
}

// Listen binds addr and prints the bound port as the first stdout line.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stdout, "%d\n", ln.Addr().(*net.TCPAddr).Port)
	return ln, nil
}

// Serve runs handle on one goroutine per connection. It returns after naccept
// connections have finished. With naccept 0 it serves until the process dies,
// which is how the suites stop a server.
func Serve(ln net.Listener, naccept int, handle func(net.Conn)) error {
	var active sync.WaitGroup
	defer active.Wait()
	for n := 0; naccept == 0 || n < naccept; n++ {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		active.Go(func() {
			defer conn.Close()
			handle(conn)
		})
	}
	return nil
}

// Join copies both ways until both directions end. One side's end of stream
// becomes a half-close on the other side, so a peer can still finish sending.
func Join(a, b io.ReadWriter) {
	var both sync.WaitGroup
	both.Go(func() { copyHalf(a, b) })
	both.Go(func() { copyHalf(b, a) })
	both.Wait()
}

// Stdio joins conn to this process's stdin and stdout. It returns when conn
// stops sending. It does not wait for stdin, because a read of stdin can block
// for as long as the parent holds the pipe open.
func Stdio(conn io.ReadWriter) {
	go copyHalf(conn, os.Stdin)
	_, _ = io.Copy(os.Stdout, conn)
}

func copyHalf(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	if half, ok := dst.(closeWriter); ok {
		_ = half.CloseWrite()
	}
}
