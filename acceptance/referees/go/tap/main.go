// Command tap is a TCP relay that records both directions and can flip one byte.
//
// tap is a referee and not a teaching tool. It exists so the acceptance suite
// can compare the wire with the app's trace from outside the app. The app has
// its own decoder for learners.
//
// Log format, one record per line, written before the bytes are forwarded:
//
//	<conn> <c2s|s2c> <offset> <hex>
//	# flip conn=<conn> dir=<c2s|s2c> offset=<offset> from=<hex> to=<hex>
//
// conn counts accepted connections from 1. offset counts bytes per connection
// and per direction from 0. The hex holds the bytes as forwarded, so after a
// flip it holds what the receiver got, and the flip line holds the original.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/wire"
)

const (
	clientToServer = "c2s"
	serverToClient = "s2c"
)

type options struct {
	listen  string
	to      string
	logPath string
	flipAt  int64
	flipDir string
	naccept int
}

func main() {
	var o options
	flag.StringVar(&o.listen, "listen", "127.0.0.1:0", "address to listen on")
	flag.StringVar(&o.to, "to", "", "host:port to relay to")
	flag.StringVar(&o.logPath, "log", "", "record file, overwritten at start")
	flag.Int64Var(&o.flipAt, "flip-at", -1, "invert the byte at this offset, once in the process")
	flag.StringVar(&o.flipDir, "flip-dir", clientToServer, "direction -flip-at counts in: c2s or s2c")
	flag.IntVar(&o.naccept, "naccept", 0, "exit after this many connections (0: run until killed)")
	flag.Parse()
	if err := o.run(); err != nil {
		report.Usage(err)
	}
}

func (o *options) run() error {
	if o.to == "" || o.logPath == "" {
		return errors.New("tap needs -to and -log")
	}
	if o.flipDir != clientToServer && o.flipDir != serverToClient {
		return fmt.Errorf("unknown -flip-dir %q", o.flipDir)
	}
	file, err := os.Create(o.logPath)
	if err != nil {
		return err
	}
	defer file.Close()
	ln, err := wire.Listen(o.listen)
	if err != nil {
		return err
	}
	relay := &relay{to: o.to, log: &hexLog{out: file}, flip: &flipper{at: o.flipAt, dir: o.flipDir}}
	var connections atomic.Int64
	return wire.Serve(ln, o.naccept, func(client net.Conn) {
		relay.serve(connections.Add(1), client)
	})
}

type relay struct {
	to   string
	log  *hexLog
	flip *flipper
}

func (r *relay) serve(id int64, client net.Conn) {
	server, err := net.Dial("tcp", r.to)
	if err != nil {
		report.Error("TAP_CONNECT_FAILED", err)
		return
	}
	defer server.Close()
	var both sync.WaitGroup
	both.Go(func() { r.pump(id, clientToServer, client, server.(*net.TCPConn)) })
	both.Go(func() { r.pump(id, serverToClient, server, client.(*net.TCPConn)) })
	both.Wait()
}

// pump owns one direction: read, flip if due, record, forward. Recording comes
// first, so once a receiver holds a byte, the log holds it too.
func (r *relay) pump(id int64, dir string, src io.Reader, dst *net.TCPConn) {
	buf := make([]byte, 32*1024)
	var offset int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			r.flip.apply(r.log, id, dir, offset, chunk)
			r.log.record(id, dir, offset, chunk)
			if _, werr := dst.Write(chunk); werr != nil {
				return
			}
			offset += int64(n)
		}
		if err != nil {
			_ = dst.CloseWrite()
			return
		}
	}
}

// flipper inverts one byte once per process. A product that reconnects after a
// tamper then gets a clean stream, and the suite sees the first failure.
type flipper struct {
	at   int64
	dir  string
	done atomic.Bool
}

func (f *flipper) apply(log *hexLog, id int64, dir string, offset int64, chunk []byte) {
	inChunk := f.at >= offset && f.at < offset+int64(len(chunk))
	if f.at < 0 || dir != f.dir || !inChunk || !f.done.CompareAndSwap(false, true) {
		return
	}
	index := f.at - offset
	from := chunk[index]
	chunk[index] = from ^ 0xFF
	log.flipped(id, dir, f.at, from, chunk[index])
}

// hexLog serializes records from both directions. Each line goes straight to
// the OS, so a killed tap leaves a complete log.
type hexLog struct {
	mu  sync.Mutex
	out io.Writer
}

func (l *hexLog) record(id int64, dir string, offset int64, chunk []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%d %s %d %x\n", id, dir, offset, chunk)
}

func (l *hexLog) flipped(id int64, dir string, offset int64, from, to byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "# flip conn=%d dir=%s offset=%d from=%02x to=%02x\n", id, dir, offset, from, to)
}
