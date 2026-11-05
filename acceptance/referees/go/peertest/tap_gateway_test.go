package peertest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func decodeHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

// exchange runs one connection through a tap: the client sends up, the far end
// answers with down, and each side closes its write half. It returns what each
// side received.
func exchange(t *testing.T, tapPort int, ln net.Listener, up, down []byte) (atServer, atClient []byte) {
	t.Helper()
	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(waitLimit))
		go func() {
			_, _ = conn.Write(down)
			_ = conn.(*net.TCPConn).CloseWrite()
		}()
		got, _ := io.ReadAll(conn)
		received <- got
	}()
	client := dialRetry(t, tapPort)
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(waitLimit))
	go func() {
		_, _ = client.Write(up)
		_ = client.(*net.TCPConn).CloseWrite()
	}()
	atClient, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	return <-received, atClient
}

func listenLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// Byte comparison: the log, per direction, equals what each end sent and received.
func TestTapRecordsBothDirections(t *testing.T) {
	ln, target := listenLoopback(t)
	log := filepath.Join(t.TempDir(), "hop.hex")
	_, port := startServer(t, "tap", "-to", fmt.Sprintf("127.0.0.1:%d", target), "-log", log)
	up, down := randomBytes(t, 1<<20), randomBytes(t, 700_000)

	atServer, atClient := exchange(t, port, ln, up, down)
	if !bytes.Equal(atServer, up) || !bytes.Equal(atClient, down) {
		t.Fatalf("relay changed bytes: server %d of %d, client %d of %d", len(atServer), len(up), len(atClient), len(down))
	}
	streams := parseTapLog(t, log, 1)
	if !bytes.Equal(streams["c2s"], up) {
		t.Fatalf("log c2s holds %d bytes, sent %d", len(streams["c2s"]), len(up))
	}
	if !bytes.Equal(streams["s2c"], down) {
		t.Fatalf("log s2c holds %d bytes, sent %d", len(streams["s2c"]), len(down))
	}
}

// -flip-at changes one byte, once. The second connection passes clean.
func TestTapFlipsOneByteOnce(t *testing.T) {
	for _, dir := range []string{"c2s", "s2c"} {
		t.Run(dir, func(t *testing.T) {
			ln, target := listenLoopback(t)
			log := filepath.Join(t.TempDir(), "hop.hex")
			const at = 100_000
			_, port := startServer(t, "tap", "-to", fmt.Sprintf("127.0.0.1:%d", target), "-log", log,
				"-flip-at", fmt.Sprint(at), "-flip-dir", dir)
			up, down := randomBytes(t, 200_000), randomBytes(t, 200_000)

			atServer, atClient := exchange(t, port, ln, up, down)
			sent, got := up, atServer
			clean, cleanGot := down, atClient
			if dir == "s2c" {
				sent, got, clean, cleanGot = down, atClient, up, atServer
			}
			wantFlippedAt(t, sent, got, at)
			if !bytes.Equal(clean, cleanGot) {
				t.Fatal("the other direction changed")
			}
			if !bytes.Equal(parseTapLog(t, log, 1)[dir], got) {
				t.Fatal("log differs from what the receiver got")
			}
			text, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			wantContains(t, string(text), fmt.Sprintf("# flip conn=1 dir=%s offset=%d from=%02x to=%02x", dir, at, sent[at], sent[at]^0xFF))

			second, _ := exchange(t, port, ln, up, down)
			if !bytes.Equal(second, up) {
				t.Fatal("the second connection was also flipped")
			}
		})
	}
}

func wantFlippedAt(t *testing.T, sent, got []byte, at int) {
	t.Helper()
	if len(sent) != len(got) {
		t.Fatalf("length %d, sent %d", len(got), len(sent))
	}
	for i := range sent {
		want := sent[i]
		if i == at {
			want ^= 0xFF
		}
		if got[i] != want {
			t.Fatalf("offset %d: got %02x, want %02x", i, got[i], want)
		}
	}
}

// A tap flip inside TLS application data makes the receiving tlspeer name the
// failure. The pair is the two tlspeer modes, and the point is the tap.
func TestTapFlipBreaksTLSRecord(t *testing.T) {
	files := newTLSFiles(t)
	server, target := startServer(t, "tlspeer", "-mode", "server", "-cert", files.srvCert, "-key", files.srvKey)
	log := filepath.Join(t.TempDir(), "hop.hex")
	_, port := startServer(t, "tap", "-to", fmt.Sprintf("127.0.0.1:%d", target), "-log", log, "-flip-at", "50000")
	client := start(t, referee("tlspeer"), "-mode", "client", "-connect", fmt.Sprintf("127.0.0.1:%d", port), "-ca", files.caCert)
	client.event(t)
	go func() { _, _ = client.stdin.Write(bytes.Repeat([]byte("x"), 100_000)) }()
	wantField(t, server.event(t), "event", "handshake")
	event := server.event(t)
	wantField(t, event, "code", "TLS_RECORD_FAILED")
	wantContains(t, fmt.Sprint(event["detail"]), "bad record MAC")
}

// The full bridge: ssh.exe, tap, gogateway, tap, tlspeer. The first hop is SSH,
// the second is TLS 1.3 with group 0x11EC, and the payload is clear on neither.
func TestGatewayEndToEnd(t *testing.T) {
	ssh := sshPath(t)
	tlsFiles := newTLSFiles(t)
	sshFiles := newSSHFiles(t, false)
	dir := t.TempDir()
	hop1, hop2 := filepath.Join(dir, "hop1.hex"), filepath.Join(dir, "hop2.hex")

	nextHop, nextPort := startServer(t, "tlspeer", "-mode", "server", "-groups", "x25519mlkem768",
		"-cert", tlsFiles.srvCert, "-key", tlsFiles.srvKey)
	_, tap2 := startServer(t, "tap", "-to", fmt.Sprintf("127.0.0.1:%d", nextPort), "-log", hop2)
	gateway, gatewayPort := startServer(t, "gogateway", "-host-key", sshFiles.hostKey, "-authorized", sshFiles.authorized,
		"-kex", "curve25519-sha256", "-next", fmt.Sprintf("127.0.0.1:%d", tap2), "-ca", tlsFiles.caCert)
	_, tap1 := startServer(t, "tap", "-to", fmt.Sprintf("127.0.0.1:%d", gatewayPort), "-log", hop1)

	known := sshFiles.knownHosts(t, "known", tap1, sshFiles.hostPub)
	local := freePort(t)
	start(t, ssh, sshFiles.sshArgs(known, tap1, "-L", fmt.Sprintf("%d:127.0.0.1:9", local), "-N", "training@127.0.0.1")...)

	conn := dialRetry(t, local)
	defer conn.Close()
	secret := []byte("PIN-BLOCK-SENTINEL-4f6e-clear-text")
	if got := roundTrip(t, conn, secret); !bytes.Equal(got, secret) {
		t.Fatalf("echo %q", got)
	}

	event := nextHop.event(t)
	wantField(t, event, "curveID", "X25519MLKEM768")
	wantField(t, event, "curveIDCode", 0x11EC)
	wantField(t, event, "versionCode", 0x0304)
	gateway.waitFor(t, `"curveIDCode":4588`)

	streams1, streams2 := parseTapLog(t, hop1, 1), parseTapLog(t, hop2, 1)
	if !bytes.HasPrefix(streams1["c2s"], []byte("SSH-2.0-")) {
		t.Fatalf("hop1 starts %q", streams1["c2s"][:min(16, len(streams1["c2s"]))])
	}
	wantTLSHelloOffersGroup(t, streams2["c2s"], 0x11EC)
	for _, stream := range [][]byte{streams1["c2s"], streams1["s2c"], streams2["c2s"], streams2["s2c"]} {
		if bytes.Contains(stream, secret) {
			t.Fatal("clear payload on the wire")
		}
	}
}

// The second hop stays pinned: a next hop with only X25519 is refused, and the
// gateway names the failure rather than forwarding on a weaker group.
func TestGatewayRefusesClassicalNextHop(t *testing.T) {
	ssh := sshPath(t)
	tlsFiles := newTLSFiles(t)
	sshFiles := newSSHFiles(t, false)
	_, nextPort := startServer(t, "tlspeer", "-mode", "server", "-groups", "x25519",
		"-cert", tlsFiles.srvCert, "-key", tlsFiles.srvKey)
	gateway, gatewayPort := startServer(t, "gogateway", "-host-key", sshFiles.hostKey, "-authorized", sshFiles.authorized,
		"-next", fmt.Sprintf("127.0.0.1:%d", nextPort), "-ca", tlsFiles.caCert)
	known := sshFiles.knownHosts(t, "known", gatewayPort, sshFiles.hostPub)
	local := freePort(t)
	start(t, ssh, sshFiles.sshArgs(known, gatewayPort, "-L", fmt.Sprintf("%d:127.0.0.1:9", local), "-N", "training@127.0.0.1")...)

	conn := dialRetry(t, local)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(waitLimit))
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("got %d bytes through a refused next hop", n)
	}
	gateway.waitFor(t, `"code":"TLS_HANDSHAKE_FAILED"`)
}

// wantTLSHelloOffersGroup walks the ClientHello fields to the key_share extension
// (51) and checks a share for the group. A search for the two bytes anywhere in
// the record would match random bytes by chance.
func wantTLSHelloOffersGroup(t *testing.T, stream []byte, group uint16) {
	t.Helper()
	if len(stream) < 9 || stream[0] != 22 || stream[5] != 1 {
		t.Fatalf("no ClientHello at the start of the stream: % x", stream[:min(9, len(stream))])
	}
	groups := helloKeyShareGroups(t, stream[9:])
	for _, offered := range groups {
		if offered == group {
			return
		}
	}
	t.Fatalf("key_share groups %04x, want %04x", groups, group)
}

func helloKeyShareGroups(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	r := &fieldReader{t: t, data: hello}
	r.skip(2 + 32)    // version, random
	r.skip(r.read(1)) // session id
	r.skip(r.read(2)) // cipher suites
	r.skip(r.read(1)) // compression
	ext := r.sub(r.read(2))
	for ext.left() > 0 {
		kind := ext.read(2)
		body := ext.sub(ext.read(2))
		if kind == 51 {
			return shareGroups(t, body)
		}
	}
	t.Fatal("no key_share extension")
	return nil
}

func shareGroups(t *testing.T, body *fieldReader) []uint16 {
	t.Helper()
	list := body.sub(body.read(2))
	var groups []uint16
	for list.left() > 0 {
		groups = append(groups, uint16(list.read(2)))
		list.skip(list.read(2))
	}
	return groups
}

// fieldReader reads big-endian TLS fields and fails the test on a short read.
type fieldReader struct {
	t    *testing.T
	data []byte
}

func (r *fieldReader) left() int { return len(r.data) }

func (r *fieldReader) take(n int) []byte {
	r.t.Helper()
	if n > len(r.data) {
		r.t.Fatalf("short ClientHello: need %d, have %d", n, len(r.data))
	}
	head := r.data[:n]
	r.data = r.data[n:]
	return head
}

func (r *fieldReader) skip(n int) { r.take(n) }

func (r *fieldReader) read(size int) int {
	value := 0
	for _, b := range r.take(size) {
		value = value<<8 | int(b)
	}
	return value
}

func (r *fieldReader) sub(n int) *fieldReader {
	return &fieldReader{t: r.t, data: r.take(n)}
}
