package peertest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var tlsGroups = []struct {
	flag, opensslName string
	code              int
	clientMarker      string // The line s_client prints for this group.
}{
	{"x25519", "X25519", 0x001D, "Peer Temp Key: X25519"},
	{"x25519mlkem768", "X25519MLKEM768", 0x11EC, "Negotiated TLS1.3 group: X25519MLKEM768"},
}

// tlspeer server against openssl s_client: both sides name the group, the echo
// comes back through OpenSSL, and the two key logs hold the same secrets.
func TestTLSPeerServerAgainstOpenSSLClient(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	for _, group := range tlsGroups {
		t.Run(group.flag, func(t *testing.T) {
			dir := t.TempDir()
			serverLog := filepath.Join(dir, "server.log")
			clientLog := filepath.Join(dir, "client.log")
			server, port := startServer(t, "tlspeer", "-mode", "server", "-groups", group.flag,
				"-cert", files.srvCert, "-key", files.srvKey, "-keylog", serverLog)
			client := start(t, openssl, "s_client", "-connect", fmt.Sprintf("127.0.0.1:%d", port),
				"-tls1_3", "-groups", group.opensslName, "-CAfile", files.caCert, "-verify_return_error",
				"-verify_ip", "127.0.0.1", "-keylogfile", clientLog, "-ign_eof")

			event := server.event(t)
			wantField(t, event, "version", "TLS 1.3")
			wantField(t, event, "versionCode", 0x0304)
			wantField(t, event, "curveID", group.opensslName)
			wantField(t, event, "curveIDCode", group.code)
			client.waitFor(t, group.clientMarker)

			client.waitFor(t, "Verify return code: 0 (ok)")
			if _, err := io.WriteString(client.stdin, "ping-from-openssl\n"); err != nil {
				t.Fatal(err)
			}
			client.waitFor(t, "ping-from-openssl")
			wantKeyLogMatch(t, serverLog, clientLog)
		})
	}
}

// tlspeer client against openssl s_server, in the design section 9 form. -rev is
// OpenSSL's own echo, and it reverses the text, so the reply cannot be a local loop.
func TestTLSPeerClientAgainstOpenSSLServer(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	for _, group := range tlsGroups {
		t.Run(group.flag, func(t *testing.T) {
			dir := t.TempDir()
			serverLog := filepath.Join(dir, "server.log")
			clientLog := filepath.Join(dir, "client.log")
			server := start(t, openssl, "s_server", "-accept", "0", "-tls1_3", "-groups", group.opensslName,
				"-cert", files.srvCert, "-key", files.srvKey, "-keylogfile", serverLog, "-naccept", "1", "-rev")
			port := opensslPort(t, server)

			client := start(t, referee("tlspeer"), "-mode", "client", "-groups", group.flag,
				"-connect", fmt.Sprintf("127.0.0.1:%d", port), "-ca", files.caCert, "-keylog", clientLog)
			event := client.event(t)
			wantField(t, event, "role", "client")
			wantField(t, event, "curveID", group.opensslName)
			wantField(t, event, "curveIDCode", group.code)

			if _, err := io.WriteString(client.stdin, "ping\n"); err != nil {
				t.Fatal(err)
			}
			client.waitFor(t, "gnip")
			wantKeyLogMatch(t, clientLog, serverLog)
		})
	}
}

// The group pin holds: a server that offers only X25519 refuses a hybrid-only
// client, and the client names the failure.
func TestTLSPeerGroupPinRefused(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	server := start(t, openssl, "s_server", "-accept", "0", "-tls1_3", "-groups", "X25519",
		"-cert", files.srvCert, "-key", files.srvKey, "-naccept", "1", "-rev")
	port := opensslPort(t, server)
	stdout, _, code := runTool(t, referee("tlspeer"), "-mode", "client", "-groups", "x25519mlkem768",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port), "-ca", files.caCert)
	wantField(t, lastJSON(t, stdout), "code", "TLS_HANDSHAKE_FAILED")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

func TestTLSPeerUntrustedServerNamed(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	other := newTLSFiles(t)
	server := start(t, openssl, "s_server", "-accept", "0", "-tls1_3",
		"-cert", files.srvCert, "-key", files.srvKey, "-naccept", "1", "-rev")
	port := opensslPort(t, server)
	stdout, _, code := runTool(t, referee("tlspeer"), "-mode", "client",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port), "-ca", other.caCert)
	wantField(t, lastJSON(t, stdout), "code", "TLS_CERT_VERIFY_FAILED")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

// Mutual TLS, with OpenSSL as the client: one control with a certificate and one
// attack that differs only by leaving the certificate out.
func TestTLSPeerRequireClientCert(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	server, port := startServer(t, "tlspeer", "-mode", "server", "-cert", files.srvCert, "-key", files.srvKey,
		"-ca", files.caCert, "-require-client-cert")
	connect := fmt.Sprintf("127.0.0.1:%d", port)

	withCert := start(t, openssl, "s_client", "-connect", connect, "-tls1_3", "-CAfile", files.caCert,
		"-cert", files.cliCert, "-key", files.cliKey, "-ign_eof")
	withCert.waitFor(t, "Verify return code: 0 (ok)")
	event := server.event(t)
	wantField(t, event, "event", "handshake")
	wantField(t, event, "peerSubject", "CN=referee test cli")
	_ = withCert.stdin.Close()

	withoutCert := start(t, openssl, "s_client", "-connect", connect, "-tls1_3", "-CAfile", files.caCert, "-ign_eof")
	event = server.event(t)
	wantField(t, event, "code", "TLS_CLIENT_CERT_MISSING")
	_ = withoutCert.stdin.Close()
}

// -relay sends the session bytes to a plain TCP target, here the test's echo.
func TestTLSPeerRelay(t *testing.T) {
	files := newTLSFiles(t)
	target := echoServer(t)
	_, port := startServer(t, "tlspeer", "-mode", "server", "-cert", files.srvCert, "-key", files.srvKey,
		"-relay", fmt.Sprintf("127.0.0.1:%d", target))
	client := start(t, opensslPath(t), "s_client", "-connect", fmt.Sprintf("127.0.0.1:%d", port),
		"-tls1_3", "-CAfile", files.caCert, "-ign_eof")
	client.waitFor(t, "Verify return code: 0 (ok)")
	if _, err := io.WriteString(client.stdin, "through-the-relay\n"); err != nil {
		t.Fatal(err)
	}
	client.waitFor(t, "through-the-relay")
}

func opensslPort(t *testing.T, server *proc) int {
	t.Helper()
	line := server.waitFor(t, "ACCEPT")
	match := regexp.MustCompile(`:(?<port>\d+)$`).FindStringSubmatch(line)
	if match == nil {
		t.Fatalf("no port in %q", line)
	}
	var port int
	fmt.Sscanf(match[1], "%d", &port)
	return port
}

// wantKeyLogMatch compares a Go key log with an OpenSSL key log for one session.
// Go writes the four traffic secrets. OpenSSL writes the same four and adds
// EXPORTER_SECRET. Any other difference fails.
func wantKeyLogMatch(t *testing.T, goLog, opensslLog string) {
	t.Helper()
	goLines := keyLogLines(t, goLog)
	if len(goLines) != 4 {
		t.Fatalf("%s holds %d lines, want 4: %v", goLog, len(goLines), goLines)
	}
	var shared []string
	for _, line := range keyLogLines(t, opensslLog) {
		if !strings.HasPrefix(line, "EXPORTER_SECRET ") {
			shared = append(shared, line)
		}
	}
	if !slices.Equal(goLines, shared) {
		t.Fatalf("key logs differ:\n%v\n%v", goLines, shared)
	}
}

// keyLogLines returns the secret lines in sorted order. OpenSSL adds a comment
// line, and the two tools write the secrets in different orders.
func keyLogLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	slices.Sort(lines)
	return lines
}

// This test pins a Windows behaviour that the design section 9 commands meet.
// s_server without -rev or -www polls stdin, treats an idle pipe as ready, and
// blocks in the read, so the handshake never finishes. The same command with
// -rev serves at once.
func TestOpenSSLServerHangsOnIdleStdinWithoutRev(t *testing.T) {
	openssl := opensslPath(t)
	files := newTLSFiles(t)
	base := []string{"s_server", "-accept", "0", "-tls1_3", "-cert", files.srvCert, "-key", files.srvKey, "-naccept", "1"}
	connect := func(server *proc) *proc {
		port := opensslPort(t, server)
		return start(t, referee("tlspeer"), "-mode", "client", "-connect", fmt.Sprintf("127.0.0.1:%d", port), "-ca", files.caCert)
	}

	withRev := connect(start(t, openssl, append(slices.Clone(base), "-rev")...))
	wantField(t, withRev.event(t), "event", "handshake")

	plain := connect(start(t, openssl, base...))
	select {
	case line := <-plain.lines:
		t.Fatalf("plain s_server answered: %s. Update the README note on -rev", line)
	case <-time.After(3 * time.Second):
	}
}
