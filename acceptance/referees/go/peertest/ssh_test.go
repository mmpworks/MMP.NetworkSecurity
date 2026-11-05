package peertest

import (
	"fmt"
	"strings"
	"testing"
)

const (
	legacyKex    = "diffie-hellman-group14-sha1"
	legacyCipher = "aes128-cbc"
	legacyMAC    = "hmac-sha1"
	legacyHost   = "ssh-rsa"
)

// Modern suite, with Windows ssh.exe as the client. ssh.exe's own -v output names
// the algorithms, so the claim does not rest on the referee's self-report.
func TestSSHPeerExecModern(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, false)
	server, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", "curve25519-sha256")
	known := files.knownHosts(t, "known", port, files.hostPub)
	args := files.sshArgs(known, port, "-v", "training@127.0.0.1", "echo", "hello", "referee")
	stdout, stderr, code := runTool(t, ssh, args...)
	if code != 0 || stdout != "hello referee\n" && stdout != "hello referee\r\n" {
		t.Fatalf("exit %d stdout %q stderr %s", code, stdout, stderr)
	}
	wantContains(t, stderr, "kex: algorithm: curve25519-sha256")
	event := server.event(t)
	wantField(t, event, "kex", "curve25519-sha256")
	wantField(t, event, "user", "training")
	event = server.event(t)
	wantField(t, event, "event", "exec")
	wantField(t, event, "exit", 0)
}

// Legacy suite, pinned to one name per slot. ssh.exe must agree on all four.
func TestSSHPeerExecLegacy(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, true)
	server, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", legacyKex, "-cipher", legacyCipher, "-mac", legacyMAC, "-host-key-alg", legacyHost)
	known := files.knownHosts(t, "known", port, files.hostPub)
	args := files.sshArgs(known, port, append(legacySSHOptions(), "-v", "training@127.0.0.1", "echo", "old")...)
	stdout, stderr, code := runTool(t, ssh, args...)
	if code != 0 || strings.TrimSpace(stdout) != "old" {
		t.Fatalf("exit %d stdout %q stderr %s", code, stdout, stderr)
	}
	wantLegacyNames(t, stderr)
	event := server.event(t)
	wantField(t, event, "kex", legacyKex)
	wantField(t, event, "hostKey", legacyHost)
	wantField(t, event, "cipherC2S", legacyCipher)
	wantField(t, event, "macC2S", legacyMAC)
	wantField(t, event, "cipherS2C", legacyCipher)
	wantField(t, event, "macS2C", legacyMAC)
}

// The design section 9 command names no host key algorithm. With an RSA key the
// library still offers ssh-rsa, and a legacy client can pick it.
func TestSSHPeerLegacyDesignCommand(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, true)
	_, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", legacyKex, "-cipher", legacyCipher, "-mac", legacyMAC)
	known := files.knownHosts(t, "known", port, files.hostPub)
	args := files.sshArgs(known, port, append(legacySSHOptions(), "-v", "training@127.0.0.1", "echo", "old")...)
	_, stderr, code := runTool(t, ssh, args...)
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	wantLegacyNames(t, stderr)
}

// The restriction is real: a default ssh.exe finds no common key exchange.
func TestSSHPeerLegacyRefusesModernClient(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, true)
	server, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", legacyKex, "-cipher", legacyCipher, "-mac", legacyMAC, "-host-key-alg", legacyHost)
	known := files.knownHosts(t, "known", port, files.hostPub)
	_, stderr, code := runTool(t, ssh, files.sshArgs(known, port, "training@127.0.0.1", "echo", "x")...)
	if code == 0 {
		t.Fatal("a modern client connected to the legacy-only server")
	}
	wantContains(t, stderr, "no matching key exchange method")
	wantField(t, server.event(t), "code", "SSH_HANDSHAKE_FAILED")
}

func TestSSHPeerOnlyEchoExists(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, false)
	server, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized)
	known := files.knownHosts(t, "known", port, files.hostPub)

	_, stderr, code := runTool(t, ssh, files.sshArgs(known, port, "training@127.0.0.1", "whoami")...)
	if code != 127 {
		t.Fatalf("exit %d, want 127; stderr %s", code, stderr)
	}
	wantContains(t, stderr, "only the echo command exists")
	server.event(t) // handshake
	event := server.event(t)
	wantField(t, event, "command", "whoami")
	wantField(t, event, "exit", 127)

	// No command means a shell request, and the server has no shell.
	_, stderr, code = runTool(t, ssh, files.sshArgs(known, port, "training@127.0.0.1")...)
	if code == 0 {
		t.Fatalf("a shell session succeeded; stderr %s", stderr)
	}
	wantContains(t, stderr, "shell request failed")
}

// A -L tunnel through ssh.exe in the design section 9 form, plus a refused target.
func TestSSHPeerTunnelWithSSHExe(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, false)
	target := echoServer(t)
	server, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", "curve25519-sha256", "-allow-tunnel", fmt.Sprintf("127.0.0.1:%d", target))
	known := files.knownHosts(t, "known", port, files.hostPub)

	allowed, refused := freePort(t), freePort(t)
	blocked := freePort(t)
	start(t, ssh, files.sshArgs(known, port,
		"-L", fmt.Sprintf("%d:127.0.0.1:%d", allowed, target),
		"-L", fmt.Sprintf("%d:127.0.0.1:%d", refused, blocked),
		"-N", "training@127.0.0.1")...)

	conn := dialRetry(t, allowed)
	defer conn.Close()
	message := []byte("through the tunnel")
	if got := roundTrip(t, conn, message); string(got) != string(message) {
		t.Fatalf("echo %q", got)
	}
	server.waitFor(t, `"allowed":true`)

	denied := dialRetry(t, refused)
	defer denied.Close()
	buf := make([]byte, 1)
	if n, err := denied.Read(buf); err == nil {
		t.Fatalf("refused tunnel returned %d bytes", n)
	}
	server.waitFor(t, `"allowed":false`)
}

// A changed host key, seen by ssh.exe, beside a control that connects.
func TestSSHPeerChangedHostKeyWithSSHExe(t *testing.T) {
	ssh := sshPath(t)
	files := newSSHFiles(t, false)
	_, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized)

	right := files.knownHosts(t, "right", port, files.hostPub)
	stdout, stderr, code := runTool(t, ssh, files.sshArgs(right, port, "training@127.0.0.1", "echo", "control")...)
	if code != 0 || strings.TrimSpace(stdout) != "control" {
		t.Fatalf("control: exit %d stdout %q stderr %s", code, stdout, stderr)
	}

	_, otherPub := ed25519Identity(t)
	wrong := files.knownHosts(t, "wrong", port, otherPub)
	_, stderr, code = runTool(t, ssh, files.sshArgs(wrong, port, "training@127.0.0.1", "echo", "attack")...)
	if code == 0 {
		t.Fatal("ssh.exe connected with a changed host key")
	}
	wantContains(t, stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED")
}

// Client mode has no independent server on this machine: there is no sshd, and
// ssh.exe is client only. These tests pair it with sshpeer's server, so they prove
// the flags and the named results, and they are not an independent anchor.
func TestSSHPeerClientModeNamedResults(t *testing.T) {
	files := newSSHFiles(t, true)
	target := echoServer(t)
	_, port := startServer(t, "sshpeer", "-host-key", files.hostKey, "-authorized", files.authorized,
		"-kex", legacyKex, "-cipher", legacyCipher, "-mac", legacyMAC, "-host-key-alg", legacyHost,
		"-allow-tunnel", fmt.Sprintf("127.0.0.1:%d", target))
	connect := fmt.Sprintf("127.0.0.1:%d", port)
	right := files.knownHosts(t, "right", port, files.hostPub)
	_, otherPub := ed25519Identity(t)
	wrong := files.knownHosts(t, "wrong", port, otherPub)
	empty := writeFile(t, files.dir, "empty", nil)
	otherIdentity, _ := ed25519Identity(t)
	stranger := writeFile(t, files.dir, "stranger.key", otherIdentity)

	legacy := []string{"-kex", legacyKex, "-cipher", legacyCipher, "-mac", legacyMAC, "-host-key-alg", legacyHost}
	client := func(identity, known string, rest ...string) []string {
		args := []string{"-mode", "client", "-connect", connect, "-identity", identity, "-known-host", known}
		return append(append(args, legacy...), rest...)
	}

	t.Run("exec control", func(t *testing.T) {
		stdout, stderr, code := runTool(t, referee("sshpeer"), client(files.userKey, right, "-exec", "echo hi")...)
		if code != 0 || !strings.HasSuffix(stdout, "hi\n") {
			t.Fatalf("exit %d stdout %q stderr %s", code, stdout, stderr)
		}
	})
	t.Run("tunnel control", func(t *testing.T) {
		p := start(t, referee("sshpeer"), client(files.userKey, right, "-tunnel", fmt.Sprintf("127.0.0.1:%d", target))...)
		wantField(t, p.event(t), "kex", legacyKex)
		if _, err := p.stdin.Write([]byte("tunnel line\n")); err != nil {
			t.Fatal(err)
		}
		p.waitFor(t, "tunnel line")
	})

	rejections := []struct {
		name, identity, known, code string
		rest                        []string
	}{
		{"changed host key", files.userKey, wrong, "HOST_KEY_CHANGED", []string{"-exec", "echo hi"}},
		{"unknown host key", files.userKey, empty, "HOST_KEY_UNKNOWN", []string{"-exec", "echo hi"}},
		{"unknown user key", stranger, right, "SSH_AUTH_FAILED", []string{"-exec", "echo hi"}},
		{"no such command", files.userKey, right, "EXEC_FAILED", []string{"-exec", "whoami"}},
		{"tunnel not allowed", files.userKey, right, "TUNNEL_REFUSED", []string{"-tunnel", "127.0.0.1:1"}},
	}
	for _, rejection := range rejections {
		t.Run(rejection.name, func(t *testing.T) {
			stdout, _, code := runTool(t, referee("sshpeer"), client(rejection.identity, rejection.known, rejection.rest...)...)
			wantField(t, lastJSON(t, stdout), "code", rejection.code)
			if code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
		})
	}
}

func legacySSHOptions() []string {
	return []string{
		"-o", "KexAlgorithms=" + legacyKex,
		"-o", "Ciphers=" + legacyCipher,
		"-o", "MACs=" + legacyMAC,
		"-o", "HostKeyAlgorithms=" + legacyHost,
	}
}

func wantLegacyNames(t *testing.T, sshVerbose string) {
	t.Helper()
	wantContains(t, sshVerbose, "kex: algorithm: "+legacyKex)
	wantContains(t, sshVerbose, "kex: host key algorithm: "+legacyHost)
	wantContains(t, sshVerbose, "kex: server->client cipher: "+legacyCipher+" MAC: "+legacyMAC)
	wantContains(t, sshVerbose, "kex: client->server cipher: "+legacyCipher+" MAC: "+legacyMAC)
}

func wantContains(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("want %q in:\n%s", want, text)
	}
}
