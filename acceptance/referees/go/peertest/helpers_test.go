package peertest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const waitLimit = 20 * time.Second

// binDir holds the referees, built once for the run from the module root.
var binDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "referees-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binDir = dir
	build := exec.Command("go", "build", "-o", dir+string(os.PathSeparator), "./...")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func referee(name string) string {
	return filepath.Join(binDir, name+".exe")
}

// Pinned independent peers. The version string is part of the pin (design
// section 9), so a different binary fails the test instead of passing quietly.
func pinned(t *testing.T, envName, fallback, wantVersion string, versionArgs ...string) string {
	t.Helper()
	path := os.Getenv(envName)
	if path == "" {
		path = fallback
	}
	out, err := exec.Command(path, versionArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", path, versionArgs, err, out)
	}
	if !strings.Contains(string(out), wantVersion) {
		t.Fatalf("%s reports %q, pin is %q", path, out, wantVersion)
	}
	return path
}

func opensslPath(t *testing.T) string {
	return pinned(t, "NETSEC_OPENSSL", `C:\Program Files\Git\mingw64\bin\openssl.exe`, "OpenSSL 3.5.7", "version")
}

func sshPath(t *testing.T) string {
	return pinned(t, "NETSEC_SSH", `C:\Windows\System32\OpenSSH\ssh.exe`, "OpenSSH_for_Windows_9.5p2", "-V")
}

// proc is a child process with stdout delivered line by line. Cleanup kills it.
type proc struct {
	cmd    *exec.Cmd
	lines  chan string
	stdin  io.WriteCloser
	stderr *safeBuffer
	done   chan error
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func start(t *testing.T, path string, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(path, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: cmd, lines: make(chan string, 1024), stdin: stdin, stderr: &safeBuffer{}, done: make(chan error, 1)}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			p.lines <- strings.TrimRight(scanner.Text(), "\r")
		}
		close(p.lines)
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = stdin.Close()
	})
	return p
}

// startServer starts a referee server and reads the port from its first line.
func startServer(t *testing.T, name string, args ...string) (*proc, int) {
	t.Helper()
	p := start(t, referee(name), args...)
	line := p.line(t)
	port, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("%s first line %q is no port; stderr: %s", name, line, p.stderr)
	}
	return p, port
}

func (p *proc) line(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			t.Fatalf("%s ended before the next line; stderr: %s", p.cmd.Path, p.stderr)
		}
		return line
	case <-time.After(waitLimit):
		t.Fatalf("%s: no line within %s; stderr: %s", p.cmd.Path, waitLimit, p.stderr)
	}
	return ""
}

// event returns the next stdout line that parses as a JSON object.
func (p *proc) event(t *testing.T) map[string]any {
	t.Helper()
	for {
		line := p.line(t)
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil {
			return event
		}
	}
}

// waitFor reads lines until one contains text.
func (p *proc) waitFor(t *testing.T, text string) string {
	t.Helper()
	for {
		line := p.line(t)
		if strings.Contains(line, text) {
			return line
		}
	}
}

func (p *proc) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.done:
		return err
	case <-time.After(waitLimit):
		t.Fatalf("%s did not exit; stderr: %s", p.cmd.Path, p.stderr)
	}
	return nil
}

func wantField(t *testing.T, event map[string]any, name string, want any) {
	t.Helper()
	got := event[name]
	if number, ok := got.(float64); ok {
		got = int(number)
	}
	if got != want {
		t.Fatalf("%s = %v, want %v; event %v", name, got, want, event)
	}
}

// runTool runs a short-lived command and returns stdout, stderr, and exit code.
func runTool(t *testing.T, path string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	timer := time.AfterFunc(waitLimit, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	err := cmd.Run()
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("%s: %v", path, err)
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// lastJSON returns the last JSON object in a tool's stdout.
func lastJSON(t *testing.T, stdout string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var event map[string]any
		if json.Unmarshal([]byte(lines[i]), &event) == nil {
			return event
		}
	}
	t.Fatalf("no JSON line in %q", stdout)
	return nil
}

// echoServer is a plain TCP echo target that lives in the test process.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// dialRetry waits for a listener another process is still opening.
func dialRetry(t *testing.T, port int) net.Conn {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %d: %v", port, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// roundTrip sends message and reads the same number of bytes back.
func roundTrip(t *testing.T, conn net.Conn, message []byte) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(waitLimit))
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	return reply
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tlsFiles holds a training CA and two leaves, written to a temp folder.
type tlsFiles struct {
	caCert, srvCert, srvKey, cliCert, cliKey string
}

func newTLSFiles(t *testing.T) tlsFiles {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "referee test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	files := tlsFiles{caCert: writeFile(t, dir, "ca.pem", pemBlock("CERTIFICATE", caDER))}
	files.srvCert, files.srvKey = newLeaf(t, dir, "srv", caCert, caKey, 2)
	files.cliCert, files.cliKey = newLeaf(t, dir, "cli", caCert, caKey, 3)
	return files
}

func newLeaf(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "referee test " + name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, name+".pem", pemBlock("CERTIFICATE", der)),
		writeFile(t, dir, name+".key", pemBlock("PRIV"+"ATE KEY", keyDER))
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

// sshFiles holds one user key and one host key in a temp folder.
type sshFiles struct {
	dir                 string
	userKey, authorized string
	hostKey             string
	hostPub             ssh.PublicKey
}

func newSSHFiles(t *testing.T, rsaHost bool) sshFiles {
	t.Helper()
	dir := t.TempDir()
	userPriv, userPub := ed25519Identity(t)
	files := sshFiles{dir: dir}
	files.userKey = writeFile(t, dir, "user.key", userPriv)
	lockForSSHExe(t, files.userKey)
	files.authorized = writeFile(t, dir, "user.pub", ssh.MarshalAuthorizedKey(userPub))
	hostPriv, hostPub := hostIdentity(t, rsaHost)
	files.hostKey = writeFile(t, dir, "host.key", hostPriv)
	files.hostPub = hostPub
	return files
}

func ed25519Identity(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "referee test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

func hostIdentity(t *testing.T, rsaHost bool) ([]byte, ssh.PublicKey) {
	t.Helper()
	if !rsaHost {
		return ed25519Identity(t)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "referee test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

// lockForSSHExe applies the ACL design section 9 names. Windows ssh.exe refuses
// a private key that other accounts can read.
func lockForSSHExe(t *testing.T, path string) {
	t.Helper()
	grant := os.Getenv("USERNAME") + ":R"
	out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", grant).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v\n%s", err, out)
	}
}

// knownHosts writes a known_hosts file naming key for this port.
func (f sshFiles) knownHosts(t *testing.T, name string, port int, key ssh.PublicKey) string {
	t.Helper()
	line := fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(key))
	return writeFile(t, f.dir, name, []byte(line))
}

// sshArgs is the design section 9 command line, plus extra -o options.
func (f sshFiles) sshArgs(knownHosts string, port int, extra ...string) []string {
	args := []string{
		"-F", "NUL", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts, "-i", f.userKey, "-p", strconv.Itoa(port),
	}
	return append(args, extra...)
}

// parseTapLog returns the bytes per direction for one connection.
func parseTapLog(t *testing.T, path string, conn int) map[string][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record := regexp.MustCompile(`^(?<conn>\d+) (?<dir>c2s|s2c) (?<offset>\d+) (?<hex>[0-9a-f]+)$`)
	streams := map[string][]byte{}
	for _, line := range strings.Split(string(data), "\n") {
		match := record.FindStringSubmatch(line)
		if match == nil || match[record.SubexpIndex("conn")] != strconv.Itoa(conn) {
			continue
		}
		dir := match[record.SubexpIndex("dir")]
		offset, _ := strconv.Atoi(match[record.SubexpIndex("offset")])
		if offset != len(streams[dir]) {
			t.Fatalf("%s offset %d, have %d bytes", dir, offset, len(streams[dir]))
		}
		streams[dir] = append(streams[dir], decodeHex(t, match[record.SubexpIndex("hex")])...)
	}
	return streams
}
