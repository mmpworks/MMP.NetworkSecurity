// Package sshconf builds the SSH server configuration that sshpeer and
// gogateway share, and reports the algorithms a connection negotiated.
package sshconf

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"mmpworks.local/netsec/referees/internal/report"
)

// Algorithms holds the flags that restrict negotiation. An empty value leaves
// the library default in place.
type Algorithms struct {
	Kex        string
	Cipher     string
	MAC        string
	HostKeyAlg string
}

// Register adds the algorithm flags to fs.
func (a *Algorithms) Register(fs *flag.FlagSet) {
	fs.StringVar(&a.Kex, "kex", "", "key exchange names, comma separated")
	fs.StringVar(&a.Cipher, "cipher", "", "cipher names, comma separated")
	fs.StringVar(&a.MAC, "mac", "", "MAC names, comma separated")
	fs.StringVar(&a.HostKeyAlg, "host-key-alg", "", "host key signature names, comma separated")
}

// Apply writes the restrictions into a library config. The library accepts
// insecure names such as aes128-cbc only when a caller lists them, and this is
// where the listing happens.
func (a Algorithms) Apply(cfg *ssh.Config) {
	cfg.KeyExchanges = split(a.Kex)
	cfg.Ciphers = split(a.Cipher)
	cfg.MACs = split(a.MAC)
}

// HostKeyAlgs returns the -host-key-alg list.
func (a Algorithms) HostKeyAlgs() []string {
	return split(a.HostKeyAlg)
}

func split(list string) []string {
	if list == "" {
		return nil
	}
	return strings.Split(list, ",")
}

// Server holds the flags for an SSH listener.
type Server struct {
	Algorithms
	Listen     string
	HostKey    string
	Authorized string
	Naccept    int
}

// Register adds the listener flags to fs.
func (s *Server) Register(fs *flag.FlagSet) {
	s.Algorithms.Register(fs)
	fs.StringVar(&s.Listen, "listen", "127.0.0.1:0", "address to listen on")
	fs.StringVar(&s.HostKey, "host-key", "", "host private key file (OpenSSH or PEM)")
	fs.StringVar(&s.Authorized, "authorized", "", "authorized public keys file")
	fs.IntVar(&s.Naccept, "naccept", 0, "exit after this many connections (0: run until killed)")
}

// Config loads the keys and returns a public-key-only server configuration.
func (s *Server) Config() (*ssh.ServerConfig, error) {
	if s.HostKey == "" || s.Authorized == "" {
		return nil, errors.New("server needs -host-key and -authorized")
	}
	allowed, err := readAuthorized(s.Authorized)
	if err != nil {
		return nil, err
	}
	signer, err := s.hostSigner()
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: allowListed(allowed)}
	s.Apply(&cfg.Config)
	cfg.AddHostKey(signer)
	return cfg, nil
}

// hostSigner restricts the host key to -host-key-alg when named. Without the
// flag, the library offers rsa-sha2-256, rsa-sha2-512, and ssh-rsa for an RSA
// key, and the client picks.
func (s *Server) hostSigner() (ssh.Signer, error) {
	pem, err := os.ReadFile(s.HostKey)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.HostKey, err)
	}
	algs := s.HostKeyAlgs()
	if algs == nil {
		return signer, nil
	}
	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("%s: key type cannot choose a signature algorithm", s.HostKey)
	}
	return ssh.NewSignerWithAlgorithms(algSigner, algs)
}

func readAuthorized(path string) (map[string]bool, error) {
	rest, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for len(rest) > 0 {
		key, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break // ParseAuthorizedKey reports end of input as an error.
		}
		allowed[string(key.Marshal())] = true
		rest = next
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no keys in %s", path)
	}
	return allowed, nil
}

func allowListed(allowed map[string]bool) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if allowed[string(key.Marshal())] {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("key not authorized")
	}
}

// Handshake is the JSON line printed after an SSH handshake finishes.
type Handshake struct {
	Event     string `json:"event"`
	Role      string `json:"role"`
	User      string `json:"user"`
	Peer      string `json:"peerVersion"`
	Kex       string `json:"kex"`
	HostKey   string `json:"hostKey"`
	CipherC2S string `json:"cipherC2S"`
	MACC2S    string `json:"macC2S"`
	CipherS2C string `json:"cipherS2C"`
	MACS2C    string `json:"macS2C"`
}

// Describe reads the negotiated algorithms from the connection. The library
// names the directions read and write, so the role maps them to c2s and s2c.
func Describe(role, peerVersion string, conn ssh.ConnMetadata) Handshake {
	h := Handshake{Event: "handshake", Role: role, User: conn.User(), Peer: peerVersion}
	meta, ok := conn.(ssh.AlgorithmsConnMetadata)
	if !ok {
		return h
	}
	algs := meta.Algorithms()
	h.Kex, h.HostKey = algs.KeyExchange, algs.HostKey
	c2s, s2c := algs.Read, algs.Write
	if role == "client" {
		c2s, s2c = s2c, c2s
	}
	h.CipherC2S, h.MACC2S = c2s.Cipher, c2s.MAC
	h.CipherS2C, h.MACS2C = s2c.Cipher, s2c.MAC
	return h
}

// Handle runs the server handshake on raw, reports it, and passes each new
// channel to onChannel on its own goroutine. Global requests get the library's
// refusal. It returns when the client disconnects.
func Handle(raw net.Conn, cfg *ssh.ServerConfig, onChannel func(ssh.NewChannel)) {
	conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		report.Error(handshakeCode(err), err)
		return
	}
	defer conn.Close()
	report.Event(Describe("server", string(conn.ClientVersion()), conn.Conn))
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		go onChannel(channel)
	}
}

func handshakeCode(err error) string {
	if strings.Contains(err.Error(), "no auth passed yet") || strings.Contains(err.Error(), "key not authorized") {
		return "SSH_AUTH_FAILED"
	}
	return "SSH_HANDSHAKE_FAILED"
}
