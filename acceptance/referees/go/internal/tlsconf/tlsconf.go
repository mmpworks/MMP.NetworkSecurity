// Package tlsconf builds the TLS 1.3 configurations that tlspeer and gogateway
// share, and reports a finished handshake as the JSON line the suite reads.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Options holds the flags both tools accept.
type Options struct {
	Groups     string
	Cert       string
	Key        string
	CA         string
	ServerName string
	KeyLog     string
	Insecure   bool
	Tls11Suite string
}

// Register adds the shared flags to fs. defaultGroup is the group a tool uses
// when the caller names none.
func (o *Options) Register(fs *flag.FlagSet, defaultGroup string) {
	fs.StringVar(&o.Groups, "groups", defaultGroup, "key exchange group: x25519 or x25519mlkem768")
	fs.StringVar(&o.Cert, "cert", "", "certificate PEM file")
	fs.StringVar(&o.Key, "key", "", "private key PEM file")
	fs.StringVar(&o.CA, "ca", "", "CA PEM file: server names to trust, or client certs to accept")
	fs.StringVar(&o.ServerName, "server-name", "", "name to verify on the server certificate (default: the host dialed)")
	fs.StringVar(&o.KeyLog, "keylog", "", "append NSS key log lines to this file")
	fs.BoolVar(&o.Insecure, "insecure", false, "client: skip server certificate verification")
	fs.StringVar(&o.Tls11Suite, "tls11-suite", "", "client: speak TLS 1.1 and offer only this suite, by its Go name. OpenSSL 3.5 has no 3DES, so A18 asks Go")
}

// Client returns a client configuration pinned to TLS 1.3 and the named group.
// A client with no -ca and no -insecure is a usage error, so a run never
// falls back to the machine's trust store by accident.
func (o *Options) Client(host string) (*tls.Config, error) {
	cfg, err := o.base()
	if err != nil {
		return nil, err
	}
	if o.Tls11Suite != "" {
		id, err := insecureSuite(o.Tls11Suite)
		if err != nil {
			return nil, err
		}
		cfg.MinVersion, cfg.MaxVersion, cfg.CipherSuites = tls.VersionTLS11, tls.VersionTLS11, []uint16{id}
	}
	cfg.ServerName = o.ServerName
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	cfg.InsecureSkipVerify = o.Insecure
	if o.CA == "" {
		if !o.Insecure {
			return nil, errors.New("client needs -ca or -insecure")
		}
		return cfg, nil
	}
	cfg.RootCAs, err = loadPool(o.CA)
	return cfg, err
}

// Server returns a server configuration pinned to TLS 1.3 and the named group.
func (o *Options) Server(requireClientCert bool) (*tls.Config, error) {
	cfg, err := o.base()
	if err != nil {
		return nil, err
	}
	if len(cfg.Certificates) == 0 {
		return nil, errors.New("server needs -cert and -key")
	}
	if !requireClientCert {
		return cfg, nil
	}
	if o.CA == "" {
		return nil, errors.New("-require-client-cert needs -ca")
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs, err = loadPool(o.CA)
	return cfg, err
}

// insecureSuite finds a suite by name in the library's lists.
func insecureSuite(name string) (uint16, error) {
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if s.Name == name {
			return s.ID, nil
		}
	}
	return 0, errors.New("the library has no suite named " + name)
}

func (o *Options) base() (*tls.Config, error) {
	group, err := curve(o.Groups)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{group},
	}
	if err := o.loadIdentity(cfg); err != nil {
		return nil, err
	}
	return cfg, o.openKeyLog(cfg)
}

func (o *Options) loadIdentity(cfg *tls.Config) error {
	if o.Cert == "" && o.Key == "" {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(o.Cert, o.Key)
	if err != nil {
		return err
	}
	cfg.Certificates = []tls.Certificate{pair}
	return nil
}

func (o *Options) openKeyLog(cfg *tls.Config) error {
	if o.KeyLog == "" {
		return nil
	}
	file, err := os.OpenFile(o.KeyLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// The file stays open for the life of the process. Each write goes straight
	// to the OS, so a killed referee still leaves a complete log.
	cfg.KeyLogWriter = file
	return nil
}

func curve(name string) (tls.CurveID, error) {
	switch strings.ToLower(name) {
	case "x25519":
		return tls.X25519, nil
	case "x25519mlkem768":
		return tls.X25519MLKEM768, nil
	}
	return 0, fmt.Errorf("unknown group %q", name)
}

func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return pool, nil
}

// Handshake is the JSON line printed after a handshake finishes.
type Handshake struct {
	Event       string `json:"event"`
	Role        string `json:"role"`
	Version     string `json:"version"`
	VersionCode uint16 `json:"versionCode"`
	Suite       string `json:"suite"`
	SuiteCode   uint16 `json:"suiteCode"`
	CurveID     string `json:"curveID"`
	CurveIDCode uint16 `json:"curveIDCode"`
	PeerSubject string `json:"peerSubject,omitempty"`
}

// Describe reads the negotiated values from ConnectionState, the library's own
// record of the session.
func Describe(role string, state tls.ConnectionState) Handshake {
	h := Handshake{
		Event:       "handshake",
		Role:        role,
		Version:     tls.VersionName(state.Version),
		VersionCode: state.Version,
		Suite:       tls.CipherSuiteName(state.CipherSuite),
		SuiteCode:   state.CipherSuite,
		CurveID:     state.CurveID.String(),
		CurveIDCode: uint16(state.CurveID),
	}
	if len(state.PeerCertificates) > 0 {
		h.PeerSubject = state.PeerCertificates[0].Subject.String()
	}
	return h
}

// FailureCode names a handshake error. Go exposes no typed error for a missing
// client certificate, so that one case matches the library's fixed message.
func FailureCode(err error) string {
	var verify *tls.CertificateVerificationError
	switch {
	case errors.As(err, &verify):
		return "TLS_CERT_VERIFY_FAILED"
	case strings.Contains(err.Error(), "didn't provide a certificate"):
		return "TLS_CLIENT_CERT_MISSING"
	}
	return "TLS_HANDSHAKE_FAILED"
}
