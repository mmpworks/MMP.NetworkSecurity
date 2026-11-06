package main

import (
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/sshconf"
	"mmpworks.local/netsec/referees/internal/wire"
)

func (c *clientOptions) run() error {
	if err := c.validate(); err != nil {
		return err
	}
	var hostKeyCode string
	cfg, err := c.config(&hostKeyCode)
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", c.connect)
	if err != nil {
		report.Reject(codeConnect, err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, c.connect, cfg)
	if err != nil {
		report.Reject(clientFailureCode(hostKeyCode, err), err)
	}
	report.Event(sshconf.Describe("client", string(conn.ServerVersion()), conn))
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	if c.exec != "" {
		c.runExec(client)
		return nil
	}
	c.runTunnel(client)
	return nil
}

func (c *clientOptions) validate() error {
	switch {
	case c.connect == "" || c.identity == "" || c.knownHost == "":
		return errors.New("client needs -connect, -identity, and -known-host")
	case (c.exec == "") == (c.tunnel == ""):
		return errors.New("client needs one of -exec or -tunnel")
	}
	return nil
}

func (c *clientOptions) config(hostKeyCode *string) (*ssh.ClientConfig, error) {
	pem, err := os.ReadFile(c.identity)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, err
	}
	known, err := knownhosts.New(c.knownHost)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:              c.user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   recordHostKeyFailure(known, hostKeyCode),
		HostKeyAlgorithms: c.algorithms.HostKeyAlgs(),
	}
	c.algorithms.Apply(&cfg.Config)
	if c.password != "" {
		cfg.Auth = []ssh.AuthMethod{ssh.Password(c.password)}
	}
	cfg.RekeyThreshold = c.rekeyBytes
	return cfg, nil
}

// recordHostKeyFailure wraps the known_hosts check. It writes the verdict to
// code before the library folds the error into its handshake failure, so the
// named result does not depend on that wrapping.
func recordHostKeyFailure(known ssh.HostKeyCallback, code *string) ssh.HostKeyCallback {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := known(host, remote, key)
		*code = hostKeyCode(err)
		return err
	}
}

func hostKeyCode(err error) string {
	var mismatch *knownhosts.KeyError
	if !errors.As(err, &mismatch) {
		return ""
	}
	if len(mismatch.Want) > 0 {
		return codeHostKeyChanged
	}
	return codeHostKeyUnknown
}

func clientFailureCode(hostKeyCode string, err error) string {
	if hostKeyCode != "" {
		return hostKeyCode
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return codeAuthFailed
	}
	return codeHandshake
}

// runExec prints the command's stdout unchanged and exits with its status.
func (c *clientOptions) runExec(client *ssh.Client) {
	session, err := client.NewSession()
	if err != nil {
		report.Reject(codeExecFailed, err)
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	if err := session.Run(c.exec); err != nil {
		report.Reject(codeExecFailed, err)
	}
}

func (c *clientOptions) runTunnel(client *ssh.Client) {
	channel, err := client.Dial("tcp", c.tunnel)
	if err != nil {
		report.Reject(codeTunnelRefused, err)
	}
	defer channel.Close()
	wire.Stdio(channel)
}
