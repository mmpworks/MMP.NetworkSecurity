// Command sshpeer is an SSH-2 referee on golang.org/x/crypto/ssh.
//
// The server mode answers one exec command, echo, inside this process. It
// starts no shell and no other process. It opens direct-tcpip tunnels only to
// the addresses named in -allow-tunnel.
//
// The client mode tests a server under test: one exec or one tunnel, with the
// host key checked against -known-host.
package main

import (
	"flag"
	"fmt"

	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/sshconf"
)

func main() {
	var mode string
	var server serverOptions
	var client clientOptions
	flag.StringVar(&mode, "mode", "server", "client or server")
	server.Register(flag.CommandLine)
	flag.StringVar(&server.allowTunnel, "allow-tunnel", "", "server: tunnel targets, host:port, comma separated")
	client.register(flag.CommandLine, &server.Algorithms)
	flag.Parse()

	var err error
	switch mode {
	case "server":
		err = server.run()
	case "client":
		err = client.run()
	default:
		err = fmt.Errorf("unknown -mode %q", mode)
	}
	if err != nil {
		report.Usage(err)
	}
}

// Named results the client mode can return.
const (
	codeHostKeyChanged = "HOST_KEY_CHANGED"
	codeHostKeyUnknown = "HOST_KEY_UNKNOWN"
	codeAuthFailed     = "SSH_AUTH_FAILED"
	codeHandshake      = "SSH_HANDSHAKE_FAILED"
	codeConnect        = "TCP_CONNECT_FAILED"
	codeTunnelRefused  = "TUNNEL_REFUSED"
	codeExecFailed     = "EXEC_FAILED"
)

// clientOptions reads the algorithm flags that the server mode registers.
type clientOptions struct {
	algorithms *sshconf.Algorithms
	connect    string
	user       string
	identity   string
	knownHost  string
	exec       string
	tunnel     string
}

func (c *clientOptions) register(fs *flag.FlagSet, shared *sshconf.Algorithms) {
	c.algorithms = shared
	fs.StringVar(&c.connect, "connect", "", "client: host:port to dial")
	fs.StringVar(&c.user, "user", "training", "client: user name")
	fs.StringVar(&c.identity, "identity", "", "client: private key file")
	fs.StringVar(&c.knownHost, "known-host", "", "client: known_hosts file")
	fs.StringVar(&c.exec, "exec", "", "client: command to run")
	fs.StringVar(&c.tunnel, "tunnel", "", "client: host:port to reach through the server, joined to stdin and stdout")
}
