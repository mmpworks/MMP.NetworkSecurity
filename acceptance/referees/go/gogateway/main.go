// Command gogateway is the Go referee for the lab gateway. It terminates SSH
// from the device and opens TLS 1.3 with X25519MLKEM768 to the next hop. Bytes
// pass through unopened: the gateway never parses what it forwards.
//
// Each direct-tcpip channel becomes one TLS session to -next. The target the
// device asks for is reported and otherwise ignored, because -next is fixed.
// The gateway offers no sessions and runs no commands.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/sshconf"
	"mmpworks.local/netsec/referees/internal/tlsconf"
	"mmpworks.local/netsec/referees/internal/wire"
)

const nextHopLimit = 30 * time.Second

type channelEvent struct {
	Event  string `json:"event"`
	Target string `json:"target"`
}

func main() {
	var device sshconf.Server
	var hop tlsconf.Options
	var next string
	device.Register(flag.CommandLine)
	hop.Register(flag.CommandLine, "x25519mlkem768")
	flag.StringVar(&next, "next", "", "next hop host:port, reached over TLS 1.3")
	flag.Parse()
	if err := run(&device, &hop, next); err != nil {
		report.Usage(err)
	}
}

func run(device *sshconf.Server, hop *tlsconf.Options, next string) error {
	host, _, err := net.SplitHostPort(next)
	if err != nil {
		return fmt.Errorf("-next: %w", err)
	}
	tlsConfig, err := hop.Client(host)
	if err != nil {
		return err
	}
	sshConfig, err := device.Config()
	if err != nil {
		return err
	}
	ln, err := wire.Listen(device.Listen)
	if err != nil {
		return err
	}
	return wire.Serve(ln, device.Naccept, func(raw net.Conn) {
		sshconf.Handle(raw, sshConfig, func(channel ssh.NewChannel) {
			forward(channel, tlsConfig, next)
		})
	})
}

// forward opens the next hop first. A refused next hop then reaches the device
// as a channel rejection.
func forward(newChannel ssh.NewChannel, tlsConfig *tls.Config, next string) {
	if newChannel.ChannelType() != "direct-tcpip" {
		_ = newChannel.Reject(ssh.Prohibited, "gateway offers tunnels only")
		return
	}
	report.Event(channelEvent{Event: "channel", Target: requestedTarget(newChannel)})
	upstream, err := dialNextHop(tlsConfig, next)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "next hop refused")
		return
	}
	defer upstream.Close()
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	wire.Join(channel, upstream)
}

func requestedTarget(channel ssh.NewChannel) string {
	var msg struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(channel.ExtraData(), &msg); err != nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", msg.Host, msg.Port)
}

func dialNextHop(cfg *tls.Config, next string) (*tls.Conn, error) {
	raw, err := net.Dial("tcp", next)
	if err != nil {
		report.Error("NEXT_HOP_CONNECT_FAILED", err)
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), nextHopLimit)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		report.Error(tlsconf.FailureCode(err), err)
		_ = raw.Close()
		return nil, err
	}
	report.Event(tlsconf.Describe("client", conn.ConnectionState()))
	return conn, nil
}
