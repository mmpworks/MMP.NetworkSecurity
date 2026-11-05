package main

import (
	"net"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"mmpworks.local/netsec/referees/internal/report"
	"mmpworks.local/netsec/referees/internal/sshconf"
	"mmpworks.local/netsec/referees/internal/wire"
)

type serverOptions struct {
	sshconf.Server
	allowTunnel string
}

type tunnelEvent struct {
	Event   string `json:"event"`
	Target  string `json:"target"`
	Allowed bool   `json:"allowed"`
}

type execEvent struct {
	Event   string `json:"event"`
	Command string `json:"command"`
	Exit    uint32 `json:"exit"`
}

func (s *serverOptions) run() error {
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	ln, err := wire.Listen(s.Listen)
	if err != nil {
		return err
	}
	allowed := strings.Split(s.allowTunnel, ",")
	return wire.Serve(ln, s.Naccept, func(raw net.Conn) {
		sshconf.Handle(raw, cfg, func(channel ssh.NewChannel) {
			route(channel, allowed)
		})
	})
}

func route(channel ssh.NewChannel, allowed []string) {
	switch channel.ChannelType() {
	case "session":
		serveSession(channel)
	case "direct-tcpip":
		serveTunnel(channel, allowed)
	default:
		_ = channel.Reject(ssh.UnknownChannelType, "only session and direct-tcpip")
	}
}

// serveSession answers exec and refuses shell, pty, subsystem, and env. One
// exec ends the session, as it does on an OpenSSH server.
func serveSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)
		runExec(channel, request.Payload)
		return
	}
}

func runExec(channel ssh.Channel, payload []byte) {
	var msg struct{ Command string }
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		report.Error("SSH_BAD_EXEC", err)
		return
	}
	output, exit := answer(msg.Command)
	if exit == 0 {
		_, _ = channel.Write([]byte(output))
	} else {
		_, _ = channel.Stderr().Write([]byte(output))
	}
	report.Event(execEvent{Event: "exec", Command: msg.Command, Exit: exit})
	status := struct{ Status uint32 }{exit}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(status))
}

// answer is the entire command language: echo and its arguments. The text after
// "echo " comes back unchanged, with no shell parsing of any kind.
func answer(command string) (string, uint32) {
	if command == "echo" {
		return "\n", 0
	}
	if text, ok := strings.CutPrefix(command, "echo "); ok {
		return text + "\n", 0
	}
	return "sshpeer: only the echo command exists\n", 127
}

func serveTunnel(newChannel ssh.NewChannel, allowed []string) {
	var msg struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}
	target := net.JoinHostPort(msg.Host, strconv.FormatUint(uint64(msg.Port), 10))
	permitted := slices.Contains(allowed, target)
	report.Event(tunnelEvent{Event: "tunnel", Target: target, Allowed: permitted})
	if !permitted {
		_ = newChannel.Reject(ssh.Prohibited, "target not in -allow-tunnel")
		return
	}
	joinTarget(newChannel, target)
}

func joinTarget(newChannel ssh.NewChannel, target string) {
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
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
