using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Machine;

namespace NetSec.Ssh
{
    /// <summary>The table rows both roles share: the messages RFC 4253 allows at any time, and the connection layer of RFC 4254.</summary>
    internal static class SshRows
    {
        const long FirstWindow = 2097152, LowWindow = 1048576;
        const int OurMaxPacket = 32768;
        const int ExitNotFound = 127;

        public static void AddAnyTime(List<StepRow<SshSession>> rows, string prefix, params string[] states)
        {
            for (int i = 0; i < states.Length; i++)
            {
                rows.Add(new StepRow<SshSession>(prefix + ".ignore", states[i], SshMsg.Ignore, Nothing, states[i]));
                rows.Add(new StepRow<SshSession>(prefix + ".debug", states[i], SshMsg.Debug, Nothing, states[i]));
                rows.Add(new StepRow<SshSession>(prefix + ".unimplemented", states[i], SshMsg.Unimplemented, Nothing, states[i]));
                rows.Add(new StepRow<SshSession>(prefix + ".ext-info", states[i], SshMsg.ExtInfo, Nothing, states[i]));
                rows.Add(new StepRow<SshSession>(prefix + ".disconnect", states[i], SshMsg.Disconnect, Disconnected, MachineStates.Closed));
            }
        }

        public static void AddConnection(List<StepRow<SshSession>> rows, string prefix)
        {
            string open = MachineStates.Open;
            rows.Add(new StepRow<SshSession>(prefix + ".local", open, InboundMessage.StartType, Local, MachineStates.Closed));
            rows.Add(new StepRow<SshSession>(prefix + ".rekey", open, SshMsg.KexInit, Rekey, open));
            rows.Add(new StepRow<SshSession>(prefix + ".global", open, SshMsg.GlobalRequest, GlobalRequest, open));
            rows.Add(new StepRow<SshSession>(prefix + ".request-done", open, SshMsg.RequestSuccess, Nothing, open));
            rows.Add(new StepRow<SshSession>(prefix + ".request-done", open, SshMsg.RequestFailure, Nothing, open));
            rows.Add(new StepRow<SshSession>("chan.window", open, SshMsg.ChannelWindowAdjust, WindowAdjust, open));
            rows.Add(new StepRow<SshSession>("chan.data", open, SshMsg.ChannelData, Data, open));
            rows.Add(new StepRow<SshSession>("chan.data", open, SshMsg.ChannelExtendedData, ExtendedData, open));
            rows.Add(new StepRow<SshSession>("chan.eof", open, SshMsg.ChannelEof, Eof, open));
            rows.Add(new StepRow<SshSession>("chan.close", open, SshMsg.ChannelClose, Close, open));
        }

        static StepDecision Nothing(SshSession s, InboundMessage m) { return StepDecision.Stay(); }

        static StepDecision Disconnected(SshSession s, InboundMessage m)
        {
            if (s.IsOpen) return StepDecision.Advance();
            return StepDecision.Fail(SshCodes.PeerDisconnect, SshChecks.PeerStayed, "the peer sent Disconnect before the handshake ended");
        }

        static StepDecision Rekey(SshSession s, InboundMessage m)
        {
            return StepDecision.Fail(SshCodes.RekeyUnsupported, SshChecks.NoRekey, "the peer asked for a new key exchange, and this lab runs one per session");
        }

        static StepDecision GlobalRequest(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            r.Prefixed("request", "id");
            if (r.U8("wantReply", "data") == 0) return StepDecision.Stay();
            return StepDecision.Stay(s.SealedPacket(SshNames.RequestFailure, new byte[] { (byte)SshMsg.RequestFailure }));
        }

        // ---------------------------------------------------------------- local commands

        /// <summary>A command from the code above enters here, on the start message type, so the interpreter emits no received event for it.</summary>
        static StepDecision Local(SshSession s, InboundMessage m)
        {
            EngineCommand c = s.Pending;
            switch (c.Kind)
            {
                case EngineCommandKind.Close:
                    return StepDecision.Advance(s.SealedPacket(SshNames.Disconnect, new ByteWriter().U8(SshMsg.Disconnect).U32(11).Prefixed("done").Prefixed("").ToArray()));
                case EngineCommandKind.Exec:
                    return StepDecision.Stay(OpenSession(s, c));
                case EngineCommandKind.OpenChannel:
                    return StepDecision.Stay(OpenTunnel(s, c));
                case EngineCommandKind.Send:
                    return StepDecision.Stay(SendOrEnd(s, c));
                default:
                    return StepDecision.Stay();
            }
        }

        static StepEffect OpenSession(SshSession s, EngineCommand c)
        {
            SshChannel channel = AddLocal(s, c.Channel);
            channel.ExecCommand = c.Text;
            byte[] payload = OpenHeader("session", channel).ToArray();
            return s.SealedPacket(SshNames.ChannelOpenSession, payload);
        }

        /// <summary>The text is host:port. A channel opens only after the peer confirms it, so data sent before that waits in the channel's queue.</summary>
        static StepEffect OpenTunnel(SshSession s, EngineCommand c)
        {
            SshChannel channel = AddLocal(s, c.Channel);
            string[] target = c.Text.Split(':');
            byte[] payload = OpenHeader("direct-tcpip", channel)
                .Prefixed(target[0]).U32(int.Parse(target[1]))
                .Prefixed("127.0.0.1").U32(0).ToArray();
            return s.SealedPacket(SshNames.ChannelOpenTunnel, payload);
        }

        static ByteWriter OpenHeader(string kind, SshChannel channel)
        {
            return new ByteWriter().U8(SshMsg.ChannelOpen).Prefixed(kind).U32(channel.Local).U32(channel.OurWindow).U32(OurMaxPacket);
        }

        static SshChannel AddLocal(SshSession s, int local)
        {
            SshChannel channel = new SshChannel();
            channel.Local = local;
            channel.OurWindow = FirstWindow;
            s.Channels[local] = channel;
            return channel;
        }

        /// <summary>A send to a channel that has gone is no failure: a relay's last read can race the peer's close.</summary>
        static StepEffect[] SendOrEnd(SshSession s, EngineCommand c)
        {
            SshChannel channel;
            if (!s.Channels.TryGetValue(c.Channel, out channel)) return new StepEffect[0];
            List<StepEffect> effects = new List<StepEffect>();
            if (c.Bytes == null || c.Bytes.Length == 0) End(s, channel, effects);
            else
            {
                channel.Queue.Add(c.Bytes);
                Drain(s, channel, effects);
            }
            return effects.ToArray();
        }

        // ---------------------------------------------------------------- sending data inside the peer's window

        /// <summary>
        /// Irreducible part of the channel: the peer grants a window of bytes and a largest packet. Each chunk is the smallest of the bytes
        /// left, the window left, and that packet size. Bytes past the window wait in the queue for a window adjust.
        /// </summary>
        public static void Drain(SshSession s, SshChannel channel, List<StepEffect> effects)
        {
            while (channel.Confirmed && channel.Queue.Count > 0 && channel.PeerWindow > 0)
            {
                byte[] head = channel.Queue[0];
                int size = (int)System.Math.Min(System.Math.Min(head.Length, channel.PeerWindow), System.Math.Min(channel.PeerMaxPacket, OurMaxPacket));
                byte[] chunk = new byte[size];
                System.Buffer.BlockCopy(head, 0, chunk, 0, size);
                effects.Add(s.SealedPacket(SshNames.ChannelData, new ByteWriter().U8(SshMsg.ChannelData).U32(channel.Remote).Prefixed(chunk).ToArray()));
                channel.PeerWindow -= size;
                if (size == head.Length) channel.Queue.RemoveAt(0);
                else
                {
                    byte[] rest = new byte[head.Length - size];
                    System.Buffer.BlockCopy(head, size, rest, 0, rest.Length);
                    channel.Queue[0] = rest;
                }
            }
            if (channel.CloseWhenDrained && channel.Queue.Count == 0) End(s, channel, effects);
        }

        /// <summary>This side has no more to send: EOF, then close. The peer's close removes the channel.</summary>
        public static void End(SshSession s, SshChannel channel, List<StepEffect> effects)
        {
            if (channel.SentClose) return;
            if (channel.Queue.Count > 0) { channel.CloseWhenDrained = true; return; }
            channel.SentClose = true;
            effects.Add(s.SealedPacket(SshNames.ChannelEof, new ByteWriter().U8(SshMsg.ChannelEof).U32(channel.Remote).ToArray()));
            effects.Add(s.SealedPacket(SshNames.ChannelClose, new ByteWriter().U8(SshMsg.ChannelClose).U32(channel.Remote).ToArray()));
        }

        // ---------------------------------------------------------------- inbound channel messages

        /// <summary>The channel a message names, or null with the failure in refused.</summary>
        public static SshChannel Find(SshSession s, long local, out StepDecision refused)
        {
            SshChannel channel;
            refused = null;
            if (local <= int.MaxValue && s.Channels.TryGetValue((int)local, out channel)) return channel;
            refused = StepDecision.Fail(SshCodes.ChannelUnknown, SshChecks.ChannelKnown, "the peer named channel " + local + ", which is not open");
            return null;
        }

        static StepDecision WindowAdjust(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            StepDecision refused;
            SshChannel channel = Find(s, r.U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            channel.PeerWindow += r.U32("bytes", "length");
            List<StepEffect> effects = new List<StepEffect>();
            Drain(s, channel, effects);
            return StepDecision.Stay(effects.ToArray());
        }

        static StepDecision Data(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            long recipient = r.U32("recipient", "id");
            return Received(s, recipient, r.Prefixed("data", "data"));
        }

        /// <summary>Extended data is stderr. The lab joins it to the channel's data, because it has one output pane.</summary>
        static StepDecision ExtendedData(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            long recipient = r.U32("recipient", "id");
            r.U32("code", "id");
            return Received(s, recipient, r.Prefixed("data", "data"));
        }

        static StepDecision Received(SshSession s, long recipient, byte[] data)
        {
            StepDecision refused;
            SshChannel channel = Find(s, recipient, out refused);
            if (channel == null) return refused;
            if (data.Length > channel.OurWindow)
                return StepDecision.Fail(SshCodes.ChannelWindow, SshChecks.ChannelWindow, "the peer sent " + data.Length + " bytes into a window of " + channel.OurWindow);
            channel.OurWindow -= data.Length;
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Deliver(channel.Local, data));
            if (channel.OurWindow < LowWindow)
            {
                long grant = FirstWindow - channel.OurWindow;
                channel.OurWindow = FirstWindow;
                effects.Add(s.SealedPacket(SshNames.ChannelWindowAdjust, new ByteWriter().U8(SshMsg.ChannelWindowAdjust).U32(channel.Remote).U32(grant).ToArray()));
            }
            return StepDecision.Stay(effects.ToArray());
        }

        static StepDecision Eof(SshSession s, InboundMessage m)
        {
            StepDecision refused;
            SshChannel channel = Find(s, new ByteReader(m.Body, 1, m.Body.Length - 1, true).U32("recipient", "id"), out refused);
            return channel == null ? refused : StepDecision.Stay();
        }

        /// <summary>An empty chunk tells the code above that the channel ended. A close not yet answered gets one close back, with no EOF, since the peer is gone.</summary>
        static StepDecision Close(SshSession s, InboundMessage m)
        {
            StepDecision refused;
            SshChannel channel = Find(s, new ByteReader(m.Body, 1, m.Body.Length - 1, true).U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            s.Channels.Remove(channel.Local);
            List<StepEffect> effects = new List<StepEffect>();
            if (!channel.SentClose) effects.Add(s.SealedPacket(SshNames.ChannelClose, new ByteWriter().U8(SshMsg.ChannelClose).U32(channel.Remote).ToArray()));
            effects.Add(Effect.Deliver(channel.Local, new byte[0]));
            return StepDecision.Stay(effects.ToArray());
        }

        // ---------------------------------------------------------------- helpers for the two role tables

        public static SshChannel AddRemote(SshSession s, long remote, long window, long maxPacket)
        {
            SshChannel channel = AddLocal(s, s.NextLocalChannel++);
            channel.Remote = (int)remote;
            channel.PeerWindow = window;
            channel.PeerMaxPacket = maxPacket;
            channel.Confirmed = true;
            return channel;
        }

        public static byte[] Confirmation(SshChannel channel)
        {
            return new ByteWriter().U8(SshMsg.ChannelConfirmation).U32(channel.Remote).U32(channel.Local).U32(channel.OurWindow).U32(OurMaxPacket).ToArray();
        }

        /// <summary>Our SSH server starts no process. Each command answers from this table, and any other command exits 127 as a shell would.</summary>
        public static byte[] RunExec(string command, string user, out int exitCode)
        {
            exitCode = 0;
            if (command == "whoami") return System.Text.Encoding.UTF8.GetBytes(user + "\n");
            if (command == "echo" || command.StartsWith("echo ")) return System.Text.Encoding.UTF8.GetBytes(command.Substring(System.Math.Min(5, command.Length)) + "\n");
            exitCode = ExitNotFound;
            return new byte[0];
        }
    }
}
