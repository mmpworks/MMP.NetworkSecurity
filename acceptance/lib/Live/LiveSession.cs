using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Bridge;
using NetSec.Machine;
using NetSec.Trace;

namespace Acceptance
{
    /// <summary>The outcome of one Open call: the channel on success, or the failure and the failed check code.</summary>
    public sealed class Handshake
    {
        public ISecureChannel Channel;
        public Exception Error;
        public RecordingSink Sink;
        public RecordingSocketLink Link;
        public bool Opened { get { return Channel != null; } }
        public string FailedCode { get { return Sink.FailedCheckCode; } }
        public string Describe()
        {
            if (Opened) return "opened";
            return "failed with code " + (FailedCode ?? "<no failed check in the trace>") + (Error != null ? " (" + Error.GetType().Name + ": " + Error.Message + ")" : "");
        }
    }

    public static class Live
    {
        /// <summary>Opens a glass-box client channel over a new connection to 127.0.0.1:port.</summary>
        public static Handshake OpenClient(WireProtocol protocol, KexGroup group, SshSuite suite, int port, string peerName, ITamperHook tamper, ulong seed, string traceId)
        {
            return OpenClient(protocol, group, suite, Tls11Suite.RsaAes128CbcSha, port, peerName, tamper, seed, traceId);
        }

        public static Handshake OpenClient(WireProtocol protocol, KexGroup group, SshSuite suite, Tls11Suite tls11, int port, string peerName, ITamperHook tamper, ulong seed, string traceId)
        {
            Handshake h = new Handshake();
            h.Sink = new RecordingSink();
            h.Link = RecordingSocketLink.ConnectTo(port);
            return Open(h, protocol, EngineRole.Client, group, suite, tls11, peerName, tamper, seed, traceId);
        }

        /// <summary>Opens a glass-box server channel over an accepted connection.</summary>
        public static Handshake OpenServer(WireProtocol protocol, KexGroup group, SshSuite suite, Socket accepted, ulong seed, string traceId)
        {
            Handshake h = new Handshake();
            h.Sink = new RecordingSink();
            h.Link = new RecordingSocketLink(accepted);
            return Open(h, protocol, EngineRole.Server, group, suite, Tls11Suite.RsaAes128CbcSha, "localhost", null, seed, traceId);
        }

        static Handshake Open(Handshake h, WireProtocol protocol, EngineRole role, KexGroup group, SshSuite suite, Tls11Suite tls11, string peerName, ITamperHook tamper, ulong seed, string traceId)
        {
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            TransportRequest req = new TransportRequest();
            req.Protocol = protocol;
            req.Role = role;
            req.Group = group;
            req.Suite = suite;
            req.Tls11Suite = tls11;
            req.Link = h.Link;
            req.Random = new TestRandom(seed);
            req.Sink = h.Sink;
            req.Gate = new OpenGate();
            req.Tamper = tamper;
            req.TraceId = traceId;
            req.Hop = "h1";
            req.PeerName = peerName;
            req.Profile = DeviceProfile.Modern;
            IFuture<ISecureChannel> open = factory.Open(req);
            if (!open.Wait(45000)) { h.Error = new TimeoutException("no result after 45 s"); h.Link.Close(); return h; }
            if (open.IsFaulted || open.IsCanceled) { h.Error = open.Exception; return h; }
            h.Channel = open.Result;
            return h;
        }

        /// <summary>Sends text and reads application data until the expected text arrives. Returns what was read.</summary>
        public static string Exchange(ISecureChannel ch, string send, string expectContains, int timeoutMs)
        {
            if (send != null) Futs.Done(ch.Send(0, Encoding.ASCII.GetBytes(send)), timeoutMs, "send");
            StringBuilder got = new StringBuilder();
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (got.ToString().IndexOf(expectContains, StringComparison.Ordinal) < 0)
            {
                int left = (int)(end - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) throw new FailException("expected '" + expectContains.Trim() + "' from the peer, read '" + got.ToString().Trim() + "'");
                IFuture<AppChunk> f = ch.Receive();
                if (!f.Wait(left)) throw new FailException("expected '" + expectContains.Trim() + "' from the peer, read '" + got.ToString().Trim() + "' and then nothing for " + timeoutMs + " ms");
                if (f.IsFaulted) throw new FailException("receive failed: " + f.Exception);
                AppChunk chunk = f.Result;
                if (chunk == null || chunk.Bytes == null || chunk.Bytes.Length == 0) break;
                got.Append(Encoding.ASCII.GetString(chunk.Bytes));
            }
            return got.ToString();
        }
    }
}
