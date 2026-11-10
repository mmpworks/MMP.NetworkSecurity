using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Jared's hang: each read loop waited for its outbox, and each outbox waited on a socket write. When both ends fill the TCP buffers, each
    /// waits for the other, and no deadline ran. Real sockets here, because a MemoryLink write never blocks.
    /// </summary>
    public class PumpTwoWayTests
    {
        const int Size = 8 * 1024 * 1024;
        const int Piece = 1024 * 1024;

        static byte[] Pattern(int start, int count)
        {
            byte[] bytes = new byte[count];
            for (int i = 0; i < count; i++) bytes[i] = (byte)((start + i) % 251);
            return bytes;
        }

        static async System.Threading.Tasks.Task<SocketLink[]> SocketPair()
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            Assert.True(await FutureWaits.Within(accepted, TimeSpan.FromMilliseconds(20000)));
            Assert.True(await FutureWaits.Within(connected, TimeSpan.FromMilliseconds(20000)));
            listener.Close();
            return new[] { connected.Result, accepted.Result };
        }

        /// <summary>A target that sends back all it reads, on its own thread, as a plain socket peer does.</summary>
        static int StartEchoSocket()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Thread thread = new Thread(() =>
            {
                try
                {
                    using (TcpClient peer = listener.AcceptTcpClient())
                    {
                        NetworkStream stream = peer.GetStream();
                        byte[] buffer = new byte[65536];
                        int read;
                        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) stream.Write(buffer, 0, read);
                    }
                }
                catch (Exception) { }
                listener.Stop();
            });
            thread.IsBackground = true;
            thread.Start();
            return port;
        }

        /// <summary>A server app that sends back each chunk and waits for each send.</summary>
        static void StartEchoApp(ISecureChannel server)
        {
            Thread thread = new Thread(() =>
            {
                while (true)
                {
                    IFuture<AppChunk> next = server.Receive();
                    // blocks: this loop runs on its own dedicated Thread, not a pool thread, so its waits starve no continuation.
                    if (!next.Wait(60000) || next.IsFaulted || next.IsCanceled || next.Result.Bytes.Length == 0) return;
                    if (!server.Send(next.Result.Channel, next.Result.Bytes).Wait(60000)) return; // blocks: the same dedicated Thread as the line above.
                }
            });
            thread.IsBackground = true;
            thread.Start();
        }

        static async System.Threading.Tasks.Task ReadAllInOrder(ISecureChannel client, int channel)
        {
            int got = 0;
            while (got < Size)
            {
                IFuture<AppChunk> next = client.Receive();
                Assert.True(await FutureWaits.Within(next, TimeSpan.FromMilliseconds(20000)), "no chunk for 20 s, at " + got + " of " + Size + " bytes");
                Assert.False(next.IsFaulted, "at " + got + " of " + Size + " bytes: " + next.Exception?.Message);
                if (next.Result.Channel != channel) continue;
                byte[] bytes = next.Result.Bytes;
                Assert.True(bytes.Length > 0, "the channel ended at " + got + " bytes");
                for (int i = 0; i < bytes.Length; i++)
                    if (bytes[i] != (byte)((got + i) % 251)) throw new InvalidOperationException("byte " + (got + i) + " is out of order");
                got += bytes.Length;
            }
        }

        static void SendAll(ISecureChannel client, int channel)
        {
            for (int at = 0; at < Size; at += Piece) client.Send(channel, Pattern(at, Piece));
        }

        [Theory]
        [InlineData(WireProtocol.Tls13)]
        [InlineData(WireProtocol.Tls11)]
        public async System.Threading.Tasks.Task Two_way_traffic_on_tls_reaches_the_end_in_order(WireProtocol protocol)
        {
            SocketLink[] links = await SocketPair();
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            IFuture<ISecureChannel> server = factory.Open(new TransportRequest { Protocol = protocol, Role = EngineRole.Server, Group = KexGroup.X25519, Tls11Suite = Tls11Suite.EcdheRsaAes128CbcSha, Link = links[1], Random = new SeededRandom(1), Sink = new NullSink(), PeerName = "localhost" });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = protocol, Role = EngineRole.Client, Group = KexGroup.X25519, Tls11Suite = Tls11Suite.EcdheRsaAes128CbcSha, Link = links[0], Random = new SeededRandom(2), Sink = new NullSink(), PeerName = "localhost" });
            Assert.True(await FutureWaits.Within(server, TimeSpan.FromMilliseconds(20000)) && await FutureWaits.Within(client, TimeSpan.FromMilliseconds(20000)));
            StartEchoApp(server.Result);
            SendAll(client.Result, 0);
            await ReadAllInOrder(client.Result, 0);
        }

        [Fact]
        public async System.Threading.Tasks.Task Two_way_traffic_on_an_ssh_tunnel_reaches_the_end_in_order()
        {
            SocketLink[] links = await SocketPair();
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            int target = StartEchoSocket();
            IFuture<ISecureChannel> server = factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Server, Suite = SshSuite.Modern, Link = links[1], Random = new SeededRandom(1), Sink = new NullSink(), AllowTunnel = (h, p) => p == target });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Client, Suite = SshSuite.Modern, Link = links[0], Random = new SeededRandom(2), Sink = new NullSink(), PeerName = "h", PeerPort = 22, TrustFirstUse = true });
            Assert.True(await FutureWaits.Within(client, TimeSpan.FromMilliseconds(20000)));
            ISshChannel channel = Assert.IsAssignableFrom<ISshChannel>(client.Result);
            IFuture<int> tunnel = channel.OpenTunnel("127.0.0.1", target);
            Assert.True(await FutureWaits.Within(tunnel, TimeSpan.FromMilliseconds(20000)));
            SendAll(channel, tunnel.Result);
            await ReadAllInOrder(channel, tunnel.Result);
        }

        // ---------------------------------------------------------------- the limits that come with reading while writing

        /// <summary>Each Feed or command makes what the test asks for, so a test can fill the outbox on purpose.</summary>
        sealed class ScriptEngine : IProtocolEngine
        {
            readonly TraceStream _stream = new TraceStream("c", "c", "c", null, "client", new FixedClock(1));
            public int FeedAppBytes;
            public int CommandWireBytes;
            int _feeds;
            public int Feeds => Volatile.Read(ref _feeds);
            public EngineStatus Status { get; private set; } = EngineStatus.Open;
            public TraceStream Stream => _stream;
            public string Peer => "server";
            public int StartWireBytes;
            public EngineOutput Start() => Output(StartWireBytes, 0);
            public EngineOutput Feed(byte[] b, int off, int n)
            {
                Interlocked.Increment(ref _feeds);
                return Output(0, FeedAppBytes);
            }
            public EngineOutput Command(EngineCommand c)
            {
                if (c.Kind == EngineCommandKind.Close) { Status = EngineStatus.Closed; return Output(0, 0); }
                return Output(CommandWireBytes, 0);
            }
            EngineOutput Output(int wire, int app)
            {
                TraceEventDraft draft = new TraceEventDraft();
                draft.Type = "script";
                OutputItem[] items = wire > 0 ? new[] { new OutputItem(_stream.Stamp(draft), new byte[wire]) } : new OutputItem[0];
                DeliveredChunk[] chunks = app > 0 ? new[] { new DeliveredChunk(0, new byte[app]) } : new DeliveredChunk[0];
                return new EngineOutput(items, chunks, Status, null);
            }
        }

        /// <summary>Reads always have a byte. A write waits as long as the test says, and forever at -1.</summary>
        sealed class ScriptLink : IByteLink
        {
            readonly int _writeMs;
            readonly bool _readsReady;
            readonly Promise<int> _noRead = new Promise<int>();
            public ScriptLink(int writeMs, bool readsReady) { _writeMs = writeMs; _readsReady = readsReady; }
            public IFuture<int> Read(byte[] b, int off, int n) => _readsReady ? Futures.Run<int>(() => 1) : _noRead.Future;
            public IFuture Write(byte[] b, int off, int n) => _writeMs < 0 ? new Promise().Future : _writeMs == 0 ? Futures.Completed : Futures.Delay(_writeMs);
            public void Close() => _noRead.TrySetResult(0);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_write_the_peer_never_takes_ends_in_a_named_deadline()
        {
            ScriptEngine engine = new ScriptEngine { CommandWireBytes = 100 };
            EnginePump pump = new EnginePump(engine, new ScriptLink(-1, false), new NullSink(), new FreeRunGate(), null, 300);
            IFuture<PumpResult> run = pump.Run();
            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(await FutureWaits.Within(run, TimeSpan.FromMilliseconds(20000)), "no deadline ended the blocked write");
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.Error?.Code);
            Assert.Equal("write deadline", run.Result.Error?.CheckName);
        }

        /// <summary>With reads running during a write, a long upload with no reply must not look like a silent peer.</summary>
        [Fact]
        public async System.Threading.Tasks.Task A_long_upload_with_no_reply_does_not_trip_the_read_deadline()
        {
            ScriptEngine engine = new ScriptEngine { CommandWireBytes = 100 };
            EnginePump pump = new EnginePump(engine, new ScriptLink(100, false), new NullSink(), new FreeRunGate(), null, 300);
            IFuture<PumpResult> run = pump.Run();
            IFuture last = null;
            for (int i = 0; i < 20; i++) last = pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(await FutureWaits.Within(last, TimeSpan.FromMilliseconds(20000)), "the upload did not finish");
            Assert.False(run.IsCompleted, run.IsCompleted ? "ended: " + run.Result.Error?.Code : "");
        }

        [Fact]
        public async System.Threading.Tasks.Task Reading_stops_at_the_inbound_limit_while_a_write_is_blocked()
        {
            ScriptEngine engine = new ScriptEngine { StartWireBytes = 100, FeedAppBytes = 1024 * 1024 };
            EnginePump pump = new EnginePump(engine, new ScriptLink(-1, true), new NullSink(), new FreeRunGate(), null, 2000);
            IFuture<PumpResult> run = pump.Run();
            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(await FutureWaits.Within(run, TimeSpan.FromMilliseconds(20000)), "no deadline ended the blocked write");
            Assert.InRange(engine.Feeds, 1, EnginePump.InboundBacklogLimit / (1024 * 1024) + 1);
            Assert.Equal("write deadline", run.Result.Error?.CheckName);
        }

        /// <summary>A sender must not wait for a quiet moment, because a two-way flow may have none.</summary>
        [Fact]
        public async System.Threading.Tasks.Task An_enqueue_finishes_when_its_own_output_is_out_while_reads_keep_coming()
        {
            ScriptEngine engine = new ScriptEngine { CommandWireBytes = 100, FeedAppBytes = 1 };
            EnginePump pump = new EnginePump(engine, new ScriptLink(0, true), new NullSink(), new FreeRunGate(), null, 30000);
            IFuture<PumpResult> run = pump.Run();
            IFuture done = pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(await FutureWaits.Within(done, TimeSpan.FromMilliseconds(20000)), "the enqueue waited for reads to stop");
            pump.Enqueue(EngineCommand.Close);
        }
    }
}
