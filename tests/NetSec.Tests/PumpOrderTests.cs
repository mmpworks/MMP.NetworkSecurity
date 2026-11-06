using System;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// A record cipher numbers its records in the order the engine makes them, so the wire must carry them in that order.
    /// The read loop and a caller's Enqueue both drive the engine. This pins that the pump keeps the engine's order across both.
    /// Under load, the swap made a sealed record arrive under the wrong keys: TLS13_AEAD_TAG on a clean link.
    /// </summary>
    public class PumpOrderTests
    {
        /// <summary>Each call makes one output. Its wire bytes are the count of outputs so far, so a swap shows on the far side.</summary>
        sealed class CountingEngine : IProtocolEngine
        {
            readonly TraceStream _stream;
            int _count;
            public volatile bool Fed;
            public CountingEngine(string actor = "client") { _stream = Make.Stream(actor); }
            public EngineStatus Status { get; private set; } = EngineStatus.Open;
            public TraceStream Stream => _stream;
            public string Peer => "server";
            public EngineOutput Start() => Empty();

            /// <summary>Holds on a moment after it signals, so the caller is waiting on the pump's lock when Feed returns.</summary>
            public EngineOutput Feed(byte[] b, int off, int n)
            {
                Fed = true;
                Thread.SpinWait(2000);
                return Next();
            }

            public EngineOutput Command(EngineCommand c)
            {
                if (c.Kind != EngineCommandKind.Close) return Next();
                Status = EngineStatus.Closed;
                return Empty();
            }

            EngineOutput Empty() => new EngineOutput(new OutputItem[0], new DeliveredChunk[0], Status, null);

            EngineOutput Next()
            {
                _count++;
                byte[] wire = { (byte)(_count >> 8), (byte)_count };
                TraceEventDraft draft = new TraceEventDraft();
                draft.Type = "count.sent";
                return new EngineOutput(new[] { new OutputItem(_stream.Stamp(draft), wire) }, new DeliveredChunk[0], Status, null);
            }
        }

        static int ReadCount(IByteLink link)
        {
            byte[] two = new byte[2];
            int filled = 0;
            while (filled < 2)
            {
                IFuture<int> read = link.Read(two, filled, 2 - filled);
                Assert.True(read.Wait(20000), "no bytes in 20 s");
                filled += read.Result;
            }
            return (two[0] << 8) | two[1];
        }

        [Fact]
        public void Wire_bytes_leave_in_engine_order_when_a_caller_and_the_read_loop_drive_the_engine_together()
        {
            const int Rounds = 3000;
            MemoryLink[] links = MemoryLink.Pair();
            CountingEngine engine = new CountingEngine();
            EnginePump pump = new EnginePump(engine, links[0], new NullSink(), new FreeRunGate(), null, 0);
            IFuture<PumpResult> run = pump.Run();

            bool done = false;
            Thread caller = new Thread(() =>
            {
                while (!Volatile.Read(ref done))
                {
                    if (!engine.Fed) continue;
                    engine.Fed = false;
                    pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
                }
            });
            caller.IsBackground = true;
            caller.Start();

            int misordered = 0, last = 0;
            for (int i = 0; i < Rounds; i++)
            {
                links[1].Write(new byte[1], 0, 1);
                for (int k = 0; k < 2; k++)
                {
                    int value = ReadCount(links[1]);
                    if (value != last + 1) misordered++;
                    last = value;
                }
            }
            Volatile.Write(ref done, true);
            caller.Join();
            pump.Enqueue(EngineCommand.Close);
            Assert.True(run.Wait(20000));
            Assert.Equal(0, misordered);
        }

        /// <summary>Delivers the bytes, then holds the writer. The peer can read and answer during that hold.</summary>
        sealed class SlowFinishLink : IByteLink
        {
            readonly IByteLink _inner;
            readonly ListSink _sink;
            public volatile int WireSentAtWrite = -1;
            public SlowFinishLink(IByteLink inner, ListSink sink) { _inner = inner; _sink = sink; }
            public IFuture<int> Read(byte[] b, int off, int n) => _inner.Read(b, off, n);
            public void Close() => _inner.Close();

            public IFuture Write(byte[] b, int off, int n)
            {
                if (WireSentAtWrite < 0) WireSentAtWrite = _sink.Events.Length;
                IFuture write = _inner.Write(b, off, n);
                Thread.Sleep(200);
                return write;
            }
        }

        static string[] WireSentActors(ListSink sink)
        {
            System.Collections.Generic.List<string> actors = new System.Collections.Generic.List<string>();
            foreach (TraceEvent e in sink.Events) if (e.Type == "wire.sent") actors.Add(e.Actor);
            return actors.ToArray();
        }

        /// <summary>
        /// The session list is one order across two pumps, and a lesson counts round trips from it. So a message is logged before its bytes can reach the peer.
        /// Logged after the write, a reply can be listed ahead of the message it answers: lesson 7 then showed 1 round trip where the run took 2.
        /// </summary>
        [Fact]
        public void A_reply_is_never_logged_ahead_of_the_message_it_answers()
        {
            MemoryLink[] links = MemoryLink.Pair();
            ListSink sink = new ListSink();
            EnginePump client = new EnginePump(new CountingEngine("client"), new SlowFinishLink(links[0], sink), sink, new FreeRunGate(), null, 0);
            EnginePump server = new EnginePump(new CountingEngine("server"), links[1], sink, new FreeRunGate(), null, 0);
            IFuture<PumpResult> clientRun = client.Run(), serverRun = server.Run();

            client.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            SpinWait.SpinUntil(() => WireSentActors(sink).Length >= 2, 20000);

            // These engines answer every message, so the exchange runs on. The first two entries are the request and its reply.
            string[] actors = WireSentActors(sink);
            Assert.Equal("client", actors[0]);
            Assert.Equal("server", actors[1]);
            client.Enqueue(EngineCommand.Close);
            server.Enqueue(EngineCommand.Close);
            links[0].Close();
            links[1].Close();
            clientRun.Wait(20000);
            serverRun.Wait(20000);
        }

        [Fact]
        public void A_message_is_in_the_trace_when_its_bytes_go_to_the_link()
        {
            MemoryLink[] links = MemoryLink.Pair();
            ListSink sink = new ListSink();
            SlowFinishLink link = new SlowFinishLink(links[0], sink);
            EnginePump pump = new EnginePump(new CountingEngine(), link, sink, new FreeRunGate(), null, 0);
            IFuture<PumpResult> run = pump.Run();

            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            // The event is logged first, so the write can still be on its way when the event shows. Wait for the write itself.
            Assert.True(SpinWait.SpinUntil(() => link.WireSentAtWrite >= 0, 20000), "the link never saw a write");
            TraceEvent[] atWrite = new TraceEvent[link.WireSentAtWrite];
            System.Array.Copy(sink.Events, atWrite, link.WireSentAtWrite);
            Assert.Contains(atWrite, e => e.Type == "wire.sent");
            pump.Enqueue(EngineCommand.Close);
            links[1].Close();
            run.Wait(20000);
        }

        /// <summary>The engine has failed, and its last output is the alert.</summary>
        sealed class AlertEngine : IProtocolEngine
        {
            readonly TraceStream _stream = Make.Stream("client");
            public EngineStatus Status { get; private set; } = EngineStatus.Open;
            public TraceStream Stream => _stream;
            public string Peer => "server";
            public EngineOutput Feed(byte[] b, int off, int n) => new EngineOutput(new OutputItem[0], new DeliveredChunk[0], Status, null);
            public EngineOutput Command(EngineCommand c) => new EngineOutput(new OutputItem[0], new DeliveredChunk[0], Status, null);

            public EngineOutput Start()
            {
                Status = EngineStatus.Failed;
                TraceEventDraft draft = new TraceEventDraft();
                draft.Type = "tls.alert.sent";
                draft.Message = "Alert";
                return new EngineOutput(new[] { new OutputItem(_stream.Stamp(draft), new byte[] { 2, 40 }) }, new DeliveredChunk[0], Status, null);
            }
        }

        sealed class FixedWriteLink : IByteLink
        {
            readonly IFuture _write;
            readonly Promise<int> _read = new Promise<int>();
            public FixedWriteLink(IFuture write) { _write = write; }
            public IFuture<int> Read(byte[] b, int off, int n) => _read.Future;
            public IFuture Write(byte[] b, int off, int n) => _write;
            public void Close() { _read.TrySetResult(0); }
        }

        static TraceEvent OneEvent(ListSink sink, string type)
        {
            TraceEvent found = null;
            foreach (TraceEvent e in sink.Events)
            {
                if (e.Type != type) continue;
                Assert.Null(found);
                found = e;
            }
            Assert.NotNull(found);
            return found;
        }

        static void AssertSaysNotLeft(ListSink sink, string code)
        {
            TraceEvent sent = OneEvent(sink, "wire.sent"), lost = OneEvent(sink, "wire.write.failed");
            Assert.Equal(sent.Message, lost.Message);
            Assert.Equal(sent.From, lost.From);
            Assert.Equal(sent.To, lost.To);
            Assert.StartsWith(code + ":", lost.Detail);
            Assert.Contains(sent.EventId, lost.Detail);
            Assert.True(lost.Wire == null || lost.Wire.Length == 0, "only bytes that left carry Wire");
        }

        /// <summary>The engine's own failure is the run's error, so a lost alert leaves the result silent. The trace must say that the alert did not leave.</summary>
        [Fact]
        public void A_lost_alert_write_says_so_in_the_trace()
        {
            ListSink sink = new ListSink();
            FixedWriteLink link = new FixedWriteLink(Futures.FromException(new InvalidOperationException("the peer is gone")));
            IFuture<PumpResult> run = new EnginePump(new AlertEngine(), link, sink, new FreeRunGate(), null, 0).Run();

            Assert.True(run.Wait(20000));
            Assert.Null(run.Result.Error);
            Assert.Equal(0, run.Result.BytesSent);
            AssertSaysNotLeft(sink, ErrorCodes.LinkLost);
        }

        [Fact]
        public void A_lost_write_on_an_open_engine_says_so_in_the_trace_and_the_result()
        {
            ListSink sink = new ListSink();
            FixedWriteLink link = new FixedWriteLink(Futures.FromException(new InvalidOperationException("the peer is gone")));
            EnginePump pump = new EnginePump(new CountingEngine(), link, sink, new FreeRunGate(), null, 0);
            IFuture<PumpResult> run = pump.Run();

            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(run.Wait(20000));
            Assert.Equal(ErrorCodes.LinkLost, run.Result.Error.Code);
            AssertSaysNotLeft(sink, ErrorCodes.LinkLost);
        }

        [Fact]
        public void A_write_past_its_deadline_says_so_in_the_trace()
        {
            ListSink sink = new ListSink();
            FixedWriteLink link = new FixedWriteLink(new Promise<int>().Future);
            EnginePump pump = new EnginePump(new CountingEngine(), link, sink, new FreeRunGate(), null, 300);
            IFuture<PumpResult> run = pump.Run();

            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.True(run.Wait(20000));
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.Error.Code);
            AssertSaysNotLeft(sink, ErrorCodes.LinkDeadline);
        }

        [Fact]
        public void A_write_that_completes_logs_no_failure()
        {
            MemoryLink[] links = MemoryLink.Pair();
            ListSink sink = new ListSink();
            EnginePump pump = new EnginePump(new CountingEngine(), links[0], sink, new FreeRunGate(), null, 0);
            IFuture<PumpResult> run = pump.Run();

            pump.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[1], null));
            Assert.Equal(1, ReadCount(links[1]));
            pump.Enqueue(EngineCommand.Close);
            Assert.True(run.Wait(20000));
            Assert.Null(run.Result.Error);
            Assert.DoesNotContain(sink.Events, e => e.Type == "wire.write.failed");
        }
    }
}
