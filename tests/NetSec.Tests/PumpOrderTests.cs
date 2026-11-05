using System;
using System.Threading;
using MMP.AsyncProxy;
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
            readonly TraceStream _stream = Make.Stream("client");
            int _count;
            public volatile bool Fed;
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
    }
}
