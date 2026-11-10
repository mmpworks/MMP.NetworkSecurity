using System;
using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Tls11;
using NetSec.Tls13;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Issue #309: what "holds part of a frame" means in each engine family. Unconsumed input at any layer counts: part of a frame, a record,
    /// a handshake message split across records, or an SSH line or packet. The pump arms its read deadline only then.
    /// </summary>
    public class PartialInputTests
    {
        [Fact]
        public void Echo_engine_holds_part_of_a_frame_until_the_rest_comes()
        {
            byte[] hello = EchoEngine.Client(Make.Hello, Make.Stream("client"), null).Start().Items.First(i => i.Wire != null).Wire;
            EchoEngine server = EchoEngine.Server(Make.Stream("server"), null);
            server.Start();
            Assert.False(server.HoldsPartialInput);
            server.Feed(hello, 0, 2);
            Assert.True(server.HoldsPartialInput, "2 bytes of a frame wait for the rest");
            server.Feed(hello, 2, hello.Length - 2);
            Assert.False(server.HoldsPartialInput, "the whole frame was taken");
        }

        /// <summary>The frame family runs in the labs only, so its case is a lab: a frame whose length claims 64 KiB more than it holds.</summary>
        [Fact]
        public async System.Threading.Tasks.Task Frame_engine_receiver_of_a_cut_short_frame_is_ended_by_its_read_deadline()
        {
            AttackDefinition longer = new AttackDefinition
            {
                AttackId = "test-frame-length", Lesson = 1, Kind = "flip-byte", Options = new LabOption[0],
                Plan = new TamperPlan { Message = "TextCbc", Offset = 1 },
            };
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = longer, DeadlineMs = 1000 };
            IFuture<LabResult> run = LabCatalog.Find(1).Run(c);
            Assert.True(await FutureWaits.Within(run, TimeSpan.FromMilliseconds(60000)), "the lab did not finish");
            TraceEvent[] events = ((ListSink)c.Sink).Events;
            string[] server = events.Where(e => e.Actor == "server" && e.Type == "check.result").Select(e => e.Message).ToArray();
            string[] client = events.Where(e => e.Actor == "client" && e.Type == "check.result").Select(e => e.Message).ToArray();
            Assert.Contains("read deadline", server);
            Assert.Equal("peer stayed until the end", client.LastOrDefault());
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.FailedCode);
        }

        [Fact]
        public void Tls13_record_buffer_holds_part_of_a_record_until_it_is_whole()
        {
            RecordBuffer records = new RecordBuffer();
            records.Append(new byte[] { 22, 3, 3, 0, 4, 1 }, 0, 6);
            Assert.True(records.HoldsPartial);
            Assert.Null(records.Next());
            records.Append(new byte[] { 0, 0, 0 }, 0, 3);
            Assert.NotNull(records.Next());
            Assert.False(records.HoldsPartial);
        }

        [Fact]
        public void Tls13_handshake_buffer_holds_part_of_a_message_split_across_records()
        {
            HandshakeBuffer handshake = new HandshakeBuffer();
            handshake.Append(new byte[] { 20, 0, 0, 4, 1, 2 });
            Assert.Null(handshake.Next());
            Assert.False(handshake.IsEmpty, "a whole record held half a handshake message, so the peer still owes bytes");
            handshake.Append(new byte[] { 3, 4 });
            Assert.NotNull(handshake.Next());
            Assert.True(handshake.IsEmpty);
        }

        [Fact]
        public void Tls11_record_and_handshake_readers_hold_partial_input()
        {
            Tls11RecordReader records = new Tls11RecordReader();
            records.Append(new byte[] { 22, 3, 2, 0, 4, 1 }, 0, 6);
            Assert.True(records.HoldsPartial);
            records.Append(new byte[] { 0, 0, 0 }, 0, 3);
            Assert.NotNull(records.Next());
            Assert.False(records.HoldsPartial);

            Tls11HandshakeReader handshake = new Tls11HandshakeReader();
            handshake.Append(new byte[] { 20, 0, 0, 4, 1, 2 });
            Assert.Null(handshake.Next());
            Assert.False(handshake.IsEmpty);
        }

        [Fact]
        public void Ssh_reader_holds_part_of_an_identification_line_and_part_of_a_packet()
        {
            SshPacketReader reader = new SshPacketReader();
            byte[] line = Encoding.ASCII.GetBytes("SSH-2.0-training");
            reader.Append(line, 0, line.Length);
            Assert.True(reader.HoldsPartial, "a line with no CRLF yet is part of a frame");
            Assert.Null(reader.TryLine());
            reader.Append(new byte[] { 13, 10 }, 0, 2);
            Assert.NotNull(reader.TryLine());
            Assert.False(reader.HoldsPartial);
            reader.Append(new byte[] { 0, 0, 0 }, 0, 3);
            Assert.True(reader.HoldsPartial, "3 bytes of a packet length are part of a frame, though the length is not known yet");
        }
    }
}
