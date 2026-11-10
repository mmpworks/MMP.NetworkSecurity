using System;
using System.Linq;
using System.Net;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    static class Make
    {
        public static readonly byte[] Hello = Encoding.UTF8.GetBytes("hello");

        public static TraceStream Stream(string actor) =>
            new TraceStream("s1/" + actor + "/echo", "s1", "t1", null, actor, new FixedClock(7));

        public static async System.Threading.Tasks.Task Done(IFuture f)
        {
            Assert.True(await FutureWaits.Within(f, TimeSpan.FromMilliseconds(20000)), "the future did not finish in 20 s");
        }
    }

    public class BytesTests
    {
        [Fact]
        public void Hex_round_trips_and_uses_lower_case()
        {
            byte[] bytes = { 0x00, 0xAB, 0xFF };
            Assert.Equal("00abff", Hex.Encode(bytes));
            Assert.Equal(bytes, Hex.Decode("00ABff"));
        }

        [Fact]
        public void Hex_refuses_an_odd_length_and_a_bad_digit()
        {
            Assert.Throws<FormatException>(() => Hex.Decode("abc"));
            Assert.Throws<FormatException>(() => Hex.Decode("zz"));
        }

        [Fact]
        public void Reader_reads_what_the_writer_wrote_and_marks_each_field()
        {
            byte[] bytes = new ByteWriter().U8(1).U16(0x0203).U24(0x040506).U32(0x0708090AL).Put(new byte[] { 0x0B }).ToArray();
            ByteReader r = new ByteReader(bytes, 0, bytes.Length, true);
            Assert.Equal(1, r.U8("a", "header"));
            Assert.Equal(0x0203, r.U16("b", "length"));
            Assert.Equal(0x040506, r.U24("c", "length"));
            Assert.Equal(0x0708090AL, r.U32("d", "id"));
            Assert.Equal(new byte[] { 0x0B }, r.Take("e", "data", 1));
            Assert.Equal(new[] { "a", "b", "c", "d", "e" }, r.Marks.Select(m => m.Name).ToArray());
            Assert.Equal(new[] { 0, 1, 3, 6, 10 }, r.Marks.Select(m => m.Offset).ToArray());
            Assert.True(r.Marks.All(m => m.VisibleToWire));
        }

        [Fact]
        public void Reader_names_a_truncated_field()
        {
            ByteReader r = new ByteReader(new byte[1], 0, 1, true);
            ParseFailure failure = Assert.Throws<ParseFailure>(() => r.U16("length", "length"));
            Assert.Equal(ErrorCodes.ParseTruncated, failure.Code);
            Assert.Contains("length", failure.Message);
        }

        [Fact]
        public void Quote_escapes_json_control_characters()
        {
            Assert.Equal("\"a\\\"b\\\\c\\n\\u0001\"", MiniJson.Quote("a\"b\\c\n\u0001"));
        }
    }

    public class TraceTests
    {
        [Fact]
        public void Stream_stamps_stable_ids_and_a_sequence_from_one()
        {
            TraceStream s = Make.Stream("client");
            TraceEvent a = s.Stamp(new TraceEventDraft { Type = "x" });
            TraceEvent b = s.Stamp(new TraceEventDraft { Type = "y" });
            Assert.Equal(1, a.StreamSeq);
            Assert.Equal(2, b.StreamSeq);
            Assert.Equal("s1/client/echo#1", a.EventId);
            Assert.Equal(TraceEvent.CurrentSchema, a.Schema);
        }

        [Fact]
        public void An_event_keeps_its_own_copy_of_the_bytes()
        {
            byte[] wire = { 1, 2 };
            TraceEvent e = Make.Stream("client").Stamp(new TraceEventDraft { Type = "x", Wire = wire });
            wire[0] = 9;
            Assert.Equal(1, e.Wire[0]);
        }

        /// <summary>A pinned line: both builds run this test, so both builds write the same bytes for one event.</summary>
        [Fact]
        public void Json_line_is_byte_for_byte_the_pinned_form_on_this_build()
        {
            TraceField field = new TraceField { Name = "type", Offset = 0, Length = 1, Kind = "header", VisibleToWire = true, Gloss = "type" };
            TraceSecret secret = new TraceSecret { Holder = "client", Name = "k", Bytes = new byte[] { 0xAB }, DerivedFrom = new[] { "a", "b" } };
            TraceCheck check = new TraceCheck { Id = "C", Name = "n", Passed = false, Code = "C", Detail = "d" };
            TraceEvent e = Make.Stream("client").Stamp(new TraceEventDraft
            {
                Type = "t", Message = "m", Step = "st", From = "client", To = "server", WaitingFor = "server",
                Wire = new byte[] { 1 }, Plain = new byte[] { 2 }, Fields = new[] { field }, Secrets = new[] { secret }, Check = check,
            });
            string expected = "{\"schema\":1,\"eventId\":\"s1/client/echo#1\",\"streamId\":\"s1/client/echo\",\"streamSeq\":1,\"sessionId\":\"s1\",\"traceId\":\"t1\",\"actor\":\"client\","
                + "\"from\":\"client\",\"to\":\"server\",\"type\":\"t\",\"message\":\"m\",\"step\":\"st\",\"wire\":\"01\",\"plain\":\"02\","
                + "\"fields\":[{\"name\":\"type\",\"offset\":0,\"length\":1,\"kind\":\"header\",\"visibleToWire\":true,\"gloss\":\"type\"}],"
                + "\"secrets\":[{\"holder\":\"client\",\"name\":\"k\",\"hex\":\"ab\",\"derivedFrom\":[\"a\",\"b\"]}],"
                + "\"check\":{\"id\":\"C\",\"name\":\"n\",\"result\":\"fail\",\"code\":\"C\",\"detail\":\"d\"},"
                + "\"waiting\":{\"actor\":\"server\"},\"atMicros\":7}";
            Assert.Equal(expected, TraceJson.ToLine(e));
        }
    }

    public class MachineTests
    {
        sealed class Probe : IMachineSession
        {
            public int Absorbed;
            public string SentType => "p.sent";
            public string ReceivedType => "p.received";
            public void Absorb(byte[] message) { Absorbed++; }
            public byte[] Protect(string message, byte[] body) => body;
            public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv) { }
            public void Remember(string name, byte[] value) { }
            public byte[] PlainOf(InboundMessage message) => message.Bytes;
        }

        static Interpreter<Probe> Machine(StepRule<Probe> rule, Probe session) => new Interpreter<Probe>(
            new StepTable<Probe>(new StepRow<Probe>("p.one", "A", 1, rule, "B")), session, "A", Make.Stream("client"), "server", null);

        static InboundMessage Message(int type) => new InboundMessage(type, "M", new byte[] { 1 }, new byte[] { 1 }, null);

        [Fact]
        public void A_rule_is_a_value_a_test_can_read_with_no_engine()
        {
            StepDecision d = StepDecision.Advance(Effect.Absorb(new byte[1]), Effect.Check("c", "CODE"));
            Assert.Equal(StepOutcome.Advance, d.Outcome);
            Assert.Equal(new[] { EffectKind.Absorb, EffectKind.Check }, d.Effects.Select(e => e.Kind).ToArray());
        }

        [Fact]
        public void Each_effect_emits_its_event_and_the_state_moves()
        {
            Probe session = new Probe();
            Interpreter<Probe> m = Machine((s, i) => StepDecision.Advance(Effect.Absorb(i.Bytes), Effect.Check("seal", "BAD_SEAL")), session);
            m.Dispatch(Message(1));
            TraceEvent[] events = m.TakeOutput().Events;
            Assert.Equal(1, session.Absorbed);
            Assert.Equal("B", m.State);
            Assert.Equal(new[] { "p.received", "check.result", "state.waiting" }, events.Select(e => e.Type).ToArray());
            Assert.True(events[1].Check.Passed);
            Assert.Equal("server", events[2].WaitingFor);
        }

        [Fact]
        public void A_failed_rule_reaches_the_trace_with_its_code_and_ends_the_engine()
        {
            Interpreter<Probe> m = Machine((s, i) => StepDecision.Fail("BAD_SEAL", "seal check", "wrong"), new Probe());
            m.Dispatch(Message(1));
            EngineOutput output = m.TakeOutput();
            TraceEvent last = output.Events.Last();
            Assert.False(last.Check.Passed);
            Assert.Equal("BAD_SEAL", last.Check.Code);
            Assert.Equal("seal check", last.Check.Name);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal("BAD_SEAL", output.Error.Code);
            Assert.Equal("p.one", output.Error.Step);
        }

        [Fact]
        public void A_message_with_no_row_is_a_named_failure()
        {
            Interpreter<Probe> m = Machine((s, i) => StepDecision.Stay(), new Probe());
            m.Dispatch(Message(99));
            EngineOutput output = m.TakeOutput();
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(ErrorCodes.UnexpectedMessage, output.Error.Code);
            Assert.Contains("99", output.Error.Message);
        }

        [Fact]
        public void Engine_duel_runs_the_echo_with_no_socket_and_no_thread()
        {
            EchoEngine client = EchoEngine.Client(Make.Hello, Make.Stream("client"), null);
            EchoEngine server = EchoEngine.Server(Make.Stream("server"), null);
            EngineDuel.Run(client, server);
            Assert.Equal(EngineStatus.Closed, client.Status);
            Assert.Equal(EngineStatus.Closed, server.Status);
        }

        [Fact]
        public void Echo_feeds_one_byte_at_a_time_and_gives_the_same_sequence_numbers()
        {
            EchoEngine server = EchoEngine.Server(Make.Stream("server"), null);
            server.Start();
            byte[] frame = new ByteWriter().U8(EchoEngine.HelloType).U16(5).Put(Make.Hello).ToArray();
            System.Collections.Generic.List<TraceEvent> events = new System.Collections.Generic.List<TraceEvent>();
            for (int i = 0; i < frame.Length; i++) events.AddRange(server.Feed(frame, i, 1).Events);
            Assert.Equal(new[] { "echo.message.received", "echo.message.sent" }, events.Select(e => e.Type).ToArray());
            Assert.Equal(EngineStatus.Closed, server.Status);
        }

        [Fact]
        public void Echo_reply_that_differs_fails_by_name()
        {
            EchoEngine client = EchoEngine.Client(Make.Hello, Make.Stream("client"), null);
            client.Start();
            byte[] wrong = new ByteWriter().U8(EchoEngine.ReplyType).U16(5).Put(Encoding.UTF8.GetBytes("jello")).ToArray();
            EngineOutput output = client.Feed(wrong, 0, wrong.Length);
            Assert.Equal(ErrorCodes.EchoMismatch, output.Error.Code);
            Assert.Equal(EchoEngine.CompareCheck, output.Events.Last().Check.Name);
        }

        [Fact]
        public void Plain_tamper_changes_the_body_before_the_event_and_the_wire()
        {
            TamperPlan plan = new TamperPlan { Point = TamperPoint.Plain, Message = EchoEngine.HelloName, Offset = 3, Xor = 1 };
            EchoEngine client = EchoEngine.Client(Make.Hello, Make.Stream("client"), plan);
            EngineOutput output = client.Start();
            Assert.Equal((byte)('h' ^ 1), output.Wire[3]);
            Assert.Equal((byte)('h' ^ 1), output.Events[0].Plain[3]);
        }

        [Fact]
        public void A_peer_that_closes_early_is_named()
        {
            EchoEngine client = EchoEngine.Client(Make.Hello, Make.Stream("client"), null);
            client.Start();
            Assert.Equal(ErrorCodes.PeerClosedEarly, client.Command(EngineCommand.PeerClosed).Error.Code);
        }
    }

    public class PumpTests
    {
        sealed class Pair
        {
            public ListSink Sink = new ListSink();
            public IFuture<PumpResult> Client, Server;
            public string Delivered;
        }

        static Pair Run(IByteLink clientLink, IByteLink serverLink, IStepGate gate, ITamperHook tamper, int deadlineMs, int clientDeadlineMs = -1)
        {
            Pair p = new Pair();
            EnginePump server = new EnginePump(EchoEngine.Server(Make.Stream("server"), null), serverLink, p.Sink, gate, null, deadlineMs);
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), clientLink, p.Sink, gate, tamper, clientDeadlineMs < 0 ? deadlineMs : clientDeadlineMs);
            client.OnApp = c => p.Delivered = Encoding.UTF8.GetString(c.Bytes, 0, c.Bytes.Length);
            client.OpenedLink = true;
            p.Server = server.Run();
            p.Client = client.Run();
            return p;
        }

        [Fact]
        public async System.Threading.Tasks.Task Memory_links_run_the_echo_through_the_pump_with_no_port()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Pair p = Run(links[0], links[1], null, null, 15000);
            await Make.Done(p.Client);
            await Make.Done(p.Server);
            Assert.Null(p.Client.Result.Error);
            Assert.Equal("hello", p.Delivered);
            Assert.Equal(8, p.Client.Result.BytesSent);
            Assert.Equal(8, p.Client.Result.BytesReceived);
        }

        [Fact]
        public async System.Threading.Tasks.Task Only_socket_events_carry_wire_and_they_join_to_the_bytes_sent()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Pair p = Run(links[0], links[1], null, null, 15000);
            await Make.Done(p.Client);
            await Make.Done(p.Server);
            TraceEvent[] withWire = p.Sink.Events.Where(e => e.Wire != null).ToArray();
            Assert.True(withWire.All(e => e.Type == "wire.sent" || e.Type == "wire.received"));
            byte[] clientSent = withWire.Where(e => e.Actor == "client" && e.To == "server").SelectMany(e => e.Wire).ToArray();
            byte[] clientGot = withWire.Where(e => e.Actor == "client" && e.From == "server").SelectMany(e => e.Wire).ToArray();
            Assert.Equal(new ByteWriter().U8(EchoEngine.HelloType).U16(5).Put(Make.Hello).ToArray(), clientSent);
            Assert.Equal(new ByteWriter().U8(EchoEngine.ReplyType).U16(5).Put(Make.Hello).ToArray(), clientGot);
        }

        [Fact]
        public async System.Threading.Tasks.Task Engine_stream_numbers_stay_fixed_across_runs()
        {
            Func<System.Threading.Tasks.Task<string>> run = async () =>
            {
                MemoryLink[] links = MemoryLink.Pair();
                Pair p = Run(links[0], links[1], null, null, 15000);
                await Make.Done(p.Client);
                await Make.Done(p.Server);
                return string.Join("|", p.Sink.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray());
            };
            Assert.Equal(await run(), await run());
        }

        [Fact]
        public async System.Threading.Tasks.Task Sockets_run_the_echo_through_all_four_begin_pairs()
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            await Make.Done(accepted);
            await Make.Done(connected);
            listener.Close();
            SocketLink clientLink = connected.Result, serverLink = accepted.Result;
            Pair p = Run(clientLink, serverLink, null, null, 15000);
            await Make.Done(p.Client);
            await Make.Done(p.Server);
            Assert.Null(p.Client.Result.Error);
            Assert.Null(p.Server.Result.Error);
            Assert.Equal("hello", p.Delivered);
            Assert.Equal(1, listener.BeginAccepts);
            Assert.Equal(1, clientLink.BeginConnects);
            Assert.True(clientLink.BeginSends > 0 && serverLink.BeginSends > 0);
            Assert.True(clientLink.BeginReceives > 0 && serverLink.BeginReceives > 0);
        }

        [Fact]
        public async System.Threading.Tasks.Task Wire_tamper_is_caught_and_named_and_the_trace_shows_the_tampered_bytes()
        {
            MemoryLink[] links = MemoryLink.Pair();
            TamperPlan plan = new TamperPlan { Point = TamperPoint.Wire, Message = EchoEngine.HelloName, Offset = 3, Xor = 1 };
            Pair p = Run(links[0], links[1], null, plan, 15000);
            await Make.Done(p.Client);
            await Make.Done(p.Server);
            Assert.Equal(ErrorCodes.EchoMismatch, p.Client.Result.Error.Code);
            TraceEvent failed = p.Sink.Events.Single(e => e.Check != null && !e.Check.Passed);
            Assert.Equal(ErrorCodes.EchoMismatch, failed.Check.Code);
            TraceEvent sent = p.Sink.Events.First(e => e.Type == "wire.sent" && e.Actor == "client");
            Assert.Equal((byte)('h' ^ 1), sent.Wire[3]);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_silent_peer_hits_the_deadline_by_name()
        {
            MemoryLink[] links = MemoryLink.Pair();
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), links[0], null, null, null, 200);
            IFuture<PumpResult> run = client.Run();
            await Make.Done(run);
            // The client holds no part of a frame, only an unanswered hello, so its idle limit ends the wait (issue #309). This pump has no pair, so it keeps the acceptor role.
            Assert.Equal(ErrorCodes.LinkIdle, run.Result.Error.Code);
            Assert.Equal("idle limit", run.Result.Error.CheckName);
            Assert.Equal(EngineStatus.Failed, run.Result.Status);
        }

        /// <summary>
        /// Issue #308: an ended pump took every later command, ran the engine and queued the output with nobody to publish it, and the caller saw a
        /// success. A relay loop that kept sending into an ended session grew that queue to 83 million outputs. Data after the end now fails by name, and
        /// a close after the end stays a quiet success, because the link is closed already.
        /// </summary>
        [Fact]
        public async System.Threading.Tasks.Task Data_sent_after_the_pump_ended_fails_by_name_and_a_late_close_still_succeeds()
        {
            MemoryLink[] links = MemoryLink.Pair();
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), links[0], null, null, null, 200);
            await Make.Done(client.Run());

            IFuture send = client.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, new byte[] { 1, 2, 3 }, null));
            Assert.True(send.IsCompleted, "a send after the end must not wait");
            Assert.True(send.IsFaulted, "a send after the end reported a success");
            NetSecException refused = Assert.IsType<NetSecException>(send.Exception);
            Assert.Equal(ErrorCodes.LinkLost, refused.Error.Code);

            IFuture close = client.Enqueue(EngineCommand.Close);
            Assert.True(close.IsCompleted && !close.IsFaulted, "a close after the end must stay a quiet success");
        }

        /// <summary>The idle limit is set by role only (issue #309): the opener waits twice the read deadline, the acceptor three times. The detail names it.</summary>
        [Theory]
        [InlineData(true, "no bytes for 400 ms")]
        [InlineData(false, "no bytes for 600 ms")]
        public async System.Threading.Tasks.Task A_silent_peer_waits_twice_the_deadline_as_opener_and_three_times_as_acceptor(bool opened, string detail)
        {
            MemoryLink[] links = MemoryLink.Pair();
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), links[0], null, null, null, 200);
            client.OpenedLink = opened;
            IFuture<PumpResult> run = client.Run();
            await Make.Done(run);
            Assert.Equal(ErrorCodes.LinkIdle, run.Result.Error.Code);
            Assert.StartsWith(detail, run.Result.Error.Message);
        }

        /// <summary>
        /// Issue #312 (Jared): a probe that dials out is the opener, so a silent peer ends it at twice the read deadline, never three times.
        /// The peer is a listener that never accepts: the OS completes the connect, and no byte ever comes back.
        /// </summary>
        [Fact]
        public async System.Threading.Tasks.Task A_probe_that_dials_a_silent_peer_waits_the_openers_idle_limit()
        {
            System.Net.Sockets.TcpListener silent = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            silent.Start();
            try
            {
                int port = ((IPEndPoint)silent.LocalEndpoint).Port;
                IFuture<ProbeResult> probe = Probe.Connect(new ProbeRequest { Protocol = WireProtocol.Tls13, Host = "127.0.0.1", Port = port, Seed = 1, DeadlineMs = 200 });
                Assert.True(await FutureWaits.Within(probe, TimeSpan.FromMilliseconds(30000)), "the probe did not end in 30 s");
                ProbeResult r = probe.Result;
                Assert.False(r.Completed);
                Assert.Equal(ErrorCodes.LinkIdle, r.Code);
                Assert.StartsWith("no bytes for 400 ms", r.Detail);
            }
            finally { silent.Stop(); }
        }

        /// <summary>
        /// ProbeResult.Detail is null only when the session completed (its doc). A probe that dials a closed port fails at the TCP connect, and on
        /// both the TLS and the SSH route that failure names its message in Detail (Jared, #364 review, issue #366).
        /// </summary>
        [Theory]
        [InlineData(WireProtocol.Tls13)]
        [InlineData(WireProtocol.Ssh)]
        public async System.Threading.Tasks.Task A_probe_that_cannot_connect_names_the_failure_in_Detail(WireProtocol protocol)
        {
            System.Net.Sockets.TcpListener closed = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            closed.Start();
            int port = ((IPEndPoint)closed.LocalEndpoint).Port;
            closed.Stop();
            IFuture<ProbeResult> probe = Probe.Connect(new ProbeRequest { Protocol = protocol, Host = "127.0.0.1", Port = port, Seed = 1, DeadlineMs = 200 });
            Assert.True(await FutureWaits.Within(probe, TimeSpan.FromMilliseconds(30000)), "the probe did not end in 30 s");
            ProbeResult r = probe.Result;
            Assert.False(r.Completed);
            Assert.Equal(ErrorCodes.LinkLost, r.Code);
            Assert.False(string.IsNullOrEmpty(r.Detail), protocol + ": Detail is empty on a failed connect");
        }

        static async System.Threading.Tasks.Task<Pair> FlippedLength(int serverDeadlineMs, int clientDeadlineMs)
        {
            MemoryLink[] links = MemoryLink.Pair();
            TamperPlan plan = new TamperPlan { Point = TamperPoint.Wire, Message = EchoEngine.HelloName, Offset = 1, Xor = 1 };
            Pair p = Run(links[0], links[1], null, plan, serverDeadlineMs, clientDeadlineMs);
            await Make.Done(p.Client);
            await Make.Done(p.Server);
            return p;
        }

        /// <summary>
        /// The length promises more bytes than ever come. The server holds part of a frame, so it waits its read deadline; the client holds nothing, so it
        /// waits its idle limit, twice its read deadline as the side that opened the connection (issue #309). Whichever limit runs out first ends that side by name and
        /// closes the link, and the other side then reads the close, so PEER_CLOSED_EARLY is its true outcome. Row 1: the server's 300 ms read deadline
        /// beats the client's 10,000 ms idle limit. Row 2: the client's 600 ms idle limit beats the server's 5,000 ms read deadline.
        /// </summary>
        [Theory]
        [InlineData(300, 5000, ErrorCodes.LinkDeadline, ErrorCodes.PeerClosedEarly)]
        [InlineData(5000, 300, ErrorCodes.PeerClosedEarly, ErrorCodes.LinkIdle)]
        public async System.Threading.Tasks.Task A_flipped_length_byte_ends_in_the_named_deadline_on_both_sides(int serverDeadlineMs, int clientDeadlineMs, string serverCode, string clientCode)
        {
            Pair p = await FlippedLength(serverDeadlineMs, clientDeadlineMs);
            Assert.Equal(serverCode, p.Server.Result.Error.Code);
            Assert.Equal(clientCode, p.Client.Result.Error.Code);
            NetSecError stuck = serverCode == ErrorCodes.PeerClosedEarly ? p.Client.Result.Error : p.Server.Result.Error;
            Assert.Equal(stuck.Code == ErrorCodes.LinkDeadline ? "read deadline" : "idle limit", stuck.CheckName);
        }

        /// <summary>
        /// With equal deadlines the outcome no longer races (issue #309): the server holds the part of a frame, so its read deadline runs out first, and the
        /// client, waiting twice as long as the opener, then reads the close.
        /// </summary>
        [Fact]
        public async System.Threading.Tasks.Task Equal_deadlines_end_on_the_side_that_holds_the_partial_frame()
        {
            Pair p = await FlippedLength(300, 300);
            Assert.Equal(ErrorCodes.LinkDeadline, p.Server.Result.Error.Code);
            Assert.Equal("read deadline", p.Server.Result.Error.CheckName);
            Assert.Equal(ErrorCodes.PeerClosedEarly, p.Client.Result.Error.Code);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_peer_that_hangs_up_early_ends_the_run_by_name()
        {
            MemoryLink[] links = MemoryLink.Pair();
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), links[0], null, null, null, 15000);
            IFuture<PumpResult> run = client.Run();
            links[1].Close();
            await Make.Done(run);
            Assert.Equal(ErrorCodes.PeerClosedEarly, run.Result.Error.Code);
        }

        [Fact]
        public async System.Threading.Tasks.Task Step_gate_releases_one_event_per_step_and_run_opens_it()
        {
            MemoryLink[] links = MemoryLink.Pair();
            StepGate gate = new StepGate();
            ListSink sink = new ListSink();
            EnginePump client = new EnginePump(EchoEngine.Client(Make.Hello, Make.Stream("client"), null), links[0], sink, gate, null, 0);
            IFuture<PumpResult> run = client.Run();
            System.Threading.Thread.Sleep(100);
            Assert.Empty(sink.Events);
            gate.Step();
            WaitFor(() => sink.Events.Length == 1);
            Assert.Equal("echo.message.sent", sink.Events[0].Type);
            System.Threading.Thread.Sleep(100);
            Assert.Single(sink.Events);
            gate.Run();
            WaitFor(() => sink.Events.Any(e => e.Type == "wire.sent"));
            links[1].Close();
            await Make.Done(run);
        }

        static void WaitFor(Func<bool> condition)
        {
            DateTime end = DateTime.UtcNow.AddSeconds(10);
            while (!condition())
            {
                Assert.True(DateTime.UtcNow < end, "the condition did not hold in 10 s");
                System.Threading.Thread.Sleep(5);
            }
        }
    }

    public class TransportTests
    {
        [Fact]
        public void Ce_profile_holds_the_budget_and_allows_only_ssh_and_tls11()
        {
            Assert.Equal(25, DeviceProfile.Ce.PoolThreads);
            Assert.Equal(64L * 1024 * 1024, DeviceProfile.Ce.RamBytes);
            Assert.Equal(TransportDecision.Refused, TransportPolicy.Decide(DeviceProfile.Ce, "glass", WireProtocol.Tls13));
            Assert.Equal(TransportDecision.Allowed, TransportPolicy.Decide(DeviceProfile.Ce, "glass", WireProtocol.Ssh));
            Assert.Equal(TransportDecision.Allowed, TransportPolicy.Decide(DeviceProfile.Ce, "glass", WireProtocol.Tls11));
            Assert.Equal(TransportDecision.Allowed, TransportPolicy.Decide(DeviceProfile.Modern, "glass", WireProtocol.Tls13));
        }

        sealed class NoKeys : NetSec.Keys.ITrainingKeySource
        {
            public NetSec.Keys.ITrainingKey Find(string keyId) => null;
        }

        [Fact]
        public void Glass_factory_refuses_tls13_under_the_ce_profile_by_code()
        {
            IFuture<ISecureChannel> open = new GlassTransportFactory(new NoKeys()).Open(new TransportRequest { Protocol = WireProtocol.Tls13, Profile = DeviceProfile.Ce });
            Assert.True(open.IsFaulted);
            NetSecException e = Assert.IsType<NetSecException>(open.Exception);
            Assert.Equal(ErrorCodes.CeTransportUnavailable, e.Error.Code);
        }
    }

    [Collection(TimingCollection.Name)]
    public class LabTests
    {
        public LabTests() { NativeLib.Ensure(); }

        static LabContext Context(AttackDefinition attack) => new LabContext
        {
            SessionId = "s9", TraceId = "s9", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack, DeadlineMs = 2000,
        };

        [Fact]
        public async System.Threading.Tasks.Task Lesson_0_runs_on_loopback_and_shows_wire_events_for_both_actors()
        {
            LabContext c = Context(null);
            IFuture<LabResult> run = LabCatalog.Find(0).Run(c);
            await Make.Done(run);
            Assert.True(run.Result.Completed);
            TraceEvent[] events = ((ListSink)c.Sink).Events;
            Assert.Contains(events, e => e.Type == "wire.sent" && e.Actor == "client");
            Assert.Contains(events, e => e.Type == "wire.sent" && e.Actor == "server");
        }

        [Fact]
        public async System.Threading.Tasks.Task Every_attack_in_the_catalog_is_caught_by_its_named_check_beside_the_control()
        {
            foreach (AttackDefinition attack in AttackCatalog.All)
            {
                IFuture<LabResult> control = LabCatalog.Find(attack.Lesson).Run(Context(null));
                await Make.Done(control);
                Assert.True(control.Result.Completed);
                LabContext attacked = Context(attack);
                IFuture<LabResult> run = LabCatalog.Find(attack.Lesson).Run(attacked);
                await Make.Done(run);
                Assert.Equal(attack.Expect == AttackOutcome.Rejected, !run.Result.Completed);
                Assert.Equal(attack.ExpectCode, run.Result.FailedCode);
                Assert.Equal(attack.ExpectCheck, run.Result.FailedCheck);
            }
        }

        [Fact]
        public void An_unbuilt_lesson_has_no_lab()
        {
            Assert.Null(LabCatalog.Find(99));
        }
    }
}
