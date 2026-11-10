using System;
using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    public class BridgeCoreTests
    {
        const string Pin = "1234", Pan = "4111111111111111";
        static readonly byte[] KeyId = Hex.Decode("1234567890123456");
        static readonly byte[] Bdk = new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial();

        static DukptPinPad NewPad() => new DukptPinPad(DukptBank.DeriveInitialKey(Bdk, KeyId), KeyId);
        static async System.Threading.Tasks.Task<(ExternalForwardLink Link, System.Net.Sockets.TcpListener Listener, System.Net.Sockets.Socket Peer)> OpenForward(ListSink sink)
        {
            System.Net.Sockets.TcpListener listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            ExternalForwardLink link = new ExternalForwardLink((System.Net.IPEndPoint)listener.LocalEndpoint, sink, "t/ce/local", "t", new FixedClock(1));
            IFuture opened = link.Open();
            System.Net.Sockets.Socket peer = listener.AcceptSocket();
            Assert.True(await FutureWaits.Within(opened, TimeSpan.FromMilliseconds(20000)));
            Assert.False(opened.IsFaulted);
            return (link, listener, peer);
        }

        /// <summary>Always has bytes, takes every write, and ignores Close. It counts what was read from it.</summary>
        sealed class EndlessLink : IByteLink
        {
            long _taken;
            public long Taken => System.Threading.Interlocked.Read(ref _taken);
            public IFuture<int> Read(byte[] b, int off, int n) { System.Threading.Interlocked.Add(ref _taken, n); return Futures.FromResult<int>(n); }
            public IFuture Write(byte[] b, int off, int n) => Futures.Completed;
            public void Close() { }
        }

        /// <summary>Ends at once: its first read returns 0, and it takes every write.</summary>
        sealed class EndedLink : IByteLink
        {
            public IFuture<int> Read(byte[] b, int off, int n) => Futures.FromResult<int>(0);
            public IFuture Write(byte[] b, int off, int n) => Futures.Completed;
            public void Close() { }
        }

        /// <summary>
        /// Issue #308's class sweep: the relay's two copies stopped only on their own link's signal. When one direction ended, Join closed both links, and a
        /// link that ignores Close kept the other copy running forever. Each copy now also stops when the other direction has ended.
        /// </summary>
        // The endless link completes every read at once, so a copy that never stops never yields either: Join runs on its own background thread,
        // under a bound. The ended link goes first, so its direction ends before the endless one starts.
        [Fact]
        public async System.Threading.Tasks.Task When_one_direction_of_a_relay_ends_the_other_stops_reading()
        {
            EndlessLink endless = new EndlessLink();
            IFuture joined = null;
            System.Threading.Thread joiner = new System.Threading.Thread(() => joined = BridgeRelay.Join(new EndedLink(), endless)) { IsBackground = true };
            joiner.Start();
            Assert.True(joiner.Join(5000) && await FutureWaits.Within(joined, TimeSpan.FromMilliseconds(5000)), "the relay was still reading after 5 s, with " + endless.Taken + " bytes taken");
            System.Threading.Thread.Sleep(500);
            long settled = endless.Taken;
            System.Threading.Thread.Sleep(1000);
            Assert.True(endless.Taken == settled, "the relay read " + (endless.Taken - settled) + " more bytes in 1 s after it ended");
        }

        /// <summary>The same rule as the pump's: a wire.sent whose bytes may not have left is followed by an event that says so, and the caller still sees the fault.</summary>
        [Fact]
        public async System.Threading.Tasks.Task A_lost_CE_write_says_so_in_the_trace_and_still_faults()
        {
            ListSink sink = new ListSink();
            (ExternalForwardLink link, System.Net.Sockets.TcpListener listener, System.Net.Sockets.Socket peer) = await OpenForward(sink);
            await FutureWaits.Within(link.Close(), TimeSpan.FromMilliseconds(20000));

            IFuture send = link.Send(new byte[] { 1, 2, 3 });
            Assert.True(await FutureWaits.Within(send, TimeSpan.FromMilliseconds(20000)));
            peer.Close();
            listener.Stop();

            Assert.True(send.IsFaulted);
            TraceEvent sent = sink.Events.Single(e => e.Type == "wire.sent");
            TraceEvent lost = sink.Events.Single(e => e.Type == "wire.write.failed");
            Assert.Equal(sent.Message, lost.Message);
            Assert.Equal(sent.From, lost.From);
            Assert.Equal(sent.To, lost.To);
            Assert.StartsWith(ErrorCodes.LinkLost + ":", lost.Detail);
            Assert.Contains(sent.EventId, lost.Detail);
            Assert.True(lost.Wire == null || lost.Wire.Length == 0, "only bytes that left carry Wire");
        }

        [Fact]
        public async System.Threading.Tasks.Task A_CE_write_that_completes_logs_no_failure()
        {
            ListSink sink = new ListSink();
            (ExternalForwardLink link, System.Net.Sockets.TcpListener listener, System.Net.Sockets.Socket peer) = await OpenForward(sink);

            IFuture send = link.Send(new byte[] { 1, 2, 3 });
            Assert.True(await FutureWaits.Within(send, TimeSpan.FromMilliseconds(20000)));
            Assert.False(send.IsFaulted);
            await FutureWaits.Within(link.Close(), TimeSpan.FromMilliseconds(20000));
            peer.Close();
            listener.Stop();

            Assert.Single(sink.Events, e => e.Type == "wire.sent");
            Assert.DoesNotContain(sink.Events, e => e.Type == "wire.write.failed");
        }

        /// <summary>Its write faults, and its read never returns. So a flow that reads after a lost write waits forever.</summary>
        sealed class LostWriteLink : IDeviceLink
        {
            public bool Received, Closed;
            public string Kind => "lost-write";
            public IFuture Open() => Futures.Completed;
            public IFuture Send(byte[] frame) => Futures.FromException(new InvalidOperationException("the peer is gone"));
            public IFuture<byte[]> Receive() { Received = true; return new Promise<byte[]>().Future; }
            public IFuture Close() { Closed = true; return Futures.Completed; }
        }

        [Fact]
        public async System.Threading.Tasks.Task A_lost_CE_write_ends_the_relay_and_names_the_write()
        {
            LinkListener padListener = new LinkListener(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = padListener.Accept();
            LostWriteLink link = new LostWriteLink();
            CeRunOptions options = new CeRunOptions();
            options.PinPad = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, padListener.Port);
            options.Link = link;
            options.Sink = new ListSink();
            options.Clock = new FixedClock(1);
            IFuture<CeRunResult> run = CeDeviceFlow.Run(options);

            Assert.True(await FutureWaits.Within(accepted, TimeSpan.FromMilliseconds(20000)));
            Assert.True(await FutureWaits.Within(FrameIo.WriteFrame(accepted.Result, Sell().Envelope.Bytes), TimeSpan.FromMilliseconds(20000)));

            Assert.True(await FutureWaits.Within(run, TimeSpan.FromMilliseconds(5000)), "the relay read after the lost write");
            accepted.Result.Close();
            padListener.Close();
            Assert.False(run.Result.Ok);
            Assert.Equal(ErrorCodes.LinkLost, run.Result.Code);
            Assert.False(link.Received);
            Assert.True(link.Closed);
        }

        static PadSale Sell(DukptPinPad pad = null) => PinPadCore.Sell(pad ?? NewPad(), "t1", Pin, Pan, new SeededRandom(5));

        [Fact]
        public void The_pad_key_follows_the_base_key_it_is_given()
        {
            Assert.Equal(PinPadCore.InjectedInitialKey, Hex.Encode(PinPadCore.InitialKeyUnder(Bdk)));
            byte[] other = (byte[])Bdk.Clone();
            other[0] ^= 1;
            Assert.NotEqual(PinPadCore.InjectedInitialKey, Hex.Encode(PinPadCore.InitialKeyUnder(other)));
        }

        [Fact]
        public void The_key_loaded_into_the_pad_is_the_one_the_bank_derives()
        {
            Assert.Equal(PinPadCore.InjectedInitialKey, Hex.Encode(DukptBank.DeriveInitialKey(Bdk, Hex.Decode(PinPadCore.InjectedKeyId))));
        }

        [Fact]
        public void A_refusal_before_the_mac_passes_keeps_the_claimed_trace_id_out_of_the_decision()
        {
            byte[] flipped = (byte[])Sell().Envelope.Bytes.Clone();
            flipped[flipped.Length - 1] ^= 1;
            BankDecision d = BankHsmCore.Decide(Bdk, new KsnLedger(), flipped);
            Assert.False(d.Ok);
            Assert.Null(d.TraceId);
            Assert.Contains("claims trace id", d.Detail);
        }

        sealed class OneLink : IByteLink
        {
            public int Writes;
            public bool Closed;
            public IFuture<int> Read(byte[] b, int off, int n) => Futures.FromResult(0);
            public IFuture Write(byte[] b, int off, int n) { Writes++; return Futures.Completed; }
            public void Close() { Closed = true; }
        }

        [Fact]
        public async System.Threading.Tasks.Task A_tunnel_with_no_bytes_opens_nothing_on_the_next_hop()
        {
            int opens = 0;
            FirstWriteOpensLink link = new FirstWriteOpensLink(() => { opens++; return Futures.FromResult<IByteLink>(new OneLink()); });
            IFuture<int> read = link.Read(new byte[4], 0, 4);
            Assert.False(read.IsCompleted);
            link.Close();
            Assert.True(await FutureWaits.Within(read, TimeSpan.FromMilliseconds(5000)));
            Assert.Equal(0, read.Result);
            Assert.Equal(0, opens);
        }

        [Fact]
        public async System.Threading.Tasks.Task The_first_write_opens_the_next_hop_once_and_the_close_reaches_it()
        {
            int opens = 0;
            OneLink inner = new OneLink();
            FirstWriteOpensLink link = new FirstWriteOpensLink(() => { opens++; return Futures.FromResult<IByteLink>(inner); });
            Assert.True(await FutureWaits.Within(link.Write(new byte[1], 0, 1), TimeSpan.FromMilliseconds(5000)));
            Assert.True(await FutureWaits.Within(link.Write(new byte[1], 0, 1), TimeSpan.FromMilliseconds(5000)));
            Assert.Equal(1, opens);
            Assert.Equal(2, inner.Writes);
            link.Close();
            for (int i = 0; i < 500 && !inner.Closed; i++) System.Threading.Thread.Sleep(10);
            Assert.True(inner.Closed);
        }

        [Fact]
        public void A_late_sink_holds_events_and_writes_them_in_order_under_the_id_it_learns()
        {
            ListSink inner = new ListSink();
            LateTraceSink late = new LateTraceSink(inner);
            TraceStream stream = new TraceStream("s/gateway/ssh", "s", null, "hop1", "gateway", new FixedClock(1));
            late.Write(stream.Stamp(new TraceEventDraft { Type = "wire.sent", Wire = new byte[] { 1 } }));
            late.Write(stream.Stamp(new TraceEventDraft { Type = "wire.sent", Wire = new byte[] { 2 } }));
            Assert.Empty(inner.Events);
            late.Learn("t1");
            late.Write(stream.Stamp(new TraceEventDraft { Type = "wire.sent", Wire = new byte[] { 3 } }));
            Assert.Equal(new[] { "t1", "t1", "t1" }, inner.Events.Select(e => e.TraceId).ToArray());
            Assert.Equal(new byte[] { 1, 2, 3 }, inner.Events.Select(e => e.Wire[0]).ToArray());
        }

        [Fact]
        public void A_late_sink_that_never_learns_still_writes_what_it_holds()
        {
            ListSink inner = new ListSink();
            LateTraceSink late = new LateTraceSink(inner);
            late.Write(new TraceStream("s", "s", null, "hop1", "gateway", new FixedClock(1)).Stamp(new TraceEventDraft { Type = "check.result" }));
            late.Flush();
            Assert.Null(Assert.Single(inner.Events).TraceId);
        }

        [Fact]
        public void The_bank_recovers_the_clear_field_the_pad_locked()
        {
            PadSale sale = Sell();
            BankDecision d = BankHsmCore.Decide(Bdk, new KsnLedger(), sale.Envelope.Bytes);
            Assert.True(d.Ok, d.Code + " " + d.Detail);
            Assert.Equal(sale.ClearField, d.ClearField);
            Assert.Equal("t1", d.TraceId);
        }

        [Fact]
        public void The_clear_field_and_the_keys_are_not_in_the_envelope()
        {
            PadSale sale = Sell();
            string envelope = Hex.Encode(sale.Envelope.Bytes);
            Assert.DoesNotContain(Hex.Encode(sale.ClearField), envelope);
            Assert.DoesNotContain(Hex.Encode(Bdk), envelope);
            Assert.DoesNotContain(Hex.Encode(DukptBank.DeriveWorkingKey(Bdk, sale.Envelope.Ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128)), envelope);
            Assert.DoesNotContain(Hex.Encode(DukptBank.DeriveWorkingKey(Bdk, sale.Envelope.Ksn, DukptKeyUsage.MacGeneration, DukptKeyType.Aes128)), envelope);
        }

        [Fact]
        public void A_flip_at_any_byte_of_the_envelope_is_refused_and_records_no_ksn()
        {
            PadSale sale = Sell();
            byte[] good = sale.Envelope.Bytes;
            for (int i = 0; i < good.Length; i++)
            {
                byte[] flipped = (byte[])good.Clone();
                flipped[i] ^= 1;
                KsnLedger ledger = new KsnLedger();
                BankDecision d = BankHsmCore.Decide(Bdk, ledger, flipped);
                Assert.False(d.Ok, "a flip at byte " + i + " passed");
                Assert.Contains(d.Code, new[] { ErrorCodes.DukptMacMismatch, ErrorCodes.EnvelopeMalformed });
                Assert.Equal(BankHsmCore.MacCheck, d.Check);
                // A refused envelope burns no KSN: neither the sale's KSN nor the KSN the flipped bytes name.
                Assert.False(ledger.Contains(sale.Envelope.Ksn), "a flip at byte " + i + " recorded the sale's KSN");
                byte[] namedKsn = null;
                try { namedKsn = PinEnvelope.Parse(flipped).Ksn; } catch (ParseFailure) { }
                if (namedKsn != null) Assert.False(ledger.Contains(namedKsn), "a flip at byte " + i + " recorded the KSN it names");
            }
            Assert.True(BankHsmCore.Decide(Bdk, new KsnLedger(), good).Ok);
        }

        [Fact]
        public void A_replayed_envelope_is_refused_by_name()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] envelope = Sell().Envelope.Bytes;
            Assert.True(BankHsmCore.Decide(Bdk, ledger, envelope).Ok);
            BankDecision again = BankHsmCore.Decide(Bdk, ledger, envelope);
            Assert.Equal(ErrorCodes.DukptKsnReplay, again.Code);
            Assert.Equal(BankHsmCore.ReplayCheck, again.Check);
        }

        /// <summary>The MAC holds and the block is bad, so only the format check refuses it. The real sale under the same KSN must still pass.</summary>
        [Fact]
        public void An_envelope_refused_at_the_format_check_does_not_burn_its_ksn()
        {
            KsnLedger ledger = new KsnLedger();
            PinEnvelope good = Sell().Envelope;
            byte[] macKey = DukptBank.DeriveWorkingKey(Bdk, good.Ksn, DukptKeyUsage.MacGeneration, DukptKeyType.Aes128);
            byte[] badBlock = (byte[])good.LockedBlock.Clone();
            badBlock[0] ^= 1;
            BankDecision refused = BankHsmCore.Decide(Bdk, ledger, PinEnvelope.Build("t1", Pan, good.Ksn, badBlock, macKey).Bytes);
            Assert.Equal(ErrorCodes.DukptPinBlockFormat, refused.Code);
            Assert.True(BankHsmCore.Decide(Bdk, ledger, good.Bytes).Ok);
        }

        [Fact]
        public void An_envelope_refused_at_the_mac_does_not_burn_its_ksn()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] good = Sell().Envelope.Bytes, flipped = (byte[])good.Clone();
            flipped[flipped.Length - 1] ^= 1;
            Assert.False(BankHsmCore.Decide(Bdk, ledger, flipped).Ok);
            Assert.True(BankHsmCore.Decide(Bdk, ledger, good).Ok);
        }

        [Fact]
        public void Each_sale_gets_its_own_ksn_and_keys_from_one_counter()
        {
            DukptPinPad pad = NewPad();
            byte[] before = Sell(pad).Envelope.Ksn, after = Sell(pad).Envelope.Ksn;
            Assert.NotEqual(before, after);
            Assert.Equal(1, before[11]);
            Assert.Equal(2, after[11]);
        }

        [Fact]
        public void Keys_taken_together_share_one_counter_and_match_the_bank()
        {
            DukptUse[] keys = NewPad().NextTogether(new[] { DukptKeyUsage.PinEncryption, DukptKeyUsage.MacGeneration }, DukptKeyType.Aes128);
            Assert.Equal(keys[0].Ksn, keys[1].Ksn);
            Assert.NotEqual(keys[0].Key, keys[1].Key);
            Assert.Equal(DukptBank.DeriveWorkingKey(Bdk, keys[0].Ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128), keys[0].Key);
            Assert.Equal(DukptBank.DeriveWorkingKey(Bdk, keys[1].Ksn, DukptKeyUsage.MacGeneration, DukptKeyType.Aes128), keys[1].Key);
        }

        [Theory]
        [InlineData("")]
        [InlineData("00")]
        [InlineData("01")]
        [InlineData("010174")]
        public void A_short_envelope_is_refused_by_name(string hex)
        {
            Assert.Equal(ErrorCodes.EnvelopeMalformed, BankHsmCore.Decide(Bdk, new KsnLedger(), Hex.Decode(hex)).Code);
        }

        [Fact]
        public async System.Threading.Tasks.Task Frames_cross_a_link_and_a_close_at_a_boundary_reads_as_null()
        {
            MemoryLink[] links = MemoryLink.Pair();
            await Make.Done(FrameIo.WriteFrame(links[0], new byte[] { 1, 2, 3 }));
            IFuture<byte[]> first = FrameIo.ReadFrame(links[1]);
            await Make.Done(first);
            Assert.Equal(new byte[] { 1, 2, 3 }, first.Result);
            links[0].Close();
            IFuture<byte[]> second = FrameIo.ReadFrame(links[1]);
            await Make.Done(second);
            Assert.Null(second.Result);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_frame_header_with_a_huge_length_faults_the_read()
        {
            MemoryLink[] links = MemoryLink.Pair();
            await Make.Done(links[0].Write(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }, 0, 4));
            IFuture<byte[]> read = FrameIo.ReadFrame(links[1]);
            await Make.Done(read);
            Assert.True(read.IsFaulted);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_close_inside_a_frame_faults_the_read()
        {
            MemoryLink[] links = MemoryLink.Pair();
            await Make.Done(links[0].Write(new byte[] { 0, 0, 0, 9, 1, 2 }, 0, 6));
            links[0].Close();
            IFuture<byte[]> read = FrameIo.ReadFrame(links[1]);
            await Make.Done(read);
            Assert.True(read.IsFaulted);
        }

        [Theory]
        [InlineData(25, 2, 1000L, true)]
        [InlineData(26, 2, 1000L, false)]
        [InlineData(25, 3, 1000L, false)]
        [InlineData(25, 2, 64L * 1024 * 1024 + 1, false)]
        public void The_budget_judge_gates_the_three_numbers_that_transfer(int pool, int threads, long heap, bool within)
        {
            BudgetVerdict v = BudgetJudge.Judge(DeviceProfile.Ce, new BudgetSample { PoolWorkersGranted = pool, DedicatedThreads = threads, ManagedHeapBytes = heap });
            Assert.Equal(within, v.Within);
            Assert.Equal(within, v.Detail == null);
        }
    }
}
