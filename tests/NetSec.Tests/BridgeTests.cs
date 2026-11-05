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
using Xunit;

namespace NetSec.Tests
{
    public class BridgeCoreTests
    {
        const string Pin = "1234", Pan = "4111111111111111";
        static readonly byte[] KeyId = Hex.Decode("1234567890123456");
        static readonly byte[] Bdk = new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial();

        static DukptPinPad NewPad() => new DukptPinPad(DukptBank.DeriveInitialKey(Bdk, KeyId), KeyId);
        static PadSale Sell(DukptPinPad pad = null) => PinPadCore.Sell(pad ?? NewPad(), "t1", Pin, Pan, new SeededRandom(5));

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
            byte[] good = Sell().Envelope.Bytes;
            for (int i = 0; i < good.Length; i++)
            {
                byte[] flipped = (byte[])good.Clone();
                flipped[i] ^= 1;
                KsnLedger ledger = new KsnLedger();
                BankDecision d = BankHsmCore.Decide(Bdk, ledger, flipped);
                Assert.False(d.Ok, "a flip at byte " + i + " passed");
                Assert.Contains(d.Code, new[] { ErrorCodes.DukptMacMismatch, ErrorCodes.EnvelopeMalformed });
                Assert.Equal(BankHsmCore.MacCheck, d.Check);
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
        public void Frames_cross_a_link_and_a_close_at_a_boundary_reads_as_null()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Make.Done(FrameIo.WriteFrame(links[0], new byte[] { 1, 2, 3 }));
            IFuture<byte[]> first = FrameIo.ReadFrame(links[1]);
            Make.Done(first);
            Assert.Equal(new byte[] { 1, 2, 3 }, first.Result);
            links[0].Close();
            IFuture<byte[]> second = FrameIo.ReadFrame(links[1]);
            Make.Done(second);
            Assert.Null(second.Result);
        }

        [Fact]
        public void A_frame_header_with_a_huge_length_faults_the_read()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Make.Done(links[0].Write(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }, 0, 4));
            IFuture<byte[]> read = FrameIo.ReadFrame(links[1]);
            Make.Done(read);
            Assert.True(read.IsFaulted);
        }

        [Fact]
        public void A_close_inside_a_frame_faults_the_read()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Make.Done(links[0].Write(new byte[] { 0, 0, 0, 9, 1, 2 }, 0, 6));
            links[0].Close();
            IFuture<byte[]> read = FrameIo.ReadFrame(links[1]);
            Make.Done(read);
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
