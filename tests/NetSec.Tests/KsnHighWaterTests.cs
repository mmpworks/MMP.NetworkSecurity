using System;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Keys;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// The bank's KSN ledger keeps a high-water mark per device (initial key ID). A counter at or below the highest
    /// counter the bank accepted from that device is refused, seen or not. A gap ahead is accepted. An exact repeat
    /// keeps its own code. The ledger records a KSN only after the sale's check passes, and a failed check answers
    /// the same way whether or not the bank has seen the KSN.
    /// </summary>
    public class KsnHighWaterTests
    {
        const DukptKeyType Aes128 = DukptKeyType.Aes128;
        const string Pan = "4111111111111111";
        static readonly byte[] DeviceA = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
        static readonly byte[] DeviceB = { 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x02 };
        static readonly byte[] Random8 = { 1, 2, 3, 4, 5, 6, 7, 8 };

        static byte[] Bdk() { return new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial(); }

        static byte[] Ksn(byte[] device, uint counter)
        {
            byte[] ksn = new byte[12];
            Array.Copy(device, ksn, 8);
            ksn[8] = (byte)(counter >> 24);
            ksn[9] = (byte)(counter >> 16);
            ksn[10] = (byte)(counter >> 8);
            ksn[11] = (byte)counter;
            return ksn;
        }

        static byte[] Block(byte[] ksn, string pin)
        {
            return PinBlock.EncryptFormat4(DukptBank.DeriveWorkingKey(Bdk(), ksn, DukptKeyUsage.PinEncryption, Aes128), pin, Pan, Random8);
        }

        static string Open(KsnLedger ledger, byte[] device, uint counter)
        {
            byte[] ksn = Ksn(device, counter);
            return DukptBank.OpenPinSale(Bdk(), ledger, ksn, Block(ksn, "1234"), Pan, Aes128).Code;
        }

        [Fact]
        public void An_older_counter_the_bank_never_saw_is_refused_as_stale()
        {
            KsnLedger ledger = new KsnLedger();
            Assert.Null(Open(ledger, DeviceA, 2));

            Assert.Equal(ErrorCodes.DukptKsnStale, Open(ledger, DeviceA, 1));
        }

        [Fact]
        public void A_gap_ahead_is_accepted()
        {
            KsnLedger ledger = new KsnLedger();
            Assert.Null(Open(ledger, DeviceA, 1));
            Assert.Null(Open(ledger, DeviceA, 5));
            Assert.Null(Open(ledger, DeviceA, 0x845FED));
        }

        [Fact]
        public void An_exact_repeat_keeps_the_replay_code_even_below_the_mark()
        {
            KsnLedger ledger = new KsnLedger();
            Assert.Null(Open(ledger, DeviceA, 3));
            Assert.Null(Open(ledger, DeviceA, 4));

            Assert.Equal(ErrorCodes.DukptKsnReplay, Open(ledger, DeviceA, 4));
            Assert.Equal(ErrorCodes.DukptKsnReplay, Open(ledger, DeviceA, 3));
        }

        [Fact]
        public void Two_devices_keep_separate_marks()
        {
            KsnLedger ledger = new KsnLedger();
            Assert.Null(Open(ledger, DeviceA, 9));
            Assert.Null(Open(ledger, DeviceB, 1));
            Assert.Equal(ErrorCodes.DukptKsnStale, Open(ledger, DeviceA, 8));
            Assert.Null(Open(ledger, DeviceB, 2));
        }

        [Fact]
        public void A_ksn_whose_check_failed_is_not_recorded_and_raises_no_mark()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] ksn7 = Ksn(DeviceA, 7);
            byte[] forged = Block(ksn7, "1234");
            forged[5] ^= 1;
            Assert.Equal(ErrorCodes.DukptPinBlockFormat, DukptBank.OpenPinSale(Bdk(), ledger, ksn7, forged, Pan, Aes128).Code);

            Assert.False(ledger.Contains(ksn7));
            Assert.Null(ledger.RefusalFor(ksn7));
            Assert.Null(Open(ledger, DeviceA, 3));   // counter 7 failed, so 3 is still above the mark
        }

        [Fact]
        public void A_forged_block_under_a_seen_ksn_gets_the_same_answer_as_under_an_unseen_one()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] seen = Ksn(DeviceA, 1);
            byte[] unseen = Ksn(DeviceA, 2);
            Assert.Null(Open(ledger, DeviceA, 1));
            byte[] forgedSeen = Block(seen, "1234");
            forgedSeen[0] ^= 1;
            byte[] forgedUnseen = Block(unseen, "1234");
            forgedUnseen[0] ^= 1;

            PinSale onSeen = DukptBank.CheckPinSale(Bdk(), ledger, seen, forgedSeen, Pan, Aes128);
            PinSale onUnseen = DukptBank.CheckPinSale(Bdk(), ledger, unseen, forgedUnseen, Pan, Aes128);

            Assert.Equal(ErrorCodes.DukptPinBlockFormat, onSeen.Code);
            Assert.Equal(onUnseen.Code, onSeen.Code);
            Assert.Null(onSeen.Pin);
            Assert.Null(onSeen.Key);
        }

        [Fact]
        public void The_mark_is_per_device_and_reported()
        {
            KsnLedger ledger = new KsnLedger();
            Assert.False(ledger.HasMark(DeviceA));
            ledger.Record(Ksn(DeviceA, 6));
            ledger.Record(Ksn(DeviceA, 4));
            Assert.True(ledger.HasMark(DeviceA));
            Assert.Equal(6u, ledger.HighestCounter(DeviceA));
            Assert.False(ledger.HasMark(DeviceB));
        }

        [Fact]
        public void A_ksn_of_the_wrong_size_is_refused_before_any_byte_is_read()
        {
            KsnLedger ledger = new KsnLedger();
            ledger.Record(Ksn(DeviceA, 3));
            byte[] shortKsn = new byte[7];
            byte[] longKsn = new byte[13];
            Assert.Throws<ArgumentNullException>(() => ledger.RefusalFor(null));
            Assert.Throws<ArgumentNullException>(() => ledger.Record(null));
            Assert.Throws<ArgumentNullException>(() => ledger.Contains(null));
            Assert.Throws<ArgumentException>(() => ledger.RefusalFor(shortKsn));
            Assert.Throws<ArgumentException>(() => ledger.RefusalFor(longKsn));
            Assert.Throws<ArgumentException>(() => ledger.Record(shortKsn));
            Assert.Throws<ArgumentException>(() => ledger.Contains(shortKsn));
            // The refused calls changed nothing.
            Assert.Equal(3u, ledger.HighestCounter(DeviceA));
            Assert.Null(ledger.RefusalFor(Ksn(DeviceA, 4)));
        }
    }
}
