using System;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Keys;
using Xunit;

namespace NetSec.Tests
{
    public class DukptTests
    {
        const DukptKeyUsage Pin = DukptKeyUsage.PinEncryption;
        const DukptKeyType Aes128 = DukptKeyType.Aes128;
        const string Pan = "4111111111111111";

        static readonly byte[] KeyId = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
        static readonly byte[] Random8 = { 1, 2, 3, 4, 5, 6, 7, 8 };

        static byte[] Bdk() { return new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial(); }

        static DukptPinPad NewPad() { return new DukptPinPad(DukptBank.DeriveInitialKey(Bdk(), KeyId), KeyId); }

        static uint CounterOf(byte[] ksn) { return ((uint)ksn[8] << 24) | ((uint)ksn[9] << 16) | ((uint)ksn[10] << 8) | ksn[11]; }

        static byte[] WorkingKey(uint counter)
        {
            byte[] ksn = new byte[12];
            Array.Copy(KeyId, ksn, 8);
            ksn[8] = (byte)(counter >> 24);
            ksn[9] = (byte)(counter >> 16);
            ksn[10] = (byte)(counter >> 8);
            ksn[11] = (byte)counter;
            return DukptBank.DeriveWorkingKey(Bdk(), ksn, Pin, Aes128);
        }

        [Fact]
        public void The_register_count_follows_the_counter()
        {
            DukptPinPad pad = NewPad();
            Assert.Equal(32, pad.HeldKeys().Length);
            int[] heldAfterSale = { 31, 31, 30, 31, 30, 30, 29, 31 };
            for (int i = 0; i < heldAfterSale.Length; i++)
            {
                Assert.Equal((uint)(i + 1), CounterOf(pad.Next(Pin, Aes128).Ksn));
                Assert.Equal(heldAfterSale[i], pad.HeldKeys().Length);
            }
        }

        [Fact]
        public void A_counter_past_the_one_bit_limit_is_skipped_and_both_sides_still_agree()
        {
            DukptPinPad pad = NewPad();
            DukptUse use = null;
            for (int i = 0; i < 0xFFFF; i++) use = pad.Next(Pin, Aes128);
            Assert.Equal(0xFFFFu, CounterOf(use.Ksn));
            Assert.Equal(WorkingKey(0xFFFF), use.Key);

            DukptUse next = pad.Next(Pin, Aes128);
            Assert.Equal(0x10000u, CounterOf(next.Ksn));
            Assert.Equal(WorkingKey(0x10000), next.Key);
        }

        [Fact]
        public void A_counter_at_the_one_bit_limit_with_a_low_bit_clear_skips_the_values_below_that_bit()
        {
            // 0x1FFFE has 16 one bits and lowest bit 1. Adding that bit gives 0x20000. The value 0x1FFFF has 17 one bits, so it never runs.
            DukptPinPad pad = NewPad();
            while (pad.NextCounter != 0x1FFFE) pad.Next(Pin, Aes128);
            DukptUse use = pad.Next(Pin, Aes128);
            Assert.Equal(0x1FFFEu, CounterOf(use.Ksn));
            Assert.Equal(WorkingKey(0x1FFFE), use.Key);
            Assert.Equal(0x20000UL, pad.NextCounter);
            Assert.Equal(WorkingKey(0x20000), pad.Next(Pin, Aes128).Key);
        }

        [Fact]
        public void The_reader_cannot_rebuild_a_used_key_from_its_registers()
        {
            DukptPinPad pad = NewPad();
            for (uint sale = 1; sale <= 200; sale++)
            {
                pad.Next(Pin, Aes128);
                for (uint past = 1; past <= sale; past++)
                {
                    byte[] key;
                    Assert.False(pad.TryDeriveFromHeldKeys(past, Pin, Aes128, out key), "sale " + sale + " rebuilt the key of counter " + past);
                    Assert.Null(key);
                }
            }
        }

        [Fact]
        public void The_reader_can_build_a_later_key_from_its_registers()
        {
            DukptPinPad pad = NewPad();
            for (int i = 0; i < 37; i++) pad.Next(Pin, Aes128);
            foreach (uint later in new uint[] { 38, 39, 40, 64, 1000, 65535, 0x80000000 })
            {
                byte[] key;
                Assert.True(pad.TryDeriveFromHeldKeys(later, Pin, Aes128, out key), "counter " + later);
                Assert.Equal(WorkingKey(later), key);
            }
        }

        [Fact]
        public void A_later_key_lookup_leaves_the_next_sale_unchanged()
        {
            DukptPinPad pad = NewPad();
            byte[] key;
            pad.TryDeriveFromHeldKeys(100, Pin, Aes128, out key);
            Assert.Equal(WorkingKey(1), pad.Next(Pin, Aes128).Key);
        }

        [Fact]
        public void Held_keys_are_copies()
        {
            DukptPinPad pad = NewPad();
            pad.HeldKeys()[0][0] ^= 1;
            Assert.Equal(WorkingKey(1), pad.Next(Pin, Aes128).Key);
        }

        [Fact]
        public void The_pad_leaves_the_callers_initial_key_alone()
        {
            byte[] initial = DukptBank.DeriveInitialKey(Bdk(), KeyId);
            byte[] copy = (byte[])initial.Clone();
            new DukptPinPad(initial, KeyId).Next(Pin, Aes128);
            Assert.Equal(copy, initial);
        }

        [Theory]
        [InlineData(15, 8)]
        [InlineData(17, 8)]
        [InlineData(16, 7)]
        [InlineData(16, 9)]
        public void A_wrong_size_is_refused(int keySize, int idSize)
        {
            Assert.Throws<ArgumentException>(() => new DukptPinPad(new byte[keySize], new byte[idSize]));
        }

        [Fact]
        public void A_ksn_of_the_wrong_size_is_refused()
        {
            Assert.Throws<ArgumentException>(() => DukptBank.DeriveWorkingKey(Bdk(), new byte[11], Pin, Aes128));
        }

        [Fact]
        public void The_ledger_refuses_a_ksn_it_has_seen()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] first = new byte[12];
            byte[] second = new byte[12];
            second[11] = 1;
            Assert.False(ledger.Contains(first));
            ledger.Record(first);
            Assert.True(ledger.Contains((byte[])first.Clone()));
            Assert.False(ledger.Contains(second));
        }

        static byte[] KsnOf(uint counter)
        {
            byte[] ksn = new byte[12];
            Array.Copy(KeyId, ksn, 8);
            ksn[8] = (byte)(counter >> 24);
            ksn[9] = (byte)(counter >> 16);
            ksn[10] = (byte)(counter >> 8);
            ksn[11] = (byte)counter;
            return ksn;
        }

        [Fact]
        public void A_forged_block_leaves_the_ksn_free_for_the_real_sale()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] ksn = KsnOf(1);
            byte[] real = PinBlock.EncryptFormat4(WorkingKey(1), "1234", Pan, Random8);
            byte[] forged = (byte[])real.Clone();
            forged[3] ^= 1;

            Assert.Equal(ErrorCodes.DukptPinBlockFormat, DukptBank.OpenPinSale(Bdk(), ledger, ksn, forged, Pan, Aes128).Code);
            PinSale opened = DukptBank.OpenPinSale(Bdk(), ledger, ksn, real, Pan, Aes128);
            Assert.Null(opened.Code);
            Assert.Equal("1234", opened.Pin);
            Assert.Equal(WorkingKey(1), opened.Key);
            Assert.Equal(1u, opened.Counter);

            Assert.Equal(ErrorCodes.DukptKsnReplay, DukptBank.OpenPinSale(Bdk(), ledger, ksn, real, Pan, Aes128).Code);
        }

        [Fact]
        public void Checking_a_sale_records_nothing_and_a_refused_replay_opens_no_pin()
        {
            KsnLedger ledger = new KsnLedger();
            byte[] ksn = KsnOf(1);
            byte[] real = PinBlock.EncryptFormat4(WorkingKey(1), "1234", Pan, Random8);
            Assert.Null(DukptBank.CheckPinSale(Bdk(), ledger, ksn, real, Pan, Aes128).Code);
            Assert.False(ledger.Contains(ksn));

            ledger.Record(ksn);
            PinSale replay = DukptBank.CheckPinSale(Bdk(), ledger, ksn, real, Pan, Aes128);
            Assert.Equal(ErrorCodes.DukptKsnReplay, replay.Code);
            Assert.Null(replay.Pin);
            Assert.Null(replay.Key);
        }

        [Fact]
        public void The_held_count_matches_the_registers()
        {
            DukptPinPad pad = NewPad();
            Assert.Equal(32, pad.HeldCount);
            for (int i = 0; i < 300; i++)
            {
                pad.Next(Pin, Aes128);
                Assert.Equal(pad.HeldKeys().Length, pad.HeldCount);
            }
        }

        /// <summary>The range ends after counter 0xFFFF0000: it has 16 one bits, and adding its lowest bit passes 32 bits. The key from the last register still matches the bank.</summary>
        [Fact]
        public void The_counter_ends_with_a_named_error_and_never_wraps()
        {
            const uint last = 0xFFFF0000;
            byte[] initial = DukptBank.DeriveInitialKey(Bdk(), KeyId);
            byte[] derivationKey = DukptDerivation.WalkDown(initial, KeyId, last, 32);
            DukptPinPad pad = new DukptPinPad(derivationKey, KeyId, last);

            DukptUse use = pad.Next(Pin, Aes128);
            Assert.Equal(last, CounterOf(use.Ksn));
            Assert.Equal(WorkingKey(last), use.Key);
            Assert.Equal(0x100000000UL, pad.NextCounter);
            Assert.Equal(0, pad.HeldCount);

            for (int i = 0; i < 2; i++)
            {
                NetSecException error = Assert.Throws<NetSecException>(() => pad.Next(Pin, Aes128));
                Assert.Equal(ErrorCodes.DukptCounterExhausted, error.Error.Code);
            }
        }

        [Fact]
        public void Loading_the_lab_reader_clears_the_initial_key_array()
        {
            byte[] initial = DukptBank.DeriveInitialKey(Bdk(), KeyId);
            byte[] expected = (byte[])initial.Clone();
            byte[] traceCopy;
            DukptPinPad pad = NetSec.Labs.Lesson06Dukpt.LoadReader(initial, out traceCopy);
            Assert.Equal(new byte[expected.Length], initial);
            Assert.Equal(expected, traceCopy);
            Assert.Equal(32, pad.HeldCount);
        }

        [Theory]
        [InlineData("1234", "4111111111111111")]
        [InlineData("123456789012", "4111111111111111")]
        [InlineData("0000", "1234567890123456789")]
        [InlineData("9876", "123456789012")]
        [InlineData("9876", "12345")]
        public void A_pin_block_opens_with_the_same_key_and_pan(string pin, string pan)
        {
            byte[] key = WorkingKey(1);
            byte[] block = PinBlock.EncryptFormat4(key, pin, pan, Random8);
            string back;
            Assert.True(PinBlock.TryDecryptFormat4(key, block, pan, out back));
            Assert.Equal(pin, back);
        }

        [Fact]
        public void A_changed_block_fails_the_format_check_at_every_byte()
        {
            byte[] key = WorkingKey(1);
            byte[] block = PinBlock.EncryptFormat4(key, "1234", Pan, Random8);
            for (int i = 0; i < block.Length; i++)
            {
                byte[] changed = (byte[])block.Clone();
                changed[i] ^= 1;
                string back;
                Assert.False(PinBlock.TryDecryptFormat4(key, changed, Pan, out back), "byte " + i);
                Assert.Null(back);
            }
        }

        [Fact]
        public void A_wrong_key_or_pan_fails_the_format_check()
        {
            byte[] block = PinBlock.EncryptFormat4(WorkingKey(1), "1234", Pan, Random8);
            string back;
            Assert.False(PinBlock.TryDecryptFormat4(WorkingKey(2), block, Pan, out back));
            Assert.False(PinBlock.TryDecryptFormat4(WorkingKey(1), block, "4111111111111112", out back));
        }

        [Fact]
        public void A_block_of_the_wrong_length_is_a_format_failure()
        {
            string back;
            Assert.False(PinBlock.TryDecryptFormat4(WorkingKey(1), new byte[15], Pan, out back));
        }

        [Fact]
        public void Other_random_bytes_give_another_block_for_the_same_pin()
        {
            byte[] key = WorkingKey(1);
            byte[] other = { 8, 7, 6, 5, 4, 3, 2, 1 };
            Assert.NotEqual(PinBlock.EncryptFormat4(key, "1234", Pan, Random8), PinBlock.EncryptFormat4(key, "1234", Pan, other));
        }

        [Theory]
        [InlineData("123")]
        [InlineData("1234567890123")]
        [InlineData("12a4")]
        public void A_bad_pin_is_refused(string pin)
        {
            Assert.Throws<ArgumentException>(() => PinBlock.EncryptFormat4(WorkingKey(1), pin, Pan, Random8));
        }

        [Theory]
        [InlineData("")]
        [InlineData("12345678901234567890")]
        [InlineData("41111x")]
        public void A_bad_pan_is_refused(string pan)
        {
            Assert.Throws<ArgumentException>(() => PinBlock.EncryptFormat4(WorkingKey(1), "1234", pan, Random8));
        }
    }
}
