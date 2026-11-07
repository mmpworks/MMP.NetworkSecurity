using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Slice W1b: the typed block and the longer text (docs/walkthrough-design.md sections 2.2g and 2.4c). The BCL's AES is the referee for the cipher bytes.</summary>
    public class AesTypedWalksTests
    {
        [Fact]
        public void A_short_text_is_padded_with_lesson_1s_rule()
        {
            AesTypedBlock b = AesTypedBlocks.Cut("Pump");
            Assert.Equal(4, b.UsedBytes);
            Assert.Equal(12, b.PaddingBytes);
            Assert.Equal(0, b.NotIncludedBytes);
            Assert.Equal("50756d700c0c0c0c0c0c0c0c0c0c0c0c", Hex.Encode(b.Block));
        }

        [Fact]
        public void Sixteen_bytes_take_no_padding_in_the_one_block_view()
        {
            AesTypedBlock b = AesTypedBlocks.Cut("Pump four is ok.");
            Assert.Equal(16, b.UsedBytes);
            Assert.Equal(0, b.PaddingBytes);
            Assert.Equal(0, b.NotIncludedBytes);
            Assert.Equal(Encoding.ASCII.GetBytes("Pump four is ok."), b.Block);
        }

        [Fact]
        public void Bytes_past_16_count_as_not_included()
        {
            AesTypedBlock b = AesTypedBlocks.Cut("Pump four is ok. More");
            Assert.Equal(16, b.UsedBytes);
            Assert.Equal(5, b.NotIncludedBytes);
            Assert.Equal(0, b.SplitCharacterBytesIn);
        }

        [Theory]
        [InlineData("123456789012345é", 1, 1)]      // A 2-byte character starts at byte 15
        [InlineData("12345678901234€", 2, 1)]       // A 3-byte character starts at byte 14
        [InlineData("1234567890123\U0001F600", 3, 1)]    // A 4-byte character starts at byte 13
        [InlineData("1234567890123456é", 0, 2)]     // The character starts at byte 16, so the cut falls between characters
        [InlineData("12345678901234é", 0, 0)]       // The character ends at byte 16
        public void A_character_that_crosses_byte_16_is_cut_at_the_byte(string text, int bytesIn, int notIncluded)
        {
            AesTypedBlock b = AesTypedBlocks.Cut(text);
            Assert.Equal(bytesIn, b.SplitCharacterBytesIn);
            Assert.Equal(notIncluded, b.NotIncludedBytes);
            Assert.Equal(Encoding.UTF8.GetBytes(text).Take(16).ToArray(), b.Block.Take(b.UsedBytes).ToArray());
        }

        [Fact]
        public void The_text_rules_refuse_with_named_codes()
        {
            Assert.Equal(ErrorCodes.WalkTextEmpty, Assert.Throws<NetSecException>(() => AesTypedBlocks.Cut("")).Error.Code);
            Assert.Equal(ErrorCodes.WalkTextInvalid, Assert.Throws<NetSecException>(() => AesTypedBlocks.Cut("ab\ud800cd")).Error.Code);
            Assert.Equal(ErrorCodes.WalkTextTooLong, Assert.Throws<NetSecException>(() => AesTypedText.Bytes(new string('a', AesTypedText.MaxBytes + 1))).Error.Code);
            Assert.Equal(AesTypedText.MaxBytes, AesTypedText.Bytes(new string('a', AesTypedText.MaxBytes)).Length);
        }

        [Fact]
        public void The_practice_key_and_iv_are_fixed_and_differ_by_size()
        {
            Assert.Equal(16, AesPractice.Key(128).Length);
            Assert.Equal(24, AesPractice.Key(192).Length);
            Assert.Equal(32, AesPractice.Key(256).Length);
            Assert.Equal(AesPractice.Key(128), AesPractice.Key(128));
            Assert.NotEqual(AesPractice.Key(128), AesPractice.Key(256).Take(16).ToArray());
            Assert.NotEqual(AesPractice.Key(128), AesPractice.Iv());
        }

        [Fact]
        public void The_longer_text_matches_the_BCLs_ECB_and_CBC_with_PKCS7()
        {
            byte[] key = AesPractice.Key(128), iv = AesPractice.Iv();
            byte[] text = Encoding.UTF8.GetBytes("Pump four is ok. Pump four is ok. Pump five is not.");
            AesLongTextView v = AesLongText.Build(key, iv, text, -1, 0);
            Assert.Equal(Bcl(key, null, text), v.Rows.SelectMany(r => r.Ecb).ToArray());
            Assert.Equal(Bcl(key, iv, text), v.Rows.SelectMany(r => r.Cbc).ToArray());
            Assert.Null(v.FlippedRows);
        }

        /// <summary>The BCL's AES with PKCS7. A null IV means ECB. CreateEncryptor runs on net48 and net10.</summary>
        static byte[] Bcl(byte[] key, byte[] iv, byte[] text)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = iv == null ? CipherMode.ECB : CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                if (iv != null) aes.IV = iv;
                using (ICryptoTransform t = aes.CreateEncryptor()) return t.TransformFinalBlock(text, 0, text.Length);
            }
        }

        [Theory]
        [InlineData(192)]
        [InlineData(256)]
        public void The_longer_text_matches_the_BCL_at_192_and_256_bits(int keyBits)
        {
            byte[] key = AesPractice.Key(keyBits), iv = AesPractice.Iv();
            byte[] text = Encoding.UTF8.GetBytes("Pump four is ok. Pump four is ok. Pump five is not.");
            AesLongTextView v = AesLongText.Build(key, iv, text, -1, 0);
            Assert.Equal(Bcl(key, null, text), v.Rows.SelectMany(r => r.Ecb).ToArray());
            Assert.Equal(Bcl(key, iv, text), v.Rows.SelectMany(r => r.Cbc).ToArray());
        }

        [Fact]
        public void Repeated_blocks_repeat_under_ECB_and_not_under_CBC()
        {
            byte[] text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("Pump four is ok.", 3)));
            AesLongTextView v = AesLongText.Build(AesPractice.Key(128), AesPractice.Iv(), text, -1, 0);
            Assert.Equal(4, v.Rows.Length);                  // 3 text blocks and 1 full padding block
            Assert.Equal(2, v.EcbRepeats);
            Assert.Equal(0, v.CbcRepeats);
            Assert.Equal(new[] { false, true, true, false }, v.Rows.Select(r => r.EcbRepeat).ToArray());
        }

        [Fact]
        public void A_flip_in_block_0_changes_one_ECB_block_and_every_CBC_block()
        {
            byte[] text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("Pump four is ok.", 3)));
            AesLongTextView v = AesLongText.Build(AesPractice.Key(128), AesPractice.Iv(), text, 0, 0);
            Assert.Equal(1, v.EcbBlocksChanged);
            Assert.Equal(4, v.CbcBlocksChanged);
            Assert.True(v.FlippedRows[0].EcbBitsChanged > 0);
            Assert.Equal(0, v.FlippedRows[1].EcbBitsChanged);
            Assert.Equal((byte)('P' ^ 0x80), v.FlippedRows[0].Data[0]);
        }

        [Theory]
        [InlineData(0, 32)]      // Byte 4 of "Pump" is padding
        [InlineData(0, 128)]     // Past the block
        [InlineData(1, 0)]       // Block 1 does not exist in a 4-byte text
        [InlineData(-2, 0)]
        [InlineData(268435456, 0)]   // x 16 wraps to 0 in an int: it must not flip block 0
        [InlineData(134217729, 0)]   // x 16 wraps negative in an int: it must not index the array
        [InlineData(int.MaxValue, 127)]
        public void A_flip_off_the_text_is_refused(int flipBlock, int flipBit)
        {
            NetSecException e = Assert.Throws<NetSecException>(() =>
                AesLongText.Build(AesPractice.Key(128), AesPractice.Iv(), Encoding.ASCII.GetBytes("Pump"), flipBlock, flipBit));
            Assert.Equal(ErrorCodes.WalkBadArgument, e.Error.Code);
        }
    }
}
