using System;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>
    /// The practice key and IV for text a learner types (docs/walkthrough-design.md section 2.2g). Public by design: each comes from a label by SHAKE256,
    /// as TrainingKeySource does, so the key is in the source and protects nothing. The course never locks typed text under a run's key.
    /// </summary>
    public static class AesPractice
    {
        const string Label = "MMP.NetworkSecurity practice ";

        public static byte[] Key(int keyBits)
        {
            if (keyBits != 128 && keyBits != 192 && keyBits != 256) throw new ArgumentOutOfRangeException("keyBits");
            return Derive("key " + keyBits, keyBits / 8);
        }

        public static byte[] Iv() { return Derive("iv", 16); }

        static byte[] Derive(string name, int length)
        {
            byte[] input = Encoding.UTF8.GetBytes(Label + name);
            Shake shake = Shake.New256();
            shake.Absorb(input, 0, input.Length);
            byte[] output = new byte[length];
            shake.Squeeze(output, 0, length);
            return output;
        }
    }

    /// <summary>Chapter 1's block, cut from one typed string.</summary>
    public sealed class AesTypedBlock
    {
        /// <summary>Always 16 bytes.</summary>
        public byte[] Block;
        public int UsedBytes, PaddingBytes, NotIncludedBytes;

        /// <summary>The bytes of the character that crosses byte 16 that are in the block. Zero when no character crosses it.</summary>
        public int SplitCharacterBytesIn;
    }

    /// <summary>Text as UTF-8 bytes, with the Host's limit. Pure.</summary>
    public static class AesTypedText
    {
        public const int MaxBytes = 65536;

        /// <summary>The UTF-8 bytes of text. Empty, too long, or not valid Unicode is a named refusal.</summary>
        public static byte[] Bytes(string text)
        {
            if (string.IsNullOrEmpty(text)) throw Refuse(ErrorCodes.WalkTextEmpty, "Type some text first.");
            byte[] bytes;
            try { bytes = new UTF8Encoding(false, true).GetBytes(text); }
            catch (ArgumentException) { throw Refuse(ErrorCodes.WalkTextInvalid, "This text holds a broken character, so it has no UTF-8 form."); }
            if (bytes.Length > MaxBytes) throw Refuse(ErrorCodes.WalkTextTooLong, "This view reads at most " + MaxBytes + " bytes of text.");
            return bytes;
        }

        internal static NetSecException Refuse(string code, string message) { return new NetSecException(NetSecError.Of(code, message)); }
    }

    public static class AesTypedBlocks
    {
        const int BlockSize = 16;

        /// <summary>
        /// The first 16 bytes of the text, or all of it with padding when it is shorter. The padding is lesson 1's rule: n bytes, each of value n. A text of
        /// 16 bytes or more takes no padding in this one-block view. A character that crosses byte 16 is cut there, and its other bytes count as not included.
        /// </summary>
        public static AesTypedBlock Cut(string text)
        {
            byte[] bytes = AesTypedText.Bytes(text);
            AesTypedBlock b = new AesTypedBlock();
            b.UsedBytes = Math.Min(bytes.Length, BlockSize);
            b.PaddingBytes = BlockSize - b.UsedBytes;
            b.NotIncludedBytes = bytes.Length - b.UsedBytes;
            b.Block = new byte[BlockSize];
            Buffer.BlockCopy(bytes, 0, b.Block, 0, b.UsedBytes);
            for (int i = b.UsedBytes; i < BlockSize; i++) b.Block[i] = (byte)b.PaddingBytes;
            b.SplitCharacterBytesIn = SplitAt(bytes, BlockSize);
            return b;
        }

        /// <summary>The bytes before the cut of the character that the cut falls inside. Zero when the cut falls on a character start or past the end.</summary>
        static int SplitAt(byte[] bytes, int cut)
        {
            if (bytes.Length <= cut) return 0;
            // A UTF-8 continuation byte has the bits 10xxxxxx. The cut splits a character when the byte after it continues one.
            if ((bytes[cut] & 0xC0) != 0x80) return 0;
            int start = cut - 1;
            while (start > 0 && (bytes[start] & 0xC0) == 0x80) start--;
            return cut - start;
        }
    }

    /// <summary>One padded block of the longer text, under ECB and under CBC.</summary>
    public sealed class AesLongTextRow
    {
        public int Block;
        public byte[] Data, Ecb, Cbc;

        /// <summary>True when an earlier block of the same mode holds the same cipher bytes.</summary>
        public bool EcbRepeat, CbcRepeat;

        /// <summary>Zero when no flip was asked.</summary>
        public int EcbBitsChanged, CbcBitsChanged;
    }

    /// <summary>A repeat count is blocks minus distinct blocks, as Lesson01Aes.MeasureBlocks counts.</summary>
    public sealed class AesLongTextView
    {
        public AesLongTextRow[] Rows;

        /// <summary>Null when no flip was asked.</summary>
        public AesLongTextRow[] FlippedRows;
        public int EcbRepeats, CbcRepeats, EcbBlocksChanged, CbcBlocksChanged;
    }

    /// <summary>
    /// The longer text, the picture of ECB and CBC (docs/walkthrough-design.md section 2.4c), and Steve's R1, "the long text is always visible". Pure. It uses
    /// the real Modes.EcbEncrypt, Modes.CbcEncrypt and Lesson01Aes.Pad, so what it shows is what lesson 1 does.
    /// </summary>
    public static class AesLongText
    {
        const int BlockSize = 16;

        /// <summary>flipBlock -1 means no flip. Else flipBit is 0 to 127, and the flipped bit must land on a text byte, not on padding.</summary>
        public static AesLongTextView Build(byte[] key, byte[] iv, byte[] text, int flipBlock, int flipBit)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (iv == null || iv.Length != BlockSize) throw new ArgumentException("The IV is 16 bytes.", "iv");
            if (text == null || text.Length == 0) throw AesTypedText.Refuse(ErrorCodes.WalkTextEmpty, "Type some text first.");
            if (text.Length > AesTypedText.MaxBytes) throw AesTypedText.Refuse(ErrorCodes.WalkTextTooLong, "This view reads at most " + AesTypedText.MaxBytes + " bytes of text.");
            AesKey k = new AesKey(key);
            byte[] padded = Lesson01Aes.Pad(text);
            AesLongTextView view = new AesLongTextView();
            view.Rows = Rows(k, iv, padded, null);
            view.EcbRepeats = Repeats(view.Rows, true);
            view.CbcRepeats = Repeats(view.Rows, false);
            if (flipBlock == -1) return view;

            // The ranges are checked before the multiply, so a large flipBlock from a request body cannot wrap the index.
            if (flipBlock < 0 || flipBlock >= view.Rows.Length || flipBit < 0 || flipBit > 127)
                throw AesTypedText.Refuse(ErrorCodes.WalkBadArgument, "The flipped bit must land on a byte of the text, not on padding.");
            int byteIndex = flipBlock * BlockSize + flipBit / 8;
            if (byteIndex >= text.Length)
                throw AesTypedText.Refuse(ErrorCodes.WalkBadArgument, "The flipped bit must land on a byte of the text, not on padding.");
            byte[] flipped = (byte[])padded.Clone();
            flipped[byteIndex] ^= (byte)(0x80 >> (flipBit % 8));
            view.FlippedRows = Rows(k, iv, flipped, view.Rows);
            for (int i = 0; i < view.FlippedRows.Length; i++)
            {
                if (view.FlippedRows[i].EcbBitsChanged > 0) view.EcbBlocksChanged++;
                if (view.FlippedRows[i].CbcBitsChanged > 0) view.CbcBlocksChanged++;
            }
            return view;
        }

        static AesLongTextRow[] Rows(AesKey k, byte[] iv, byte[] padded, AesLongTextRow[] baseRows)
        {
            byte[] ecb = Modes.EcbEncrypt(k, padded), cbc = Modes.CbcEncrypt(k, iv, padded);
            int blocks = padded.Length / BlockSize;
            AesLongTextRow[] rows = new AesLongTextRow[blocks];
            for (int i = 0; i < blocks; i++)
            {
                AesLongTextRow r = new AesLongTextRow();
                r.Block = i;
                r.Data = Slice(padded, i);
                r.Ecb = Slice(ecb, i);
                r.Cbc = Slice(cbc, i);
                for (int j = 0; j < i; j++)
                {
                    if (Same(rows[j].Ecb, r.Ecb)) r.EcbRepeat = true;
                    if (Same(rows[j].Cbc, r.Cbc)) r.CbcRepeat = true;
                }
                if (baseRows != null)
                {
                    r.EcbBitsChanged = BitsDiffer(baseRows[i].Ecb, r.Ecb);
                    r.CbcBitsChanged = BitsDiffer(baseRows[i].Cbc, r.Cbc);
                }
                rows[i] = r;
            }
            return rows;
        }

        static int Repeats(AesLongTextRow[] rows, bool ecb)
        {
            int repeats = 0;
            for (int i = 0; i < rows.Length; i++) if (ecb ? rows[i].EcbRepeat : rows[i].CbcRepeat) repeats++;
            return repeats;
        }

        static byte[] Slice(byte[] data, int block)
        {
            byte[] b = new byte[BlockSize];
            Buffer.BlockCopy(data, block * BlockSize, b, 0, BlockSize);
            return b;
        }

        static bool Same(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static int BitsDiffer(byte[] a, byte[] b)
        {
            int n = 0;
            for (int i = 0; i < a.Length; i++)
                for (int x = a[i] ^ b[i]; x != 0; x &= x - 1) n++;
            return n;
        }
    }
}
