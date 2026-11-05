using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES, FIPS 197, with 128, 192 or 256 bit keys. The step names follow the standard. The state is 16 bytes,
    /// column by column, so row r of column c is state[r + 4c]. An instance holds only the round keys and is safe to share.
    /// The table lookups use secret indexes, which can leak through a CPU cache. Production AES uses hardware instructions.
    /// </summary>
    public sealed class AesKey
    {
        const int BlockSize = 16;

        static readonly byte[] Sbox = new byte[256];
        static readonly byte[] InverseSbox = new byte[256];
        static readonly byte[] Times2 = new byte[256], Times3 = new byte[256];
        static readonly byte[] Times9 = new byte[256], Times11 = new byte[256], Times13 = new byte[256], Times14 = new byte[256];

        // state[i] takes the byte from state[map[i]].
        static readonly int[] ShiftRowsMap = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
        static readonly int[] InverseShiftRowsMap = { 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3 };

        readonly byte[] _roundKeys;
        readonly int _rounds;

        static AesKey()
        {
            BuildSbox();
            for (int a = 0; a < 256; a++)
            {
                Times2[a] = Multiply((byte)a, 2);
                Times3[a] = Multiply((byte)a, 3);
                Times9[a] = Multiply((byte)a, 9);
                Times11[a] = Multiply((byte)a, 11);
                Times13[a] = Multiply((byte)a, 13);
                Times14[a] = Multiply((byte)a, 14);
            }
        }

        public AesKey(byte[] key)
        {
            Arg.NotNull(key, "key");
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("an AES key is 16, 24 or 32 bytes", "key");
            _rounds = key.Length / 4 + 6;
            _roundKeys = ExpandKey(key, _rounds);
        }

        public void EncryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            byte[] state = new byte[BlockSize];
            byte[] scratch = new byte[BlockSize];
            Buffer.BlockCopy(i, io, state, 0, BlockSize);

            AddRoundKey(state, 0);
            for (int round = 1; round < _rounds; round++)
            {
                SubstituteAndMove(state, scratch, Sbox, ShiftRowsMap);
                MixColumns(state);
                AddRoundKey(state, round);
            }
            SubstituteAndMove(state, scratch, Sbox, ShiftRowsMap);
            AddRoundKey(state, _rounds);

            Buffer.BlockCopy(state, 0, o, oo, BlockSize);
        }

        public void DecryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            byte[] state = new byte[BlockSize];
            byte[] scratch = new byte[BlockSize];
            Buffer.BlockCopy(i, io, state, 0, BlockSize);

            AddRoundKey(state, _rounds);
            for (int round = _rounds - 1; round > 0; round--)
            {
                SubstituteAndMove(state, scratch, InverseSbox, InverseShiftRowsMap);
                AddRoundKey(state, round);
                InverseMixColumns(state);
            }
            SubstituteAndMove(state, scratch, InverseSbox, InverseShiftRowsMap);
            AddRoundKey(state, 0);

            Buffer.BlockCopy(state, 0, o, oo, BlockSize);
        }

        void AddRoundKey(byte[] state, int round)
        {
            int offset = round * BlockSize;
            for (int i = 0; i < BlockSize; i++) state[i] ^= _roundKeys[offset + i];
        }

        /// <summary>SubBytes and ShiftRows, or their inverses. The order of the two makes no difference to the result.</summary>
        static void SubstituteAndMove(byte[] state, byte[] scratch, byte[] box, int[] map)
        {
            for (int i = 0; i < BlockSize; i++) scratch[i] = box[state[map[i]]];
            Buffer.BlockCopy(scratch, 0, state, 0, BlockSize);
        }

        static void MixColumns(byte[] s)
        {
            for (int c = 0; c < BlockSize; c += 4)
            {
                byte a = s[c], b = s[c + 1], d = s[c + 2], e = s[c + 3];
                s[c] = (byte)(Times2[a] ^ Times3[b] ^ d ^ e);
                s[c + 1] = (byte)(a ^ Times2[b] ^ Times3[d] ^ e);
                s[c + 2] = (byte)(a ^ b ^ Times2[d] ^ Times3[e]);
                s[c + 3] = (byte)(Times3[a] ^ b ^ d ^ Times2[e]);
            }
        }

        static void InverseMixColumns(byte[] s)
        {
            for (int c = 0; c < BlockSize; c += 4)
            {
                byte a = s[c], b = s[c + 1], d = s[c + 2], e = s[c + 3];
                s[c] = (byte)(Times14[a] ^ Times11[b] ^ Times13[d] ^ Times9[e]);
                s[c + 1] = (byte)(Times9[a] ^ Times14[b] ^ Times11[d] ^ Times13[e]);
                s[c + 2] = (byte)(Times13[a] ^ Times9[b] ^ Times14[d] ^ Times11[e]);
                s[c + 3] = (byte)(Times11[a] ^ Times13[b] ^ Times9[d] ^ Times14[e]);
            }
        }

        /// <summary>KeyExpansion, FIPS 197 section 5.2, on bytes. Each word is the word before it, changed at key-length steps, xor the word one key back.</summary>
        static byte[] ExpandKey(byte[] key, int rounds)
        {
            int keyWords = key.Length / 4;
            int totalWords = 4 * (rounds + 1);
            byte[] w = new byte[totalWords * 4];
            Buffer.BlockCopy(key, 0, w, 0, key.Length);

            byte[] temp = new byte[4];
            byte rcon = 1;
            for (int word = keyWords; word < totalWords; word++)
            {
                Buffer.BlockCopy(w, (word - 1) * 4, temp, 0, 4);
                if (word % keyWords == 0)
                {
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= rcon;
                    rcon = Times2[rcon];
                }
                else if (keyWords > 6 && word % keyWords == 4)
                {
                    SubWord(temp);
                }
                for (int i = 0; i < 4; i++) w[word * 4 + i] = (byte)(w[(word - keyWords) * 4 + i] ^ temp[i]);
            }
            return w;
        }

        static void RotWord(byte[] t)
        {
            byte first = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = first;
        }

        static void SubWord(byte[] t)
        {
            for (int i = 0; i < 4; i++) t[i] = Sbox[t[i]];
        }

        /// <summary>The S-box is the inverse in GF(2^8), then an affine map (FIPS 197 section 5.1.1). 3 generates the field, so powers of 3 give the inverses.</summary>
        static void BuildSbox()
        {
            byte[] power = new byte[255];
            int[] log = new int[256];
            byte x = 1;
            for (int i = 0; i < 255; i++)
            {
                power[i] = x;
                log[x] = i;
                x = (byte)(x ^ Xtime(x));
            }
            for (int a = 0; a < 256; a++)
            {
                byte inverse = a == 0 ? (byte)0 : power[(255 - log[a]) % 255];
                byte s = (byte)(inverse ^ Rotl8(inverse, 1) ^ Rotl8(inverse, 2) ^ Rotl8(inverse, 3) ^ Rotl8(inverse, 4) ^ 0x63);
                Sbox[a] = s;
                InverseSbox[s] = (byte)a;
            }
        }

        static byte Rotl8(byte v, int n) { return (byte)((v << n) | (v >> (8 - n))); }

        /// <summary>Multiply by 2 in GF(2^8), modulo x^8 + x^4 + x^3 + x + 1.</summary>
        static byte Xtime(byte a) { return (byte)((a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0)); }

        static byte Multiply(byte a, int b)
        {
            byte product = 0;
            for (byte shifted = a; b != 0; b >>= 1)
            {
                if ((b & 1) != 0) product ^= shifted;
                shifted = Xtime(shifted);
            }
            return product;
        }
    }
}
