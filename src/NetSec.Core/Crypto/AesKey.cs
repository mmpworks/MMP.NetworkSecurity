using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES, FIPS 197, with 128, 192 or 256 bit keys. The state is four 32-bit words, column c in word c with row 0 in the high byte, so a
    /// block loads and stores big-endian. Each round is one table lookup per state byte (AesTables.Te or Td) with the column rotations done
    /// by shifts, so a block allocates nothing. Decrypt uses the equivalent inverse cipher (FIPS 197 section 5.3.5), with its round keys
    /// built in the constructor. An instance holds only the two schedules and is safe to share between threads.
    /// The table lookups use secret indexes, which can leak through a CPU cache. Production AES uses hardware instructions.
    /// </summary>
    public sealed partial class AesKey
    {
        const int BlockSize = 16;

        // state[i] takes the byte from state[map[i]] (the walk and ShiftMap read these; the word path does ShiftRows by its index choice).
        static readonly int[] ShiftRowsMap = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
        static readonly int[] InverseShiftRowsMap = { 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3 };

        readonly uint[] _ek;     // encrypt round keys: 4 (Nr + 1) words in FIPS 197 order
        readonly uint[] _dk;     // decrypt round keys of the equivalent inverse cipher
        readonly int _rounds;

        public AesKey(byte[] key)
        {
            Arg.NotNull(key, "key");
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("an AES key is 16, 24 or 32 bytes", "key");
            _rounds = key.Length / 4 + 6;
            _ek = ExpandWords(key, _rounds);
            _dk = InverseSchedule(_ek, _rounds);
        }

        public void EncryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            // All 16 input bytes are read before the first output byte is written, so the same or an overlapping array is safe.
            uint s0 = Endian.LoadBe32(i, io), s1 = Endian.LoadBe32(i, io + 4), s2 = Endian.LoadBe32(i, io + 8), s3 = Endian.LoadBe32(i, io + 12);
            EncryptWords(ref s0, ref s1, ref s2, ref s3);
            StoreBlock(s0, s1, s2, s3, o, oo);
        }

        public void DecryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            uint s0 = Endian.LoadBe32(i, io), s1 = Endian.LoadBe32(i, io + 4), s2 = Endian.LoadBe32(i, io + 8), s3 = Endian.LoadBe32(i, io + 12);
            DecryptWords(ref s0, ref s1, ref s2, ref s3);
            StoreBlock(s0, s1, s2, s3, o, oo);
        }

        internal static void StoreBlock(uint s0, uint s1, uint s2, uint s3, byte[] o, int oo)
        {
            Endian.StoreBe32(s0, o, oo);
            Endian.StoreBe32(s1, o, oo + 4);
            Endian.StoreBe32(s2, o, oo + 8);
            Endian.StoreBe32(s3, o, oo + 12);
        }

        /// <summary>One block, in words. The modes, CMAC and GCM call this, so their blocks allocate nothing either.</summary>
        internal void EncryptWords(ref uint s0, ref uint s1, ref uint s2, ref uint s3)
        {
            uint[] rk = _ek, te = AesTables.Te;
            byte[] sb = AesTables.Sbox;
            s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
            int k = 4;
            for (int round = 1; round < _rounds; round++, k += 4)
            {
                // Column c takes row r from column c + r (ShiftRows); row r's column of products is Te rotated right by 8 r bits.
                uint t0 = te[s0 >> 24] ^ Ror8(te[(s1 >> 16) & 0xFF]) ^ Ror16(te[(s2 >> 8) & 0xFF]) ^ Ror24(te[s3 & 0xFF]) ^ rk[k];
                uint t1 = te[s1 >> 24] ^ Ror8(te[(s2 >> 16) & 0xFF]) ^ Ror16(te[(s3 >> 8) & 0xFF]) ^ Ror24(te[s0 & 0xFF]) ^ rk[k + 1];
                uint t2 = te[s2 >> 24] ^ Ror8(te[(s3 >> 16) & 0xFF]) ^ Ror16(te[(s0 >> 8) & 0xFF]) ^ Ror24(te[s1 & 0xFF]) ^ rk[k + 2];
                uint t3 = te[s3 >> 24] ^ Ror8(te[(s0 >> 16) & 0xFF]) ^ Ror16(te[(s1 >> 8) & 0xFF]) ^ Ror24(te[s2 & 0xFF]) ^ rk[k + 3];
                s0 = t0; s1 = t1; s2 = t2; s3 = t3;
            }
            // The last round has no MixColumns: SubBytes and ShiftRows byte by byte.
            uint u0 = ((uint)sb[s0 >> 24] << 24) ^ ((uint)sb[(s1 >> 16) & 0xFF] << 16) ^ ((uint)sb[(s2 >> 8) & 0xFF] << 8) ^ sb[s3 & 0xFF] ^ rk[k];
            uint u1 = ((uint)sb[s1 >> 24] << 24) ^ ((uint)sb[(s2 >> 16) & 0xFF] << 16) ^ ((uint)sb[(s3 >> 8) & 0xFF] << 8) ^ sb[s0 & 0xFF] ^ rk[k + 1];
            uint u2 = ((uint)sb[s2 >> 24] << 24) ^ ((uint)sb[(s3 >> 16) & 0xFF] << 16) ^ ((uint)sb[(s0 >> 8) & 0xFF] << 8) ^ sb[s1 & 0xFF] ^ rk[k + 2];
            uint u3 = ((uint)sb[s3 >> 24] << 24) ^ ((uint)sb[(s0 >> 16) & 0xFF] << 16) ^ ((uint)sb[(s1 >> 8) & 0xFF] << 8) ^ sb[s2 & 0xFF] ^ rk[k + 3];
            s0 = u0; s1 = u1; s2 = u2; s3 = u3;
        }

        internal void DecryptWords(ref uint s0, ref uint s1, ref uint s2, ref uint s3)
        {
            uint[] rk = _dk, td = AesTables.Td;
            byte[] ib = AesTables.InverseSbox;
            s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
            int k = 4;
            for (int round = 1; round < _rounds; round++, k += 4)
            {
                // Column c takes row r from column c - r (InvShiftRows).
                uint t0 = td[s0 >> 24] ^ Ror8(td[(s3 >> 16) & 0xFF]) ^ Ror16(td[(s2 >> 8) & 0xFF]) ^ Ror24(td[s1 & 0xFF]) ^ rk[k];
                uint t1 = td[s1 >> 24] ^ Ror8(td[(s0 >> 16) & 0xFF]) ^ Ror16(td[(s3 >> 8) & 0xFF]) ^ Ror24(td[s2 & 0xFF]) ^ rk[k + 1];
                uint t2 = td[s2 >> 24] ^ Ror8(td[(s1 >> 16) & 0xFF]) ^ Ror16(td[(s0 >> 8) & 0xFF]) ^ Ror24(td[s3 & 0xFF]) ^ rk[k + 2];
                uint t3 = td[s3 >> 24] ^ Ror8(td[(s2 >> 16) & 0xFF]) ^ Ror16(td[(s1 >> 8) & 0xFF]) ^ Ror24(td[s0 & 0xFF]) ^ rk[k + 3];
                s0 = t0; s1 = t1; s2 = t2; s3 = t3;
            }
            uint u0 = ((uint)ib[s0 >> 24] << 24) ^ ((uint)ib[(s3 >> 16) & 0xFF] << 16) ^ ((uint)ib[(s2 >> 8) & 0xFF] << 8) ^ ib[s1 & 0xFF] ^ rk[k];
            uint u1 = ((uint)ib[s1 >> 24] << 24) ^ ((uint)ib[(s0 >> 16) & 0xFF] << 16) ^ ((uint)ib[(s3 >> 8) & 0xFF] << 8) ^ ib[s2 & 0xFF] ^ rk[k + 1];
            uint u2 = ((uint)ib[s2 >> 24] << 24) ^ ((uint)ib[(s1 >> 16) & 0xFF] << 16) ^ ((uint)ib[(s0 >> 8) & 0xFF] << 8) ^ ib[s3 & 0xFF] ^ rk[k + 2];
            uint u3 = ((uint)ib[s3 >> 24] << 24) ^ ((uint)ib[(s2 >> 16) & 0xFF] << 16) ^ ((uint)ib[(s1 >> 8) & 0xFF] << 8) ^ ib[s0 & 0xFF] ^ rk[k + 3];
            s0 = u0; s1 = u1; s2 = u2; s3 = u3;
        }

        static uint Ror8(uint x) { return (x >> 8) | (x << 24); }
        static uint Ror16(uint x) { return (x >> 16) | (x << 16); }
        static uint Ror24(uint x) { return (x >> 24) | (x << 8); }

        /// <summary>KeyExpansion, FIPS 197 section 5.2, on words. Word i is the word before it, changed at key-length steps, xor the word one key back.</summary>
        static uint[] ExpandWords(byte[] key, int rounds)
        {
            int keyWords = key.Length / 4;
            uint[] w = new uint[4 * (rounds + 1)];
            for (int i = 0; i < keyWords; i++) w[i] = Endian.LoadBe32(key, 4 * i);
            uint rcon = 1;
            for (int i = keyWords; i < w.Length; i++)
            {
                uint temp = w[i - 1];
                if (i % keyWords == 0)
                {
                    temp = SubstituteWord((temp << 8) | (temp >> 24)) ^ (rcon << 24);   // RotWord, SubWord, xor Rcon
                    rcon = (rcon << 1) ^ ((rcon & 0x80) != 0 ? 0x11Bu : 0u);          // the next Rcon: doubled in GF(2^8)
                }
                else if (keyWords > 6 && i % keyWords == 4)
                {
                    temp = SubstituteWord(temp);
                }
                w[i] = w[i - keyWords] ^ temp;
            }
            return w;
        }

        static uint SubstituteWord(uint w)
        {
            byte[] sb = AesTables.Sbox;
            return ((uint)sb[w >> 24] << 24) | ((uint)sb[(w >> 16) & 0xFF] << 16) | ((uint)sb[(w >> 8) & 0xFF] << 8) | sb[w & 0xFF];
        }

        /// <summary>
        /// The equivalent inverse cipher's round keys (FIPS 197 section 5.3.5): the encrypt keys in reverse round order, with InvMixColumns
        /// on every round key but the first and the last. InvMixColumns of a byte b is Td(S(b)), because Td holds the products of I(x).
        /// </summary>
        static uint[] InverseSchedule(uint[] ek, int rounds)
        {
            uint[] dk = new uint[ek.Length];
            for (int round = 0; round <= rounds; round++)
                for (int j = 0; j < 4; j++)
                {
                    uint w = ek[4 * (rounds - round) + j];
                    dk[4 * round + j] = round == 0 || round == rounds ? w : InverseMixWord(w);
                }
            return dk;
        }

        static uint InverseMixWord(uint w)
        {
            uint[] td = AesTables.Td;
            byte[] sb = AesTables.Sbox;
            return td[sb[w >> 24]] ^ Ror8(td[sb[(w >> 16) & 0xFF]]) ^ Ror16(td[sb[(w >> 8) & 0xFF]]) ^ Ror24(td[sb[w & 0xFF]]);
        }
    }
}
