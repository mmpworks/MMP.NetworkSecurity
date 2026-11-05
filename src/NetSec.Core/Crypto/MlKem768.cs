using System;
using NetSec.Errors;

namespace NetSec.Crypto
{
    public sealed class MlKemPair
    {
        readonly byte[] _ek, _dk;

        internal MlKemPair(byte[] ek, byte[] dk)
        {
            _ek = ek;
            _dk = dk;
        }

        /// <summary>FIPS 203 ek, 1184 bytes. Returns a copy.</summary>
        public byte[] Ek { get { return (byte[])_ek.Clone(); } }

        /// <summary>FIPS 203 dk, 2400 bytes. Returns a copy.</summary>
        public byte[] Dk { get { return (byte[])_dk.Clone(); } }
    }

    public sealed class MlKemSealed
    {
        readonly byte[] _ciphertext, _sharedSecret;

        internal MlKemSealed(byte[] ciphertext, byte[] sharedSecret)
        {
            _ciphertext = ciphertext;
            _sharedSecret = sharedSecret;
        }

        /// <summary>1088 bytes. Returns a copy.</summary>
        public byte[] Ciphertext { get { return (byte[])_ciphertext.Clone(); } }

        /// <summary>32 bytes. Returns a copy.</summary>
        public byte[] SharedSecret { get { return (byte[])_sharedSecret.Clone(); } }
    }

    /// <summary>
    /// ML-KEM-768 (FIPS 203 section 6). These are the "internal" algorithms: the caller supplies d, z and m, so one input
    /// always gives one output. A caller takes those bytes from an IRandomSource. That is how a same-seed rerun gives
    /// the same bytes, and how published vectors reach this code.
    /// Built to show the parts. Do not copy: managed code gives no constant-time guarantee.
    /// </summary>
    public static class MlKem768
    {
        static readonly MlKemParameters Parameters = MlKemParameters.Ml768;

        /// <summary>FIPS 203 algorithm 16. dk holds, in order: the K-PKE key, ek, H(ek), z.</summary>
        public static MlKemPair KeyGen(byte[] d, byte[] z)
        {
            CheckSeed(d, "d");
            CheckSeed(z, "z");
            byte[] ek, dkPke;
            KPke.KeyGen(Parameters, d, out ek, out dkPke);
            byte[] dk = new byte[Parameters.DecapsulationKeyLength];
            int offset = 0;
            offset = Append(dk, offset, dkPke);
            offset = Append(dk, offset, ek);
            offset = Append(dk, offset, MlKemSampling.H(ek));
            Append(dk, offset, z);
            return new MlKemPair(ek, dk);
        }

        /// <summary>FIPS 203 algorithm 17, with the key check of section 7.2. (K, r) = G(m || H(ek)).</summary>
        public static MlKemSealed Encaps(byte[] ek, byte[] m)
        {
            CheckSeed(m, "m");
            CheckEncapsulationKey(ek);
            byte[] kr = MlKemSampling.G(m, MlKemSampling.H(ek));
            byte[] ciphertext = KPke.Encrypt(Parameters, ek, m, KPke.Slice(kr, 32, 32));
            return new MlKemSealed(ciphertext, KPke.Slice(kr, 0, 32));
        }

        /// <summary>
        /// FIPS 203 algorithm 18, with the checks of section 7.3. Decrypt, then encrypt again with the recovered message. A
        /// ciphertext that does not match gives J(z || c). So a forged ciphertext gets a random-looking secret and no error
        /// (implicit rejection). As in the algorithm, J runs before the compare, so accept and reject run the same steps. That
        /// is the shape of the algorithm and no timing claim: managed code gives no constant-time guarantee.
        /// </summary>
        public static byte[] Decaps(byte[] dk, byte[] c)
        {
            MlKemParameters p = Parameters;
            if (dk == null) throw new ArgumentNullException("dk");
            if (c == null) throw new ArgumentNullException("c");
            if (dk.Length != p.DecapsulationKeyLength) throw Invalid(ErrorCodes.MlKemKeyInvalid, "dk is not " + p.DecapsulationKeyLength + " bytes");
            if (c.Length != p.CiphertextLength) throw Invalid(ErrorCodes.MlKemCiphertextInvalid, "the ciphertext is not " + p.CiphertextLength + " bytes");

            byte[] dkPke = KPke.Slice(dk, 0, p.PkeDecryptionKeyLength);
            byte[] ek = KPke.Slice(dk, p.PkeDecryptionKeyLength, p.EncapsulationKeyLength);
            byte[] h = KPke.Slice(dk, p.PkeDecryptionKeyLength + p.EncapsulationKeyLength, 32);
            byte[] z = KPke.Slice(dk, p.PkeDecryptionKeyLength + p.EncapsulationKeyLength + 32, 32);
            if (!AreEqual(h, MlKemSampling.H(ek))) throw Invalid(ErrorCodes.MlKemKeyInvalid, "dk holds a wrong hash of ek");

            byte[] m = KPke.Decrypt(p, dkPke, c);
            byte[] kr = MlKemSampling.G(m, h);
            byte[] rejected = MlKemSampling.J(z, c);
            byte[] expected = KPke.Encrypt(p, ek, m, KPke.Slice(kr, 32, 32));
            return AreEqual(c, expected) ? KPke.Slice(kr, 0, 32) : rejected;
        }

        /// <summary>Section 7.2: each 12-bit value in ek must be below q, so a decode then an encode gives the same bytes.</summary>
        static void CheckEncapsulationKey(byte[] ek)
        {
            MlKemParameters p = Parameters;
            if (ek == null) throw new ArgumentNullException("ek");
            if (ek.Length != p.EncapsulationKeyLength) throw Invalid(ErrorCodes.MlKemKeyInvalid, "ek is not " + p.EncapsulationKeyLength + " bytes");
            byte[] again = new byte[384];
            for (int i = 0; i < p.K; i++)
            {
                Array.Clear(again, 0, again.Length);
                MlKemEncoding.ByteEncode(12, MlKemEncoding.ByteDecode(12, ek, 384 * i), again, 0);
                for (int j = 0; j < again.Length; j++)
                    if (again[j] != ek[384 * i + j]) throw Invalid(ErrorCodes.MlKemKeyInvalid, "ek holds a value at or above q");
            }
        }

        static void CheckSeed(byte[] seed, string name)
        {
            if (seed == null || seed.Length != 32) throw new ArgumentException(name + " must have 32 bytes", name);
        }

        static NetSecException Invalid(string code, string message) { return new NetSecException(NetSecError.Of(code, message)); }

        static int Append(byte[] target, int offset, byte[] part)
        {
            Array.Copy(part, 0, target, offset, part.Length);
            return offset + part.Length;
        }

        static bool AreEqual(byte[] a, byte[] b)
        {
            int difference = a.Length ^ b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++) difference |= a[i] ^ b[i];
            return difference == 0;
        }
    }
}
