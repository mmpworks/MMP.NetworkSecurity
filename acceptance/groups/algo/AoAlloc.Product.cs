#if NET
using System;
using NetSec.Crypto;
using NetSec.Dukpt;

namespace Acceptance
{
    /// <summary>
    /// AO-5 measured by the suite on the product (AoAllocMeter). What is left beyond the returned array, per block (or per message for
    /// HMAC and per derivation for DUKPT), must be 0 B. The bench report's bytesPerOp is a second record; AO-0 reads a disagreement as a red.
    /// </summary>
    public static class AoAlloc
    {
        const int Blocks = 64;
        static double PerUnit(Action op, int outLen, int units) { return AoAllocMeter.PerUnit(op, outLen, units); }
        static string Judge(string what, double perUnit, string unit) { return AoAllocMeter.Judge(what, perUnit, unit); }

        static AesKey Aes(Ctx c) { AoSubject.Make(c); return new AesKey(new Rng(0xA05).Bytes(16)); }
        static readonly byte[] Data = new Rng(0xA05D).Bytes(16 * Blocks);
        static readonly byte[] Iv = new byte[16], Nonce = new byte[12], Aad = new byte[0];

        [Clause("AO-5.aes-block.net10")]
        public static string AesBlock(Ctx c)
        {
            AesKey k = Aes(c);
            byte[] i = new byte[16], o = new byte[16];
            double enc = PerUnit(delegate { k.EncryptBlock(i, 0, o, 0); }, -1, 1), dec = PerUnit(delegate { k.DecryptBlock(i, 0, o, 0); }, -1, 1);
            return Judge("AesKey.EncryptBlock/DecryptBlock", Math.Max(enc, dec), "block");
        }

        [Clause("AO-5.aes-ecb.net10")]
        public static string AesEcb(Ctx c) { AesKey k = Aes(c); return Judge("Modes.EcbEncrypt", PerUnit(delegate { Modes.EcbEncrypt(k, Data); }, Data.Length, Blocks), "block"); }

        [Clause("AO-5.aes-cbc.net10")]
        public static string AesCbc(Ctx c)
        {
            AesKey k = Aes(c);
            double e = PerUnit(delegate { Modes.CbcEncrypt(k, Iv, Data); }, Data.Length, Blocks), d = PerUnit(delegate { Modes.CbcDecrypt(k, Iv, Data); }, Data.Length, Blocks);
            return Judge("Modes.CbcEncrypt/CbcDecrypt", Math.Max(e, d), "block");
        }

        [Clause("AO-5.aes-ctr.net10")]
        public static string AesCtr(Ctx c) { AesKey k = Aes(c); return Judge("Modes.Ctr", PerUnit(delegate { Modes.Ctr(k, Iv, Data); }, Data.Length, Blocks), "block"); }

        [Clause("AO-5.aes-gcm.net10")]
        public static string AesGcm(Ctx c) { AesKey k = Aes(c); return Judge("Gcm.Seal", PerUnit(delegate { Gcm.Seal(k, Nonce, Aad, Data); }, Data.Length + 16, Blocks), "block"); }

        [Clause("AO-5.aes-cmac.net10")]
        public static string AesCmac(Ctx c) { AesKey k = Aes(c); return Judge("Cmac.Compute", PerUnit(delegate { Cmac.Compute(k, Data); }, 16, Blocks), "block"); }

        static string HashUpdate(Ctx c, string what, Func<IHash> make, int block)
        {
            AoSubject.Make(c);
            IHash h = make();
            byte[] data = new Rng(0xA05A).Bytes(block * Blocks);
            return Judge(what + ".Update", PerUnit(delegate { h.Update(data, 0, data.Length); }, -1, Blocks), "block");
        }

        [Clause("AO-5.md5.net10")] public static string Md5(Ctx c) { return HashUpdate(c, "Md5", Hashes.Md5, 64); }
        [Clause("AO-5.sha1.net10")] public static string Sha1(Ctx c) { return HashUpdate(c, "Sha1", Hashes.Sha1, 64); }
        [Clause("AO-5.sha256.net10")] public static string Sha256(Ctx c) { return HashUpdate(c, "Sha256", Hashes.Sha256, 64); }
        [Clause("AO-5.sha512.net10")] public static string Sha512(Ctx c) { return HashUpdate(c, "Sha512", Hashes.Sha512, 128); }
        [Clause("AO-5.keccak.net10")] public static string Keccak(Ctx c) { return HashUpdate(c, "Sha3_256 (Keccak)", Hashes.Sha3_256, 136); }

        /// <summary>
        /// PRD AO-5: 0 B per message for HMAC through HmacKey.Compute with a caller-owned work object and output buffer (S3). Until the type
        /// exists the suite measures the wrapper Hmac.Compute, which allocates by design (7.3 item 14), so the row is FAIL until S3.
        /// </summary>
        [Clause("AO-5.hmac.net10")]
        public static string Hmac(Ctx c)
        {
            AoSubject.Make(c);
            if (AoSeams.HasType("HmacKey")) throw new NotRunException("SIGNATURE_NOT_CONFIRMED", "HmacKey exists; the anchor binds HmacKey.Compute(work, ...) when the S3 PR confirms 7.3 item 14");
            byte[] key = new Rng(0xA05B).Bytes(32), msg = new Rng(0xA05C).Bytes(1024);
            return Judge("Hmac.Compute (SHA-256, the wrapper)", PerUnit(delegate { NetSec.Crypto.Hmac.Compute(Hashes.Sha256, key, msg); }, 32, 1), "message");
        }

        [Clause("AO-5.tdes.net10")]
        public static string Tdes(Ctx c)
        {
            AoSubject.Make(c);
            TdesKey k = new TdesKey(new Rng(0xA05E).Bytes(24));
            byte[] i = new byte[8], o = new byte[8];
            double e = PerUnit(delegate { k.EncryptBlock(i, 0, o, 0); }, -1, 1), d = PerUnit(delegate { k.DecryptBlock(i, 0, o, 0); }, -1, 1);
            return Judge("TdesKey.EncryptBlock/DecryptBlock", Math.Max(e, d), "block");
        }

        [Clause("AO-5.dukpt-derive.net10")]
        public static string Dukpt(Ctx c)
        {
            AoSubject.Make(c);
            byte[] bdk = new Rng(0xA05F).Bytes(16);
            byte[] ksn = Hex.Concat(new Rng(0xA060).Bytes(8), new byte[] { 0, 0, 0x10, 0x01 });
            return Judge("DukptBank.DeriveWorkingKey (AES-128 PIN key)", PerUnit(delegate { DukptBank.DeriveWorkingKey(bdk, ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128); }, 16, 1), "derivation");
        }
    }
}
#endif
