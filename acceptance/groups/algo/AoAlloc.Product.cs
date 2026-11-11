using System;
using NetSec.Crypto;
using NetSec.Dukpt;

namespace Acceptance
{
    /// <summary>
    /// AO-5 measured by the suite on the product (AoAllocMeter), on both builds. What is left beyond the returned array, per block (or per
    /// message for HMAC and the whole-message hashes, per call for a caller-buffer form, per derivation for DUKPT), must stay within the
    /// row's budget in acceptance/ao-budgets.tsv, which is 0 when the file has no line. The net10 rows judge bytes; the cf rows judge zero
    /// against not zero (see AoAllocMeter). The bench report's bytesPerOp is a second record; AO-0 reads a disagreement as a red.
    /// </summary>
    public static class AoAlloc
    {
        const int Blocks = 64;
        /// <summary>cf: calls for a 64-block message op or a slow op; the detail prints the count and the unseen limit.</summary>
        const int CfMessageCalls = 15625, CfDukptCalls = 20000;

        static AoAllocMeter.PerUnitResult PerUnit(Action op, int outLen, int units) { return AoAllocMeter.PerUnit(op, outLen, units); }
        static AoAllocMeter.PerUnitResult Larger(AoAllocMeter.PerUnitResult a, AoAllocMeter.PerUnitResult b) { return AoAllocMeter.Max(a, b); }

        /// <summary>Judged against the budget of the row's net10 id (budgets are judged on net10 only).</summary>
        static string Judge(Ctx c, string row, string what, AoAllocMeter.PerUnitResult p, string unit)
        {
            return AoAllocMeter.Judge(what, p, unit, AoBudgets.For(c, row + ".net10"));
        }

        static AesKey Aes(Ctx c) { AoSubject.Make(c); return new AesKey(new Rng(0xA05).Bytes(16)); }
        static readonly byte[] Data = new Rng(0xA05D).Bytes(16 * Blocks);
        static readonly byte[] Iv = new byte[16], Nonce = new byte[12], Aad = new byte[0];

        // On cf a message op runs CfMessageCalls calls; PerUnit divides by units, so units = Blocks keeps the cf run at 1,000,000 blocks.
        [Clause("AO-5.aes-block", PerBuild = true)]
        public static string AesBlock(Ctx c)
        {
            AesKey k = Aes(c);
            byte[] i = new byte[16], o = new byte[16];
            var enc = PerUnit(delegate { k.EncryptBlock(i, 0, o, 0); }, -1, 1);
            var dec = PerUnit(delegate { k.DecryptBlock(i, 0, o, 0); }, -1, 1);
            return Judge(c, "AO-5.aes-block", "AesKey.EncryptBlock/DecryptBlock", Larger(enc, dec), "block");
        }

        [Clause("AO-5.aes-ecb", PerBuild = true)]
        public static string AesEcb(Ctx c) { AesKey k = Aes(c); return Judge(c, "AO-5.aes-ecb", "Modes.EcbEncrypt", PerUnit(delegate { Modes.EcbEncrypt(k, Data); }, Data.Length, Blocks), "block"); }

        [Clause("AO-5.aes-cbc", PerBuild = true)]
        public static string AesCbc(Ctx c)
        {
            AesKey k = Aes(c);
            var e = PerUnit(delegate { Modes.CbcEncrypt(k, Iv, Data); }, Data.Length, Blocks);
            var d = PerUnit(delegate { Modes.CbcDecrypt(k, Iv, Data); }, Data.Length, Blocks);
            return Judge(c, "AO-5.aes-cbc", "Modes.CbcEncrypt/CbcDecrypt", Larger(e, d), "block");
        }

        [Clause("AO-5.aes-ctr", PerBuild = true)]
        public static string AesCtr(Ctx c) { AesKey k = Aes(c); return Judge(c, "AO-5.aes-ctr", "Modes.Ctr", PerUnit(delegate { Modes.Ctr(k, Iv, Data); }, Data.Length, Blocks), "block"); }

        /// <summary>
        /// GcmKey.Seal(nonce, aad, plain), the allocating form, on one key built outside the loop, when GcmKey exists (Jared on #405, B1:
        /// PRD 7.3 item 12, the static Gcm.Seal builds a GcmKey on each call). Until then it measures the static wrapper.
        /// </summary>
        [Clause("AO-5.aes-gcm", PerBuild = true)]
        public static string AesGcm(Ctx c)
        {
            AesKey k = Aes(c);
            Func<byte[], byte[], byte[], byte[]> seal = AoSeams.GcmKeySeal(k);
            if (seal == null) return Judge(c, "AO-5.aes-gcm", "Gcm.Seal (the wrapper; no GcmKey yet)", PerUnit(delegate { Gcm.Seal(k, Nonce, Aad, Data); }, Data.Length + 16, Blocks), "block");
            return Judge(c, "AO-5.aes-gcm", "GcmKey.Seal", PerUnit(delegate { seal(Nonce, Aad, Data); }, Data.Length + 16, Blocks), "block");
        }

        /// <summary>The static Gcm.Seal wrapper, always. PRD 7.3 item 16: it gets a byte budget at S1 (net10 only; no cf row).</summary>
        [Clause("AO-5.aes-gcm-static.net10")]
        public static string AesGcmStatic(Ctx c)
        {
            if (AoAllocMeter.OnCf) throw new NotRunException("NOT_THIS_BUILD", "the static wrapper's budget is judged on net10 only");
            AesKey k = Aes(c);
            return AoAllocMeter.Judge("Gcm.Seal (static wrapper)", PerUnit(delegate { Gcm.Seal(k, Nonce, Aad, Data); }, Data.Length + 16, Blocks), "block", AoBudgets.For(c, "AO-5.aes-gcm-static.net10"));
        }

        [Clause("AO-5.aes-cmac", PerBuild = true)]
        public static string AesCmac(Ctx c) { AesKey k = Aes(c); return Judge(c, "AO-5.aes-cmac", "Cmac.Compute", PerUnit(delegate { Cmac.Compute(k, Data); }, 16, Blocks), "block"); }

        static string HashUpdate(Ctx c, string row, string what, Func<IHash> make, int block)
        {
            AoSubject.Make(c);
            IHash h = make();
            byte[] data = new Rng(0xA05A).Bytes(block * Blocks);
            return Judge(c, row, what + ".Update", PerUnit(delegate { h.Update(data, 0, data.Length); }, -1, Blocks), "block");
        }

        [Clause("AO-5.md5", PerBuild = true)] public static string Md5(Ctx c) { return HashUpdate(c, "AO-5.md5", "Md5", Hashes.Md5, 64); }
        [Clause("AO-5.sha1", PerBuild = true)] public static string Sha1(Ctx c) { return HashUpdate(c, "AO-5.sha1", "Sha1", Hashes.Sha1, 64); }
        [Clause("AO-5.sha256", PerBuild = true)] public static string Sha256(Ctx c) { return HashUpdate(c, "AO-5.sha256", "Sha256", Hashes.Sha256, 64); }
        [Clause("AO-5.sha512", PerBuild = true)] public static string Sha512(Ctx c) { return HashUpdate(c, "AO-5.sha512", "Sha512", Hashes.Sha512, 128); }
        [Clause("AO-5.keccak", PerBuild = true)] public static string Keccak(Ctx c) { return HashUpdate(c, "AO-5.keccak", "Sha3_256 (Keccak)", Hashes.Sha3_256, 136); }

        /// <summary>
        /// One whole hash of a fixed 1024-byte message: the factory, one Update, Finish. Every byte counts, the digest too (lead, 2026-11-11:
        /// the padding and digest arrays are garbage on every message). FAIL until S3 adds a Finish that writes into a caller buffer; the op
        /// moves to that API at S3. units = Blocks only sets the cf call count; the detail is per message.
        /// </summary>
        static string HashMessage(Ctx c, string row, string what, Func<IHash> make)
        {
            AoSubject.Make(c);
            byte[] msg = new Rng(0xA05D1).Bytes(1024);
            var p = PerUnit(delegate { IHash h = make(); h.Update(msg, 0, msg.Length); GC.KeepAlive(h.Finish()); }, -1, AoAllocMeter.OnCf ? Blocks : 1);
            if (AoAllocMeter.OnCf) { p.Low *= Blocks; p.High *= Blocks; }
            return Judge(c, row, what + " whole message (factory, Update, Finish)", p, "message");
        }

        [Clause("AO-5.md5-message", PerBuild = true)] public static string Md5Message(Ctx c) { return HashMessage(c, "AO-5.md5-message", "Md5", Hashes.Md5); }
        [Clause("AO-5.sha1-message", PerBuild = true)] public static string Sha1Message(Ctx c) { return HashMessage(c, "AO-5.sha1-message", "Sha1", Hashes.Sha1); }
        [Clause("AO-5.sha256-message", PerBuild = true)] public static string Sha256Message(Ctx c) { return HashMessage(c, "AO-5.sha256-message", "Sha256", Hashes.Sha256); }
        [Clause("AO-5.sha512-message", PerBuild = true)] public static string Sha512Message(Ctx c) { return HashMessage(c, "AO-5.sha512-message", "Sha512", Hashes.Sha512); }
        [Clause("AO-5.keccak-message", PerBuild = true)] public static string KeccakMessage(Ctx c) { return HashMessage(c, "AO-5.keccak-message", "Sha3_256 (Keccak)", Hashes.Sha3_256); }

        /// <summary>
        /// PRD AO-5: 0 B per message for HMAC through HmacKey.Compute with a caller-owned work object and output buffer (S3). Until the type
        /// exists the suite measures the wrapper Hmac.Compute, which allocates by design (7.3 item 14), so the row is FAIL until S3.
        /// </summary>
        [Clause("AO-5.hmac", PerBuild = true)]
        public static string Hmac(Ctx c)
        {
            AoSubject.Make(c);
            if (AoSeams.HasType("HmacKey")) throw new NotRunException("SIGNATURE_NOT_CONFIRMED", "HmacKey exists; the anchor binds HmacKey.Compute(work, ...) when the S3 PR confirms 7.3 item 14");
            byte[] key = new Rng(0xA05B).Bytes(32), msg = new Rng(0xA05C).Bytes(1024);
            var p = PerUnit(delegate { NetSec.Crypto.Hmac.Compute(Hashes.Sha256, key, msg); }, 32, AoAllocMeter.OnCf ? Blocks : 1);
            if (AoAllocMeter.OnCf) { p.Low *= Blocks; p.High *= Blocks; }
            return Judge(c, "AO-5.hmac", "Hmac.Compute (SHA-256, the wrapper)", p, "message");
        }

        [Clause("AO-5.tdes", PerBuild = true)]
        public static string Tdes(Ctx c)
        {
            AoSubject.Make(c);
            TdesKey k = new TdesKey(new Rng(0xA05E).Bytes(24));
            byte[] i = new byte[8], o = new byte[8];
            var e = PerUnit(delegate { k.EncryptBlock(i, 0, o, 0); }, -1, 1);
            var d = PerUnit(delegate { k.DecryptBlock(i, 0, o, 0); }, -1, 1);
            return Judge(c, "AO-5.tdes", "TdesKey.EncryptBlock/DecryptBlock", Larger(e, d), "block");
        }

        [Clause("AO-5.dukpt-derive", PerBuild = true)]
        public static string Dukpt(Ctx c)
        {
            AoSubject.Make(c);
            byte[] bdk = new Rng(0xA05F).Bytes(16);
            // Counter 0x00000F0F: 8 one bits, so the walk down runs 8 steps. The bench uses the same counter (agreed with Richard, 2026-11-11).
            byte[] ksn = Hex.Concat(new Rng(0xA060).Bytes(8), new byte[] { 0, 0, 0x0F, 0x0F });
            int units = AoAllocMeter.OnCf ? AoAllocMeter.CfUnits / CfDukptCalls : 1;
            var p = PerUnit(delegate { DukptBank.DeriveWorkingKey(bdk, ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128); }, 16, units);
            if (AoAllocMeter.OnCf) { p.Low *= units; p.High *= units; }
            return Judge(c, "AO-5.dukpt-derive", "DukptBank.DeriveWorkingKey (AES-128 PIN key)", p, "derivation");
        }

        // ---- caller-buffer forms (PRD 7.3 item 15, 7.4 rule 2): 0 B for the whole call, output included, because the caller made it ----

        static readonly byte[] Out = new byte[16 * Blocks + 16], Tag = new byte[16], Ctr0 = new byte[16];

        static string Into(Ctx c, string row, string what, Action op)
        {
            var p = PerUnit(op, -1, Blocks);
            p.Low *= Blocks; p.High *= Blocks;
            return Judge(c, row, what + " (1024-byte message, caller's buffers)", p, "call");
        }

        [Clause("AO-5.aes-ecb-into", PerBuild = true)]
        public static string EcbInto(Ctx c)
        {
            AesKey k = Aes(c);
            var e = AoSeams.EcbInto(true); var d = AoSeams.EcbInto(false);
            string a = Into(c, "AO-5.aes-ecb-into", "Modes.EcbEncrypt into", delegate { e(k, Data, 0, Data.Length, Out, 0); });
            return a + "; " + Into(c, "AO-5.aes-ecb-into", "Modes.EcbDecrypt into", delegate { d(k, Data, 0, Data.Length, Out, 0); });
        }

        [Clause("AO-5.aes-cbc-into", PerBuild = true)]
        public static string CbcInto(Ctx c)
        {
            AesKey k = Aes(c);
            var e = AoSeams.CbcInto(true); var d = AoSeams.CbcInto(false);
            string a = Into(c, "AO-5.aes-cbc-into", "Modes.CbcEncrypt into", delegate { e(k, Iv, 0, Data, 0, Data.Length, Out, 0); });
            return a + "; " + Into(c, "AO-5.aes-cbc-into", "Modes.CbcDecrypt into", delegate { d(k, Iv, 0, Data, 0, Data.Length, Out, 0); });
        }

        [Clause("AO-5.aes-ctr-into", PerBuild = true)]
        public static string CtrInto(Ctx c)
        {
            AesKey k = Aes(c);
            var f = AoSeams.CtrInto();
            return Into(c, "AO-5.aes-ctr-into", "Modes.Ctr into", delegate { f(k, Ctr0, 0, Data, 0, Data.Length, Out, 0); });
        }

        [Clause("AO-5.aes-cmac-into", PerBuild = true)]
        public static string CmacInto(Ctx c)
        {
            AesKey k = Aes(c);
            var f = AoSeams.CmacInto();
            return Into(c, "AO-5.aes-cmac-into", "Cmac.Compute into", delegate { f(k, Data, 0, Data.Length, Tag, 0); });
        }

        [Clause("AO-5.aes-cmackey-into", PerBuild = true)]
        public static string CmacKeyInto(Ctx c)
        {
            AesKey k = Aes(c);
            var f = AoSeams.CmacKeyCompute(k);
            return Into(c, "AO-5.aes-cmackey-into", "CmacKey.Compute into", delegate { f(Data, 0, Data.Length, Tag, 0); });
        }

        [Clause("AO-5.aes-gcm-seal-into", PerBuild = true)]
        public static string GcmSealInto(Ctx c)
        {
            AesKey k = Aes(c);
            var f = AoSeams.GcmKeySealInto(k);
            return Into(c, "AO-5.aes-gcm-seal-into", "GcmKey.Seal into", delegate { f(Nonce, 0, Aad, 0, 0, Data, 0, Data.Length, Out, 0); });
        }

        [Clause("AO-5.aes-gcm-open-into", PerBuild = true)]
        public static string GcmOpenInto(Ctx c)
        {
            AesKey k = Aes(c);
            var seal = AoSeams.GcmKeySealInto(k);
            var open = AoSeams.GcmKeyOpenInto(k);
            byte[] sealedBytes = new byte[Data.Length + 16], plain = new byte[Data.Length];
            seal(Nonce, 0, Aad, 0, 0, Data, 0, Data.Length, sealedBytes, 0);
            return Into(c, "AO-5.aes-gcm-open-into", "GcmKey.TryOpen into", delegate { open(Nonce, 0, Aad, 0, 0, sealedBytes, 0, sealedBytes.Length, plain, 0); });
        }

        // ---- streamed forms and caller-buffer Verify forms (PRD 7.3 item 15): one object used again for each message, 0 B for the message ----

        [Clause("AO-5.aes-cbc-stream", PerBuild = true)]
        public static string CbcStream(Ctx c)
        {
            AesKey k = Aes(c);
            var e = AoSeams.Stream(k, "CbcChain", "CbcEncrypt"); var d = AoSeams.Stream(k, "CbcChain", "CbcDecrypt");
            string a = Into(c, "AO-5.aes-cbc-stream", "CbcChain.Init, Modes.CbcEncrypt with the CbcChain, Clear", delegate { e.Init(Iv, 0); e.Call(Data, 0, Data.Length, Out, 0); e.Clear(); });
            return a + "; " + Into(c, "AO-5.aes-cbc-stream", "CbcChain.Init, Modes.CbcDecrypt with the CbcChain, Clear", delegate { d.Init(Iv, 0); d.Call(Data, 0, Data.Length, Out, 0); d.Clear(); });
        }

        [Clause("AO-5.aes-ctr-stream", PerBuild = true)]
        public static string CtrStream(Ctx c)
        {
            AesKey k = Aes(c);
            var f = AoSeams.Stream(k, "CtrCounter", "Ctr");
            return Into(c, "AO-5.aes-ctr-stream", "CtrCounter.Init, Modes.Ctr with the CtrCounter, Clear", delegate { f.Init(Ctr0, 0); f.Call(Data, 0, Data.Length, Out, 0); f.Clear(); });
        }

        [Clause("AO-5.aes-cmac-verify-into", PerBuild = true)]
        public static string CmacVerifyInto(Ctx c)
        {
            AesKey k = Aes(c);
            var v = AoSeams.CmacVerifyInto(); var compute = AoSeams.CmacInto();
            byte[] tag = new byte[16];
            compute(k, Data, 0, Data.Length, tag, 0);
            if (!v(k, Data, 0, Data.Length, tag, 0)) throw new FailException("Cmac.Verify refused the tag that Cmac.Compute wrote");
            return Into(c, "AO-5.aes-cmac-verify-into", "Cmac.Verify with offsets", delegate { v(k, Data, 0, Data.Length, tag, 0); });
        }

        [Clause("AO-5.aes-cmackey-verify-into", PerBuild = true)]
        public static string CmacKeyVerifyInto(Ctx c)
        {
            AesKey k = Aes(c);
            var v = AoSeams.CmacKeyVerify(k); var compute = AoSeams.CmacKeyCompute(k);
            byte[] tag = new byte[16];
            compute(Data, 0, Data.Length, tag, 0);
            if (!v(Data, 0, Data.Length, tag, 0)) throw new FailException("CmacKey.Verify refused the tag that CmacKey.Compute wrote");
            return Into(c, "AO-5.aes-cmackey-verify-into", "CmacKey.Verify", delegate { v(Data, 0, Data.Length, tag, 0); });
        }
    }
}
