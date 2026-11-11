using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// Draws one case for an algorithm. The draw happens once; the returned AoCase then runs on each side with private copies of the
    /// inputs, and records the outputs and every input array afterwards (a side that changes its caller's input differs).
    /// </summary>
    public static class AoGrammar
    {
        public static readonly string[] Algorithms = {
            "aes-block", "aes-ecb", "aes-cbc", "aes-ctr", "aes-gcm", "aes-cmac", "tdes-block",
            "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512", "shake128", "shake256",
            "hmac", "hkdf", "tls11-prf", "pinblock-format4" };

        static readonly string[] HashAlgs = { "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512" };

        public static int BlockOf(string alg)
        {
            switch (alg)
            {
                case "md5": case "sha1": case "sha256": return 64;
                case "sha384": case "sha512": return 128;
                case "sha3-256": return 136;
                case "sha3-512": return 72;
                default: return 64;
            }
        }

        public static int DigestOf(string alg)
        {
            switch (alg)
            {
                case "md5": return 16;
                case "sha1": return 20;
                case "sha256": case "sha3-256": return 32;
                case "sha384": return 48;
                default: return 64;
            }
        }

        delegate void Body();

        static void Try(AoRec r, Body b)
        {
            try { b(); r.Add("ok"); }
            catch (Exception e) { r.Add(AoRec.SigOf(e)); }
        }

        static byte[] C(byte[] b) { return b == null ? null : (byte[])b.Clone(); }

        public static AoCase Draw(string alg, Rng r)
        {
            switch (alg)
            {
                case "aes-block": return AesBlock(r);
                case "aes-ecb": return Ecb(r);
                case "aes-cbc": return Cbc(r);
                case "aes-ctr": return Ctr(r);
                case "aes-gcm": return GcmCase(r);
                case "aes-cmac": return CmacCase(r);
                case "tdes-block": return TdesBlock(r);
                case "shake128": return ShakeCase(r, true);
                case "shake256": return ShakeCase(r, false);
                case "hmac": return HmacCase(r);
                case "hkdf": return HkdfCase(r);
                case "tls11-prf": return PrfCase(r);
                case "pinblock-format4": return PinCase(r);
                case "aes-walk": return WalkCase(r);
                default:
                    if (Array.IndexOf(HashAlgs, alg) >= 0) return HashCase(r, alg);
                    throw new ArgumentException("no grammar for " + alg);
            }
        }

        static byte[] AesKeyBytes(Rng r) { return r.Int(100) == 0 ? r.Bytes(AoDraw.BadAesKeyLengths[r.Int(AoDraw.BadAesKeyLengths.Length)]) : r.Bytes(AoDraw.KeyLen(r)); }

        // ---- AES ----

        static AoCase AesBlock(Rng r)
        {
            byte[] key = AesKeyBytes(r);
            int n = 1 + r.Int(3);
            AoBlockCall[] calls = new AoBlockCall[n];
            for (int i = 0; i < n; i++) calls[i] = AoBlockCall.Draw(r, 16);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key);
                object ko = s.NewAes(k);
                foreach (AoBlockCall call in calls)
                    call.Run(delegate (byte[] i, int io, byte[] o, int oo) { s.AesEncrypt(ko, i, io, o, oo); },
                             delegate (byte[] i, int io, byte[] o, int oo) { s.AesDecrypt(ko, i, io, o, oo); }, rec);
                rec.Add(k);
            };
        }

        static byte[] BlockData(Rng r)
        {
            int n = AoDraw.Blocks(r, 16, 64);
            if (r.Int(33) == 0) n += 1 + r.Int(15);
            return r.Int(200) == 0 ? null : r.Bytes(n);
        }

        static byte[] Iv(Rng r)
        {
            int p = r.Int(100);
            if (p == 0) return null;
            if (p < 3) { int[] bad = { 0, 8, 15, 17, 32 }; return r.Bytes(bad[r.Int(bad.Length)]); }
            return r.Bytes(16);
        }

        static AoCase Ecb(Rng r)
        {
            byte[] key = AesKeyBytes(r), data = BlockData(r);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), d = C(data);
                object ko = s.NewAes(k);
                byte[] o = null;
                Try(rec, delegate { o = s.Ecb(ko, d); });
                rec.Add(o); rec.Add(d); rec.Add(k);
            };
        }

        static AoCase Cbc(Rng r)
        {
            byte[] key = AesKeyBytes(r), data = BlockData(r), iv = Iv(r);
            bool enc = r.Int(2) == 0;
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), d = C(data), v = C(iv);
                object ko = s.NewAes(k);
                byte[] o = null;
                Try(rec, delegate { o = s.Cbc(ko, v, d, enc); });
                rec.Add(o); rec.Add(d); rec.Add(v); rec.Add(k);
            };
        }

        static AoCase Ctr(Rng r)
        {
            byte[] key = AesKeyBytes(r), data = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 4096));
            byte[] ctr = r.Int(50) == 0 ? Iv(r) : AoDraw.NearWrapCounter(r);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), d = C(data), c = C(ctr);
                object ko = s.NewAes(k);
                byte[] o = null;
                Try(rec, delegate { o = s.Ctr(ko, c, d); });
                rec.Add(o); rec.Add(d); rec.Add(c); rec.Add(k);
            };
        }

        static byte[] Nonce(Rng r)
        {
            int p = r.Int(100);
            if (p < 70) return r.Bytes(12);
            if (p == 70) return null;
            int[] lens = { 0, 1, 8, 11, 13, 16, 32, 60, 64 };
            return r.Bytes(lens[r.Int(lens.Length)]);
        }

        static AoCase GcmCase(Rng r)
        {
            byte[] key = AesKeyBytes(r), nonce = Nonce(r);
            byte[] aad = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 1024));
            byte[] plain = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 4096));
            int tamper = r.Int(6);           // 0 to 2 open the true seal; 3 flips a seal bit, 4 an aad bit, 5 cuts the seal short
            int cut = r.Int(17), flip = r.Int(1 << 20);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), n = C(nonce), a = C(aad), p = C(plain);
                object ko = s.NewAes(k);
                byte[] sealedBytes = null;
                Try(rec, delegate { sealedBytes = s.GcmSeal(ko, n, a, p); });
                rec.Add(sealedBytes); rec.Add(n); rec.Add(a); rec.Add(p);
                if (sealedBytes == null) { rec.Add(k); return; }
                byte[] open = C(sealedBytes), openAad = C(a);
                if (tamper == 3 && open.Length > 0) open[(flip / 8) % open.Length] ^= (byte)(1 << (flip % 8));
                if (tamper == 4 && openAad != null && openAad.Length > 0) openAad[(flip / 8) % openAad.Length] ^= (byte)(1 << (flip % 8));
                if (tamper == 5) { byte[] sh = new byte[Math.Min(open.Length, cut)]; Array.Copy(open, sh, sh.Length); open = sh; }
                byte[] plainOut = null;
                bool ok = false;
                Try(rec, delegate { ok = s.GcmOpen(ko, n, openAad, open, out plainOut); });
                rec.Add(ok); rec.Add(plainOut); rec.Add(open); rec.Add(k);
            };
        }

        static AoCase CmacCase(Rng r)
        {
            byte[] key = AesKeyBytes(r), msg = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 4096));
            int tamper = r.Int(4);   // 0, 1 true tag; 2 flipped bit; 3 truncated
            int flipAt = r.Int(16), bit = r.Int(8), cut = r.Int(16);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), m = C(msg);
                object ko = s.NewAes(k);
                byte[] tag = null;
                Try(rec, delegate { tag = s.Cmac(ko, m); });
                rec.Add(tag); rec.Add(m);
                if (tag != null)
                {
                    byte[] check = C(tag);
                    if (tamper == 2) check[flipAt % check.Length] ^= (byte)(1 << bit);
                    if (tamper == 3) { byte[] sh = new byte[Math.Min(cut, check.Length)]; Array.Copy(check, sh, sh.Length); check = sh; }
                    bool ok = false;
                    Try(rec, delegate { ok = s.CmacVerify(ko, m, check); });
                    rec.Add(ok); rec.Add(check);
                }
                rec.Add(k);
            };
        }

        // ---- TDES ----

        static AoCase TdesBlock(Rng r)
        {
            byte[] key;
            if (r.Int(50) == 0) { int[] bad = { 0, 8, 15, 17, 23, 25, 32 }; key = r.Bytes(bad[r.Int(bad.Length)]); }
            else key = r.Bytes(r.Int(2) == 0 ? 16 : 24);
            int n = 1 + r.Int(3);
            AoBlockCall[] calls = new AoBlockCall[n];
            for (int i = 0; i < n; i++) calls[i] = AoBlockCall.Draw(r, 8);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key);
                object ko = s.NewTdes(k);
                foreach (AoBlockCall call in calls)
                    call.Run(delegate (byte[] i, int io, byte[] o, int oo) { s.TdesEncrypt(ko, i, io, o, oo); },
                             delegate (byte[] i, int io, byte[] o, int oo) { s.TdesDecrypt(ko, i, io, o, oo); }, rec);
                rec.Add(k);
            };
        }

        // ---- hashes ----

        static AoCase HashCase(Rng r, string alg)
        {
            int n = AoDraw.Len(r, 4096);
            int pre = r.Int(9), post = r.Int(9);
            byte[] buf = r.Bytes(pre + n + post);
            int[] pieces = AoDraw.Pieces(r, n, BlockOf(alg));
            int cloneAfter = r.Int(pieces.Length + 1);   // pieces.Length means no clone
            bool updateAfterFinish = r.Int(10) == 0;
            return delegate (AoSide s, AoRec rec)
            {
                byte[] b = C(buf);
                IAoHash h = s.NewHash(alg);
                IAoHash clone = null;
                int off = pre, cloneOff = -1;
                for (int i = 0; i < pieces.Length; i++)
                {
                    if (i == cloneAfter) { clone = h.Clone(); cloneOff = off; }
                    int at = off, len = pieces[i];
                    Try(rec, delegate { h.Update(b, at, len); });
                    off += pieces[i];
                }
                byte[] d = null;
                Try(rec, delegate { d = h.Finish(); });
                rec.Add(d);
                if (updateAfterFinish) Try(rec, delegate { h.Update(b, 0, 1); });
                if (clone != null)
                {
                    int rest = pre + n - cloneOff;
                    int at = cloneOff;
                    Try(rec, delegate { clone.Update(b, at, rest); });
                    byte[] dc = null;
                    Try(rec, delegate { dc = clone.Finish(); });
                    rec.Add(dc);
                }
                rec.Add(b);
            };
        }

        static AoCase ShakeCase(Rng r, bool is128)
        {
            byte[] data = r.Int(100) == 0 ? null : r.Bytes(AoDraw.Len(r, 4096));
            int count = 1 + r.Int(4);
            int[] sizes = new int[count];
            for (int i = 0; i < count; i++) sizes[i] = AoDraw.Len(r, 600);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] d = C(data), o = null;
                Try(rec, delegate { o = s.Shake(is128, d, sizes); });
                rec.Add(o); rec.Add(d);
            };
        }

        static AoCase HmacCase(Rng r)
        {
            string alg = HashAlgs[r.Int(HashAlgs.Length)];
            byte[] key = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 300));
            byte[] data = r.Int(200) == 0 ? null : r.Bytes(AoDraw.Len(r, 4096));
            int tamper = r.Int(4), flip = r.Int(1 << 20), cut = r.Int(64);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), d = C(data), tag = null;
                Try(rec, delegate { tag = s.Hmac(alg, k, d); });
                rec.Add(tag);
                if (tag != null)
                {
                    byte[] check = C(tag);
                    if (tamper == 2) check[flip % check.Length] ^= (byte)(1 << (flip % 8));
                    if (tamper == 3) { byte[] sh = new byte[Math.Min(cut, check.Length)]; Array.Copy(check, sh, sh.Length); check = sh; }
                    bool ok = false;
                    Try(rec, delegate { ok = s.HmacVerify(alg, k, d, check); });
                    rec.Add(ok);
                }
                rec.Add(k); rec.Add(d);
            };
        }

        static AoCase HkdfCase(Rng r)
        {
            string alg = HashAlgs[r.Int(HashAlgs.Length)];
            int hl = DigestOf(alg);
            byte[] salt = r.Int(10) == 0 ? null : r.Bytes(AoDraw.Len(r, 200));
            byte[] ikm = r.Bytes(AoDraw.Len(r, 200));
            bool usePrk = r.Int(5) != 0;
            byte[] prk = r.Bytes(AoDraw.Len(r, 2 * hl));
            byte[] info = r.Int(100) == 0 ? null : r.Bytes(AoDraw.Len(r, 100));
            int n;
            int p = r.Int(200);
            if (p == 0) n = 255 * hl;
            else if (p == 1) n = 255 * hl + 1;
            else if (p == 2) n = -1;
            else if (p < 60) { int[] e = { 0, 1, hl - 1, hl, hl + 1, 2 * hl, 2 * hl + 1 }; n = e[r.Int(e.Length)]; }
            else n = r.Int(4 * hl + 1);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] sa = C(salt), ik = C(ikm), inf = C(info), extracted = null, expanded = null;
                Try(rec, delegate { extracted = s.HkdfExtract(alg, sa, ik); });
                rec.Add(extracted);
                byte[] pk = usePrk && extracted != null ? C(extracted) : C(prk);
                Try(rec, delegate { expanded = s.HkdfExpand(alg, pk, inf, n); });
                rec.Add(expanded); rec.Add(sa); rec.Add(ik); rec.Add(inf); rec.Add(pk);
            };
        }

        // ---- TLS 1.1 PRF ----

        static AoCase PrfCase(Rng r)
        {
            int op = r.Int(5);
            byte[] a = r.Int(100) == 0 ? null : r.Bytes(AoDraw.Len(r, 120));
            byte[] cr = r.Bytes(r.Int(20) == 0 ? AoDraw.Len(r, 64) : 32), sr = r.Bytes(r.Int(20) == 0 ? AoDraw.Len(r, 64) : 32);
            string label = r.Int(3) == 0 ? (r.Int(2) == 0 ? "client finished" : "server finished") : AoDraw.Ascii(r, r.Int(24));
            byte[] seed = r.Bytes(AoDraw.Len(r, 100));
            int count = r.Int(100) == 0 ? -1 : AoDraw.Len(r, 400);
            byte[] digest = r.Bytes(r.Int(10) == 0 ? AoDraw.Len(r, 64) : 36);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] x = C(a), c1 = C(cr), s1 = C(sr), sd = C(seed), dg = C(digest), o = null;
                byte[][] kb = null;
                switch (op)
                {
                    case 0: Try(rec, delegate { o = s.PrfDerive(x, label, sd, count); }); break;
                    case 1: Try(rec, delegate { o = s.PrfMaster(x, c1, s1); }); break;
                    case 2: Try(rec, delegate { kb = s.PrfKeyBlock(x, c1, s1); }); break;
                    case 3: Try(rec, delegate { o = s.PrfFinished(x, label, dg); }); break;
                    default: Try(rec, delegate { o = s.PrfMd5Sha1(x); }); break;
                }
                rec.Add(o);
                if (kb != null) foreach (byte[] part in kb) rec.Add(part);
                rec.Add(x); rec.Add(c1); rec.Add(s1); rec.Add(sd); rec.Add(dg);
            };
        }

        // ---- the AES lesson walk (AO-7) ----

        static AoCase WalkCase(Rng r)
        {
            byte[] key = AesKeyBytes(r);
            byte[] block = r.Int(100) == 0 ? r.Bytes(r.Int(16)) : r.Bytes(16);
            byte[] before = r.Bytes(r.Int(50) == 0 ? 3 : 16);
            int rcon = r.Int(20) == 0 ? -1 : r.Int(16);
            bool inverse = r.Int(2) == 0;
            int op = r.Int(5);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(key), b = C(block), bf = C(before);
                object walk = null;
                switch (op)
                {
                    case 0: { object ko = s.NewAes(k); Try(rec, delegate { walk = s.WalkEncrypt(ko, b); }); break; }
                    case 1: { object ko = s.NewAes(k); Try(rec, delegate { walk = s.WalkDecrypt(ko, b); }); break; }
                    case 2: { object ko = s.NewAes(k); Try(rec, delegate { walk = s.WalkKeyExpansion(ko); }); break; }
                    case 3: Try(rec, delegate { walk = s.WalkTables(rcon); }); break;
                    default: Try(rec, delegate { walk = s.WalkMixTerms(bf, inverse); }); break;
                }
                rec.Add(AoDump.Of(walk)); rec.Add(k); rec.Add(b); rec.Add(bf);
            };
        }

        // ---- PIN block format 4 ----

        static AoCase PinCase(Rng r)
        {
            byte[] pinKey = AesKeyBytes(r);
            string pin = r.Int(33) == 0 ? (r.Int(2) == 0 ? AoDraw.Digits(r, r.Int(2) == 0 ? 3 : 13) : "12a4") : AoDraw.Digits(r, 4 + r.Int(9));
            string pan = r.Int(33) == 0 ? AoDraw.Digits(r, r.Int(2) == 0 ? 11 : 20) : AoDraw.Digits(r, 12 + r.Int(8));
            string otherPan = AoDraw.Digits(r, 12 + r.Int(8));
            byte[] random8 = r.Bytes(r.Int(50) == 0 ? 7 : 8);
            int mode = r.Int(4);     // 0, 1 right pan; 2 other pan; 3 flipped block bit
            int flip = r.Int(16 * 8);
            return delegate (AoSide s, AoRec rec)
            {
                byte[] k = C(pinKey), rnd = C(random8), block = null, field = null, opened = null;
                Try(rec, delegate { block = s.PinEncrypt4(k, pin, pan, rnd); });
                Try(rec, delegate { field = s.PinClearField4(pin, rnd); });
                rec.Add(block); rec.Add(field);
                if (block != null)
                {
                    byte[] b = C(block);
                    if (mode == 3 && b.Length > 0) b[(flip / 8) % b.Length] ^= (byte)(1 << (flip % 8));
                    string usePan = mode == 2 ? otherPan : pan;
                    string got = null;
                    bool ok1 = false, ok2 = false;
                    Try(rec, delegate { ok1 = s.PinTryDecrypt4(k, b, usePan, out got); });
                    Try(rec, delegate { ok2 = s.PinTryOpenField4(k, b, usePan, out opened); });
                    rec.Add(ok1); rec.Add(got); rec.Add(ok2); rec.Add(opened); rec.Add(b);
                }
                rec.Add(k); rec.Add(rnd);
            };
        }
    }
}
