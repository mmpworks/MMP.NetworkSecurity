using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// The fake Host's P6, P8b and P9 walk routes: SHA-256, HMAC, the seal chain, ECDSA and DES. Each is served from the suite's own vector
    /// files and reference code, and each named defect is one way a Host could get the walk wrong.
    /// </summary>
    public sealed partial class FakeHost
    {
        string VectorsDir() { return Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(_vaultScript))), "vectors"); }

        static List<object> Words(uint[] w) { List<object> o = new List<object>(); foreach (uint v in w) o.Add(Sha256WalkClauses.W8(v)); return o; }

        /// <summary>SHA-256 on FIPS 180-4's examples. Defects: sha256-round-wrong (round 10's state), sha256-bad-name-ok (an unknown name answers 200).</summary>
        bool Sha256Route(HttpListenerContext ctx, string path)
        {
            if (path != Sha256WalkClauses.Path || M("walk-routes-missing")) return false;
            string name = ctx.Request.QueryString["name"];
            if (name != "abc" && name != "two-block") { if (M("sha256-bad-name-ok")) name = "abc"; else { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "name must be abc or two-block."); return true; } }
            byte[] msg = Sha256WalkClauses.Message(name);
            uint[] hv = Sha256WalkClauses.H0();
            uint[] k = Sha256WalkClauses.K();
            List<object> blocks = new List<object>();
            foreach (byte[] block in Sha256WalkClauses.Pad(msg))
            {
                uint[] schedule; List<Sha256WalkClauses.Round> rounds;
                uint[] hOut = Sha256WalkClauses.Compress(hv, block, out schedule, out rounds);
                List<object> rs = new List<object>();
                for (int t = 0; t < 64; t++)
                {
                    uint[] st = (uint[])rounds[t].State.Clone();
                    if (t == 10 && M("sha256-round-wrong")) st[0] ^= 1;
                    rs.Add(D("t", (double)t, "k", Sha256WalkClauses.W8(k[t]), "w", Sha256WalkClauses.W8(rounds[t].W), "t1", Sha256WalkClauses.W8(rounds[t].T1), "t2", Sha256WalkClauses.W8(rounds[t].T2), "state", Words(st)));
                }
                blocks.Add(D("bytes", Hex.Encode(block).ToLowerInvariant(), "hIn", Words(hv), "schedule", Words(schedule), "rounds", rs, "hOut", Words(hOut)));
                hv = hOut;
            }
            string digest;
            using (SHA256 sha = SHA256.Create()) digest = Hex.Encode(sha.ComputeHash(msg)).ToLowerInvariant();
            WalkWrite(ctx, 200, D("name", name, "source", "FIPS 180-4", "keySource", "none", "message", Encoding.ASCII.GetString(msg), "digest", digest, "blocks", blocks), false);
            return true;
        }

        /// <summary>HMAC-SHA-256 on RFC 4231's cases. Defects: hmac-inner-pad-wrong (xor 0x5c inside), hmac-case5-ok (case 5 answers 200).</summary>
        bool HmacRoute(HttpListenerContext ctx, string path)
        {
            if (path != HmacWalkClauses.Path || M("walk-routes-missing")) return false;
            string cs = ctx.Request.QueryString["case"];
            if (cs == "5" && M("hmac-case5-ok")) cs = "1";
            if (Array.IndexOf(new string[] { "1", "2", "3", "4", "6", "7" }, cs) < 0) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "case must be 1, 2, 3, 4, 6 or 7."); return true; }
            VectorRecord v = Nsv.Load(VectorsDir(), "hmac-rfc4231.nsv", "hmac-sha256").Find(x => x.Str("case") == cs);
            byte[] key = Hex.Decode(v.Str("key")), data = Hex.Decode(v.Str("data"));
            byte[] used = key.Length > 64 ? HmacWalkClauses.Sha256(key) : key, padded = HmacWalkClauses.PaddedKey(key);
            byte[] ipad = HmacWalkClauses.Xor(padded, M("hmac-inner-pad-wrong") ? (byte)0x5c : (byte)0x36), opad = HmacWalkClauses.Xor(padded, 0x5c);
            byte[] inner = HmacWalkClauses.Sha256(ipad, data), mac = HmacWalkClauses.Sha256(opad, inner);
            Func<byte[], string> hx = b => Hex.Encode(b).ToLowerInvariant();
            WalkWrite(ctx, 200, D("case", double.Parse(cs), "source", "RFC 4231 section 4", "keySource", "rfc4231", "hash", "SHA-256", "blockSize", 64.0, "key", hx(key), "message", hx(data),
                "keyHashed", key.Length > 64, "keyUsed", hx(used), "paddedKey", hx(padded), "innerPad", hx(ipad), "innerDigest", hx(inner), "outerPad", hx(opad), "mac", hx(mac)), false);
            return true;
        }

        /// <summary>The 4-row fixture seal chain. Defects: seal-middle-not-caught (firstBadSeq 0 for middle), seal-text-wrong (the text leaves out detail).</summary>
        bool SealChainRoute(HttpListenerContext ctx, string path)
        {
            if (path != SealChainWalkClauses.Path || M("walk-routes-missing")) return false;
            string edit = ctx.Request.QueryString["edit"] ?? "none";
            if (edit != "none" && edit != "middle" && edit != "newest") { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "edit must be none, middle or newest."); return true; }
            string seed = SealChainWalkClauses.Sha256Hex(SealChainWalkClauses.SeedText);
            string[][] rows = {
                new string[] { "2026-11-01T09:00:00Z", "app", "store", "lesson1.aes", "1", "ok", "stored" },
                new string[] { "2026-11-01T09:01:00Z", "app", "read", "lesson1.aes", "1", "ok", "read" },
                new string[] { "2026-11-01T09:02:00Z", "attacker", "read", "lesson1.aes", "", "refused", "no grant" },
                new string[] { "2026-11-01T09:03:00Z", "app", "rotate", "lesson1.aes", "2", "ok", "rotated" },
            };
            // Each row's stored prev hash is the honest chain's. An edit then changes one row's detail after the fact.
            List<Dictionary<string, object>> links = new List<Dictionary<string, object>>();
            string prev = seed;
            for (int i = 0; i < 4; i++)
            {
                string[] r = rows[i];
                Dictionary<string, object> l = D("seq", (double)(i + 1), "at", r[0], "caller", r[1], "op", r[2], "name", r[3], "version", r[4] == "" ? null : (object)double.Parse(r[4]), "result", r[5], "detail", r[6], "storedPrevHash", prev);
                prev = SealChainWalkClauses.Sha256Hex(SealChainWalkClauses.Compose(l));
                links.Add(l);
            }
            if (edit == "middle") links[1]["detail"] = "read twice";
            if (edit == "newest") links[3]["detail"] = "rotated by someone else";
            string expected = seed;
            int firstBad = 0;
            foreach (Dictionary<string, object> l in links)
            {
                string text = SealChainWalkClauses.Compose(l);
                if (M("seal-text-wrong")) text = text.Substring(0, text.LastIndexOf('\n'));
                bool holds = (string)l["storedPrevHash"] == expected;
                if (!holds && firstBad == 0) firstBad = (int)(double)l["seq"];
                l["text"] = text; l["expectedPrevHash"] = expected; l["linkHolds"] = holds; l["hash"] = SealChainWalkClauses.Sha256Hex(text);
                expected = (string)l["hash"];
            }
            if (edit == "middle" && M("seal-middle-not-caught")) firstBad = 0;
            List<object> outLinks = new List<object>(); foreach (Dictionary<string, object> l in links) outLinks.Add(l);
            WalkWrite(ctx, 200, D("edit", edit, "source", "fixture", "seed", seed, "firstBadSeq", (double)firstBad, "links", outLinks), false);
            return true;
        }

        static Dictionary<string, object> EcPt(EcdsaWalkClauses.Pt p) { return p == null ? null : D("x", EcdsaWalkClauses.H32(p.X), "y", EcdsaWalkClauses.H32(p.Y)); }

        /// <summary>ECDSA P-256 on RFC 6979 A.2.5. Defects: ecdsa-kg-row-wrong (row 100's afterDouble), ecdsa-s-wrong.</summary>
        bool EcdsaRoute(HttpListenerContext ctx, string path)
        {
            if (path != EcdsaWalkClauses.Path || M("walk-routes-missing")) return false;
            string m = ctx.Request.QueryString["message"];
            VectorRecord v = m == null ? null : Nsv.Load(VectorsDir(), "ecdsa-rfc6979.nsv", "ecdsa-p256-sha256").Find(x => x.Str("message") == m);
            if (v == null) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "message must be sample or test."); return true; }
            EcdsaWalkClauses.Curve cv = EcdsaWalkClauses.P256();
            Func<string, BigInteger> be = s => new BigInteger(Hex.Decode(s), isUnsigned: true, isBigEndian: true);
            BigInteger x = be(v.Str("x")), k = be(v.Str("k")), r = be(v.Str("r")), s = be(v.Str("s"));
            if (M("ecdsa-s-wrong")) s = (s + 1) % cv.N;
            byte[] msg = Encoding.ASCII.GetBytes(m), h1;
            using (SHA256 sha = SHA256.Create()) h1 = sha.ComputeHash(msg);
            BigInteger e = new BigInteger(h1, isUnsigned: true, isBigEndian: true) % cv.N;
            List<object> kg = new List<object>();
            EcdsaWalkClauses.Pt acc = null;
            int top = (int)k.GetBitLength();
            for (int i = 0; i < top; i++)
            {
                int bit = top - 1 - i;
                bool one = !((k >> bit) & 1).IsZero;
                acc = EcdsaWalkClauses.Add(cv, acc, acc);
                EcdsaWalkClauses.Pt shownDouble = i == 100 && M("ecdsa-kg-row-wrong") ? EcdsaWalkClauses.Add(cv, acc, cv.G) : acc;
                Dictionary<string, object> row = D("bit", (double)bit, "isOne", one, "afterDouble", EcPt(shownDouble), "afterAdd", null);
                if (one) { acc = EcdsaWalkClauses.Add(cv, acc, cv.G); row["afterAdd"] = EcPt(acc); }
                kg.Add(row);
            }
            BigInteger w = EcdsaWalkClauses.Inv(s, cv.N), u1 = e * w % cv.N, u2 = r * w % cv.N;
            EcdsaWalkClauses.Pt u = EcdsaWalkClauses.Mul(cv, x, cv.G);
            EcdsaWalkClauses.Pt vx = EcdsaWalkClauses.Add(cv, EcdsaWalkClauses.Mul(cv, u1, cv.G), EcdsaWalkClauses.Mul(cv, u2, u));
            WalkWrite(ctx, 200, D("message", m, "source", "RFC 6979 A.2.5", "keySource", "rfc6979", "curve", "P-256", "hash", "SHA-256", "byteOrder", "big-endian",
                "privateKey", EcdsaWalkClauses.H32(x), "publicKey", EcPt(u), "h1", Hex.Encode(h1).ToLowerInvariant(), "e", EcdsaWalkClauses.H32(e), "rfc6979", new List<object>(),
                "k", EcdsaWalkClauses.H32(k), "kG", kg, "bigR", EcPt(acc), "r", EcdsaWalkClauses.H32(r), "kInverse", EcdsaWalkClauses.H32(EcdsaWalkClauses.Inv(k, cv.N)), "s", EcdsaWalkClauses.H32(s),
                "verify", D("w", EcdsaWalkClauses.H32(w), "u1", EcdsaWalkClauses.H32(u1), "u2", EcdsaWalkClauses.H32(u2), "x", EcPt(vx), "valid", vx != null && vx.X % cv.N == r)), false);
            return true;
        }

        /// <summary>
        /// DES on CAVP's first TECBvarkey, TECBvartext and TECBsubtab rows. The fake has no DES of its own: its 16 rounds hold the Feistel rule
        /// on made-up f values, and its output is CAVP's ciphertext. Defects: des-feistel-wrong (round 5's rightOut), des-box-row-wrong.
        /// </summary>
        bool DesRoute(HttpListenerContext ctx, string path)
        {
            if (path != DesWalkClauses.Path || M("walk-routes-missing")) return false;
            string name = ctx.Request.QueryString["name"];
            if (Array.IndexOf(DesWalkClauses.Names, name) < 0) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "name must be varkey, vartext or subtab."); return true; }
            VectorRecord v = Nsv.Load(VectorsDir(), "tdes-cavp.nsv", "tdes-ecb-encrypt-kat").Find(x => x.Str("file") == "TECB" + name);
            string key8 = v.Str("key").ToLowerInvariant().Substring(0, 16), pt = v.Str("plaintext").ToLowerInvariant(), ct = v.Str("ciphertext").ToLowerInvariant();
            uint l = Convert.ToUInt32(pt.Substring(0, 8), 16), r = Convert.ToUInt32(pt.Substring(8), 16);
            List<object> rounds = new List<object>(), keys = new List<object>();
            for (int i = 1; i <= 16; i++)
            {
                uint f = (uint)(0x9e3779b9u * (uint)i);
                uint lOut = r, rOut = l ^ f;
                if (i == 5 && M("des-feistel-wrong")) rOut ^= 1;
                List<object> boxes = new List<object>();
                for (int b = 1; b <= 8; b++)
                {
                    int six = (int)((f >> (b * 3)) & 63);
                    string bits = Convert.ToString(six, 2).PadLeft(6, '0');
                    int row = Convert.ToInt32("" + bits[0] + bits[5], 2), col = Convert.ToInt32(bits.Substring(1, 4), 2);
                    if (b == 3 && i == 2 && M("des-box-row-wrong")) row = (row + 1) % 4;
                    boxes.Add(D("box", (double)b, "six", bits, "row", (double)row, "column", (double)col, "output", "0000"));
                }
                rounds.Add(D("round", (double)i, "leftIn", l.ToString("x8"), "rightIn", r.ToString("x8"), "key", "000000000000", "expanded", "000000000000", "mixed", "000000000000", "boxes", boxes, "boxesOut", "00000000", "f", f.ToString("x8"), "leftOut", lOut.ToString("x8"), "rightOut", rOut.ToString("x8")));
                keys.Add(D("round", (double)i, "c", "0000000", "d", "0000000", "key", "000000000000"));
                l = lOut; r = rOut;
            }
            WalkWrite(ctx, 200, D("name", name, "source", "NIST CAVP TECB" + name, "keySource", "cavp", "key", key8, "plaintext", pt, "ciphertext", ct,
                "schedule", D("pc1", "00000000000000", "rounds", keys), "ip", pt, "rounds", rounds, "preOutput", ct, "output", ct), false);
            return true;
        }
    }
}
