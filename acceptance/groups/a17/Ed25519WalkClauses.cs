using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace Acceptance
{
    /// <summary>
    /// The Ed25519 walk (docs/sections-plan.md section 4, slice P8): GET /api/walk/ed25519?test=1|2|3. It runs on RFC 8032 section 7.1's
    /// published test keys only, so it stays open with Show keys OFF. The anchors are the suite's vector file and .NET's own SHA-512 and
    /// BigInteger, not the engine: the public key and the signature equal the RFC's; expanded is SHA-512(seed); scalar is its low half,
    /// clamped as RFC 8032 section 5.1.5 says; prefix is its high half; r is SHA-512(prefix || M) and h is SHA-512(R || A || M), each mod L;
    /// and S = (r + h * a) mod L. A missing test, or test 4, is 400 WALK_BAD_ARGUMENT.
    /// </summary>
    public static class Ed25519WalkClauses
    {
        public const string Path = "/api/walk/ed25519";

        /// <summary>The order of the base point, RFC 8032 section 5.1: L = 2^252 + 27742317777372353535851937790883648493.</summary>
        public static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

        public static BigInteger FromLittleEndian(byte[] b) { return new BigInteger(b, isUnsigned: true, isBigEndian: false); }

        // ---------------------------------------------------------------- edwards25519 (RFC 8032 section 5.1), affine, on BigInteger; the identity is (0, 1)

        public static readonly BigInteger Pq = BigInteger.Pow(2, 255) - 19;
        static BigInteger Fm(BigInteger v) { BigInteger r = v % Pq; return r.Sign < 0 ? r + Pq : r; }
        static BigInteger FInv(BigInteger v) { return BigInteger.ModPow(Fm(v), Pq - 2, Pq); }
        /// <summary>d = -121665 / 121666 mod p.</summary>
        public static readonly BigInteger Dc = Fm(-121665 * FInv(121666));

        public sealed class EPt { public BigInteger X, Y; public EPt(BigInteger x, BigInteger y) { X = x; Y = y; } }

        /// <summary>The x for a y, with the given low bit (section 5.1.3). Null when no x fits.</summary>
        public static EPt FromY(BigInteger y, int sign)
        {
            BigInteger u = Fm(y * y - 1), v = Fm(Dc * y * y + 1), x2 = Fm(u * FInv(v));
            BigInteger x = BigInteger.ModPow(x2, (Pq + 3) / 8, Pq);
            if (Fm(x * x) != x2) x = Fm(x * BigInteger.ModPow(2, (Pq - 1) / 4, Pq));
            if (Fm(x * x) != x2) return null;
            if ((int)(x & 1) != sign) x = Fm(-x);
            return new EPt(x, y);
        }

        /// <summary>The base point B: y = 4/5, x even (section 5.1).</summary>
        public static EPt BasePoint() { return FromY(Fm(4 * FInv(5)), 0); }

        public static EPt EAdd(EPt p, EPt q)
        {
            BigInteger t = Fm(Dc * p.X * q.X * p.Y * q.Y);
            return new EPt(Fm((p.X * q.Y + p.Y * q.X) * FInv(1 + t)), Fm((p.Y * q.Y + p.X * q.X) * FInv(1 - t)));
        }

        public static EPt EMul(BigInteger k, EPt p)
        {
            EPt r = new EPt(0, 1);
            for (int bit = (int)k.GetBitLength() - 1; bit >= 0; bit--) { r = EAdd(r, r); if (!((k >> bit) & 1).IsZero) r = EAdd(r, p); }
            return r;
        }

        /// <summary>Section 5.1.2: y little-endian, with the low bit of x in the top bit.</summary>
        public static byte[] Encode(EPt p) { byte[] b = ToLittleEndian32(p.Y); if (!(p.X & 1).IsZero) b[31] |= 0x80; return b; }

        public static EPt Decode(byte[] b) { byte[] y = (byte[])b.Clone(); int sign = y[31] >> 7; y[31] &= 0x7f; return FromY(FromLittleEndian(y), sign); }

        public static byte[] ToLittleEndian32(BigInteger v)
        {
            byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: false);
            byte[] out32 = new byte[32];
            Array.Copy(raw, out32, Math.Min(raw.Length, 32));
            return out32;
        }

        public static byte[] Sha512(params byte[][] parts)
        {
            using (SHA512 sha = SHA512.Create())
            {
                foreach (byte[] p in parts) sha.TransformBlock(p, 0, p.Length, null, 0);
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return sha.Hash;
            }
        }

        /// <summary>RFC 8032 section 5.1.5: clear the low 3 bits, clear bit 255, set bit 254. Little-endian.</summary>
        public static byte[] Clamp(byte[] lowHalf)
        {
            byte[] k = (byte[])lowHalf.Clone();
            k[0] &= 248; k[31] &= 127; k[31] |= 64;
            return k;
        }

        static string Hx(byte[] b) { return Hex.Encode(b).ToLowerInvariant(); }

        static byte[] Field(Dictionary<string, object> d, string name, string where)
        {
            string s = MiniJson.Str(d, name);
            Check.True(!string.IsNullOrEmpty(s), where + ": no " + name);
            return Hex.Decode(s);
        }

        /// <summary>r and h come as the 32-byte little-endian value mod L, as RFC 8032 encodes scalars (Richard's shape), not the 64-byte hash.</summary>
        static void SameModL(string where, byte[] hash64, byte[] shown)
        {
            BigInteger want = FromLittleEndian(hash64) % L;
            Check.True(shown.Length == 32, where + ": the value is " + shown.Length + " bytes, and the contract gives 32 (the hash mod L)");
            Check.Equal(where, Hx(ToLittleEndian32(want)), Hx(shown));
        }

        [Clause("A19.host.ed25519-walk-open-and-rfc8032")]
        public static string WalkOpenAndRfc8032(Ctx c)
        {
            List<VectorRecord> tests = c.Vectors("ed25519-rfc8032.nsv", "ed25519");
            using (HostProc h = A17.Host(c, "walk-ed25519"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                for (int n = 1; n <= 3; n++)
                {
                    VectorRecord v = tests[n - 1];
                    string where = "test=" + n + " (RFC 8032 " + v.Str("test") + ")";
                    Reply r = HostHttp.Get(h, Path + "?test=" + n);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P8)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + where + " got " + r + ". The walk runs on RFC 8032's published test keys, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, where + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    Check.Equal(where + ": keySource", "rfc8032", MiniJson.Str(r.Json, "keySource"));
                    byte[] seed = Hex.Decode(v.Str("seed")), msg = Hex.Decode(v.Str("message") ?? ""), pub = Hex.Decode(v.Str("public")), sig = Hex.Decode(v.Str("signature"));
                    Check.Equal(where + ": seed", Hx(seed), Hx(Field(r.Json, "seed", where)));
                    Check.Equal(where + ": message", Hx(msg), (MiniJson.Str(r.Json, "message") ?? "").ToLowerInvariant());
                    byte[] expanded = Sha512(seed);
                    Check.Equal(where + ": expanded is SHA-512(seed)", Hx(expanded), Hx(Field(r.Json, "expanded", where)));
                    byte[] low = new byte[32], prefix = new byte[32];
                    Array.Copy(expanded, low, 32); Array.Copy(expanded, 32, prefix, 0, 32);
                    byte[] a = Clamp(low);
                    Check.Equal(where + ": scalar is the low half clamped (RFC 8032 section 5.1.5)", Hx(a), Hx(Field(r.Json, "scalar", where)));
                    Check.Equal(where + ": prefix is the high half", Hx(prefix), Hx(Field(r.Json, "prefix", where)));
                    Check.Equal(where + ": publicKey is RFC 8032's", Hx(pub), Hx(Field(r.Json, "publicKey", where)));
                    byte[] rPoint = new byte[32], sBytes = new byte[32];
                    Array.Copy(sig, rPoint, 32); Array.Copy(sig, 32, sBytes, 0, 32);
                    Check.Equal(where + ": signature is RFC 8032's", Hx(sig), Hx(Field(r.Json, "signature", where)));
                    Check.Equal(where + ": rPoint is the signature's first half", Hx(rPoint), Hx(Field(r.Json, "rPoint", where)));
                    byte[] rHash = Sha512(prefix, msg), hHash = Sha512(rPoint, pub, msg);
                    SameModL(where + ": r is SHA-512(prefix || M) mod L", rHash, Field(r.Json, "r", where));
                    SameModL(where + ": h is SHA-512(R || A || M) mod L", hHash, Field(r.Json, "h", where));
                    BigInteger sWant = (FromLittleEndian(rHash) % L + FromLittleEndian(hHash) % L * FromLittleEndian(a)) % L;
                    Check.Equal(where + ": s is (r + h * a) mod L, and is the signature's second half", Hx(ToLittleEndian32(sWant)), Hx(Field(r.Json, "s", where)));
                    Check.Equal(where + ": RFC 8032's S equals (r + h * a) mod L", Hx(sBytes), Hx(ToLittleEndian32(sWant)));
                    Dictionary<string, object> verify = MiniJson.Obj(r.Json, "verify");
                    Check.True(verify != null && MiniJson.Bool(verify, "valid", false), where + ": verify.valid should be true");
                    Check.Equal(where + ": verify.rPrime equals R", Hx(rPoint), Hx(Field(verify, "rPrime", where + " verify")));
                    // The middle points, on the suite's own edwards25519 arithmetic (Jared, #283): sB = S*B, minusHA = h*(-A), and their sum is R.
                    EPt bp = BasePoint(), aPt = Decode(pub);
                    Check.True(aPt != null, where + ": RFC 8032's public key does not decode to a curve point");
                    Check.Equal(where + ": RFC 8032's public key is a*B on the suite's own curve arithmetic", Hx(pub), Hx(Encode(EMul(FromLittleEndian(a), bp))));
                    BigInteger hModL = FromLittleEndian(hHash) % L;
                    EPt sB = EMul(FromLittleEndian(sBytes), bp), minusHA = EMul(hModL, new EPt(Fm(-aPt.X), aPt.Y));
                    Check.Equal(where + ": verify.sB is S*B", Hx(Encode(sB)), Hx(Field(verify, "sB", where + " verify")));
                    Check.Equal(where + ": verify.minusHA is h*(-A)", Hx(Encode(minusHA)), Hx(Field(verify, "minusHA", where + " verify")));
                    Check.Equal(where + ": S*B + h*(-A) is R, the RFC's own R", Hx(rPoint), Hx(Encode(EAdd(sB, minusHA))));
                }
                foreach (string bad in new string[] { "", "?test=4", "?test=0", "?test=a" })
                {
                    Reply r = HostHttp.Get(h, Path + bad);
                    Check.True(r.Status == 400 && r.Code == "WALK_BAD_ARGUMENT", Path + bad + " should get 400 WALK_BAD_ARGUMENT, and got " + r);
                }
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF RFC 8032 TESTs 1 to 3 answer: the public key and signature equal the RFC's, expanded, the clamped scalar and the prefix follow SHA-512(seed), r and h are their hashes mod L, S = (r + h a) mod L, and verify is valid with R' = R; 4 bad tests each get 400 WALK_BAD_ARGUMENT";
            }
        }
    }
}
