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
