using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Acceptance
{
    /// <summary>
    /// The HMAC walk (docs/sections-plan.md section 4, slice P6): GET /api/walk/hmac?case=1|2|3|4|6|7, on RFC 4231 section 4's HMAC-SHA-256
    /// cases. Case 5 is truncated, so it is left out. The walk runs on published test keys only, so it stays open with Show keys OFF. The
    /// anchors are the suite's vector file and RFC 2104's construction run here on .NET's SHA-256: a key longer than the 64-byte block is
    /// hashed first, the key is padded with zeros to 64 bytes, the inner pad is K xor 0x36, the inner digest is SHA-256(inner pad || message),
    /// the outer pad is K xor 0x5c, and the MAC is SHA-256(outer pad || inner digest). .NET's HMACSHA256 checks the MAC a second way.
    /// </summary>
    public static class HmacWalkClauses
    {
        public const string Path = "/api/walk/hmac";
        public static readonly int[] Cases = { 1, 2, 3, 4, 6, 7 };

        public static byte[] Sha256(params byte[][] parts)
        {
            using (SHA256 sha = SHA256.Create())
            {
                foreach (byte[] p in parts) sha.TransformBlock(p, 0, p.Length, null, 0);
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return sha.Hash;
            }
        }

        public static byte[] Xor(byte[] k, byte b) { byte[] o = new byte[k.Length]; for (int i = 0; i < k.Length; i++) o[i] = (byte)(k[i] ^ b); return o; }

        public static byte[] PaddedKey(byte[] key)
        {
            byte[] used = key.Length > 64 ? Sha256(key) : key;
            byte[] padded = new byte[64];
            Array.Copy(used, padded, used.Length);
            return padded;
        }

        static string Hx(byte[] b) { return Hex.Encode(b).ToLowerInvariant(); }

        [Clause("A19.host.hmac-walk-open-and-rfc4231")]
        public static string WalkOpenAndRfc4231(Ctx c)
        {
            List<VectorRecord> all = c.Vectors("hmac-rfc4231.nsv", "hmac-sha256");
            using (HostProc h = A17.Host(c, "walk-hmac"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                foreach (int n in Cases)
                {
                    VectorRecord v = all.Find(x => x.Str("case") == n.ToString());
                    Check.True(v != null, "vectors/hmac-rfc4231.nsv has no case " + n);
                    string where = "case=" + n + " (RFC 4231 test case " + n + ")";
                    Reply r = HostHttp.Get(h, Path + "?case=" + n);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P6)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + where + " got " + r + ". The walk runs on RFC 4231's published keys, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, where + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    Check.Equal(where + ": keySource", "rfc4231", MiniJson.Str(r.Json, "keySource"));
                    byte[] key = Hex.Decode(v.Str("key")), data = Hex.Decode(v.Str("data")), mac = Hex.Decode(v.Str("mac"));
                    Check.Equal(where + ": key", Hx(key), (MiniJson.Str(r.Json, "key") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": message", Hx(data), (MiniJson.Str(r.Json, "message") ?? "").ToLowerInvariant());
                    Check.True(MiniJson.Bool(r.Json, "keyHashed", false) == (key.Length > 64), where + ": keyHashed should be " + (key.Length > 64) + " for a " + key.Length + "-byte key");
                    byte[] used = key.Length > 64 ? Sha256(key) : key, padded = PaddedKey(key);
                    Check.Equal(where + ": keyUsed", Hx(used), (MiniJson.Str(r.Json, "keyUsed") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": paddedKey (64 bytes)", Hx(padded), (MiniJson.Str(r.Json, "paddedKey") ?? "").ToLowerInvariant());
                    byte[] ipad = Xor(padded, 0x36), opad = Xor(padded, 0x5c), inner = Sha256(ipad, data);
                    Check.Equal(where + ": innerPad is K xor 0x36", Hx(ipad), (MiniJson.Str(r.Json, "innerPad") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": innerDigest is SHA-256(inner pad || message)", Hx(inner), (MiniJson.Str(r.Json, "innerDigest") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": outerPad is K xor 0x5c", Hx(opad), (MiniJson.Str(r.Json, "outerPad") ?? "").ToLowerInvariant());
                    byte[] bcl;
                    using (HMACSHA256 hm = new HMACSHA256(key)) bcl = hm.ComputeHash(data);
                    Check.Equal(where + ": RFC 4231's MAC equals .NET's HMACSHA256", Hx(mac), Hx(bcl));
                    Check.Equal(where + ": RFC 4231's MAC is SHA-256(outer pad || inner digest)", Hx(mac), Hx(Sha256(opad, inner)));
                    Check.Equal(where + ": mac", Hx(mac), (MiniJson.Str(r.Json, "mac") ?? "").ToLowerInvariant());
                }
                foreach (string bad in new string[] { "", "?case=5", "?case=8", "?case=a" })
                {
                    Reply r = HostHttp.Get(h, Path + bad);
                    Check.True(r.Status == 400 && r.Code == "WALK_BAD_ARGUMENT", Path + bad + " should get 400 WALK_BAD_ARGUMENT, and got " + r);
                }
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF RFC 4231 cases 1, 2, 3, 4, 6 and 7 answer: the padded key, both pads, the inner digest and the MAC follow RFC 2104 on .NET SHA-256, and each MAC equals RFC 4231's and .NET's HMACSHA256; case 5 and 3 other bad cases get 400";
            }
        }
    }
}
