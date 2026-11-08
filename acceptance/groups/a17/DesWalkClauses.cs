using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Acceptance
{
    /// <summary>
    /// The Feistel walk on DES (docs/sections-plan.md section 4, slice P9): GET /api/walk/des?name=varkey|vartext|subtab, on the first known
    /// answer of NIST CAVP's TECBvarkey, TECBvartext and TECBsubtab (one DES key used three times). The walk runs on published test keys
    /// only, so it stays open with Show keys OFF. The anchors are the suite's vector file and .NET's DES: the ciphertext and the walk's output
    /// equal CAVP's, and for varkey and subtab .NET's DES gives the same ciphertext. The vartext key is DES's weak key 0101010101010101, which
    /// .NET's DES refuses, so vartext rests on CAVP alone, as the clause's result line says. Each round must hold the Feistel rule
    /// (leftOut = rightIn, rightOut = leftIn xor f, and the next round starts from this one's outputs), and each S-box row is bits 1 and 6
    /// of its 6 bits, and its column bits 2 to 5 (FIPS 46-3).
    /// </summary>
    public static class DesWalkClauses
    {
        public const string Path = "/api/walk/des";
        public static readonly string[] Names = { "varkey", "vartext", "subtab" };

        public static VectorRecord Kat(List<VectorRecord> all, string name)
        {
            string file = "TECB" + name;
            VectorRecord v = all.Find(x => x.Str("file") == file);
            Check.True(v != null, "vectors/tdes-cavp.nsv has no " + file + " record");
            return v;
        }

        static ulong U64(string hex) { return Convert.ToUInt64(hex, 16); }

        static string S(Dictionary<string, object> d, string name) { return (MiniJson.Str(d, name) ?? "").ToLowerInvariant(); }

        /// <summary>.NET's DES, ECB, one block. Null when .NET refuses the key (a weak or semi-weak DES key).</summary>
        public static byte[] BclDes(byte[] key8, byte[] block)
        {
            try
            {
                using (DES des = DES.Create())
                {
                    des.Key = key8;
                    return des.EncryptEcb(block, PaddingMode.None);
                }
            }
            catch (CryptographicException) { return null; }
        }

        [Clause("A19.host.des-walk-open-and-cavp")]
        public static string WalkOpenAndCavp(Ctx c)
        {
            List<VectorRecord> all = c.Vectors("tdes-cavp.nsv", "tdes-ecb-encrypt-kat");
            List<string> cavpOnly = new List<string>();
            using (HostProc h = A17.Host(c, "walk-des"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                foreach (string name in Names)
                {
                    VectorRecord v = Kat(all, name);
                    string where = "name=" + name + " (CAVP TECB" + name + " row 1)";
                    Reply r = HostHttp.Get(h, Path + "?name=" + name);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P9)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + where + " got " + r + ". The walk runs on CAVP's published keys, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, where + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    Check.Equal(where + ": keySource", "cavp", MiniJson.Str(r.Json, "keySource"));
                    string key24 = v.Str("key").ToLowerInvariant(), key8 = key24.Substring(0, 16);
                    Check.True(key24 == key8 + key8 + key8, where + ": the CAVP record is not one DES key used three times");
                    string shownKey = S(r.Json, "key");
                    Check.True(shownKey == key8 || shownKey == key24, where + ": key is " + shownKey + ", and CAVP's DES key is " + key8);
                    Check.Equal(where + ": plaintext", v.Str("plaintext").ToLowerInvariant(), S(r.Json, "plaintext"));
                    string ct = v.Str("ciphertext").ToLowerInvariant();
                    Check.Equal(where + ": ciphertext is CAVP's", ct, S(r.Json, "ciphertext"));
                    Check.Equal(where + ": output is the ciphertext", ct, S(r.Json, "output"));
                    byte[] bcl = BclDes(Hex.Decode(key8), Hex.Decode(v.Str("plaintext")));
                    if (bcl == null) cavpOnly.Add(name);
                    else Check.Equal(where + ": .NET's DES gives CAVP's ciphertext", ct, Hex.Encode(bcl).ToLowerInvariant());

                    List<object> rounds = MiniJson.Arr(r.Json, "rounds") ?? new List<object>();
                    Check.True(rounds.Count == 16, where + ": " + rounds.Count + " rounds, and DES has 16");
                    Dictionary<string, object> schedule = MiniJson.Obj(r.Json, "schedule");
                    Check.True(schedule != null && (MiniJson.Arr(schedule, "rounds") ?? new List<object>()).Count == 16, where + ": the key schedule should have 16 round keys");
                    ulong prevL = 0, prevR = 0;
                    for (int i = 0; i < 16; i++)
                    {
                        Dictionary<string, object> rd = MiniJson.AsObject(rounds[i]);
                        string rw = where + " round " + (i + 1);
                        ulong lIn = U64(S(rd, "leftIn")), rIn = U64(S(rd, "rightIn")), f = U64(S(rd, "f")), lOut = U64(S(rd, "leftOut")), rOut = U64(S(rd, "rightOut"));
                        if (i > 0) Check.True(lIn == prevL && rIn == prevR, rw + ": it should start from round " + i + "'s outputs");
                        Check.True(lOut == rIn, rw + ": leftOut should equal rightIn (the Feistel rule)");
                        Check.True(rOut == (lIn ^ f), rw + ": rightOut should equal leftIn xor f (the Feistel rule)");
                        List<object> boxes = MiniJson.Arr(rd, "boxes") ?? new List<object>();
                        Check.True(boxes.Count == 8, rw + ": " + boxes.Count + " S-boxes, and DES has 8");
                        foreach (object o in boxes)
                        {
                            Dictionary<string, object> b = MiniJson.AsObject(o);
                            string six = MiniJson.Str(b, "six") ?? "";
                            Check.True(six.Length == 6, rw + ": an S-box input is not 6 bits");
                            int row = Convert.ToInt32("" + six[0] + six[5], 2), col = Convert.ToInt32(six.Substring(1, 4), 2);
                            Check.True((int)MiniJson.Num(b, "row", -1) == row && (int)MiniJson.Num(b, "column", -1) == col, rw + " box " + MiniJson.Num(b, "box", -1) + ": row is bits 1 and 6 of " + six + " (" + row + ") and column bits 2 to 5 (" + col + ")");
                        }
                        prevL = lOut; prevR = rOut;
                    }
                }
                foreach (string bad in new string[] { "", "?name=nope" })
                {
                    Reply r = HostHttp.Get(h, Path + bad);
                    Check.True(r.Status == 400 && r.Code == "WALK_BAD_ARGUMENT", Path + bad + " should get 400 WALK_BAD_ARGUMENT, and got " + r);
                }
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                string only = cavpOnly.Count == 0 ? "" : " " + string.Join(", ", cavpOnly.ToArray()) + " rests on CAVP alone, because .NET's DES refuses its weak key;";
                return "with Show keys OFF the 3 CAVP known answers answer: the ciphertext and the output equal CAVP's, and .NET's DES agrees where it accepts the key;" + only + " all 48 rounds hold the Feistel rule and every S-box row and column follow its 6 bits; 2 bad names get 400";
            }
        }
    }
}
