using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// The X25519 ladder walk (docs/sections-plan.md section 4, slice P8): GET /api/walk/x25519?step=alice-public|bob-public|shared. It runs on the
    /// public test scalars of RFC 7748 section 6.1, never a session's key, so it stays open with Show keys OFF. The anchor is the suite's own
    /// vectors/x25519-rfc7748.nsv [x25519-dh], not the engine: each result must equal RFC 7748's, the clamp must follow section 5, and each ladder
    /// row must read its bit of the clamped scalar, from bit 254 down to bit 0.
    /// </summary>
    public static class X25519WalkClauses
    {
        public const string Path = "/api/walk/x25519";

        /// <summary>RFC 7748 section 5: clear the low 3 bits, clear bit 255, set bit 254. Little-endian.</summary>
        public static byte[] Clamp(byte[] scalar)
        {
            byte[] k = (byte[])scalar.Clone();
            k[0] &= 248; k[31] &= 127; k[31] |= 64;
            return k;
        }

        public static bool Bit(byte[] littleEndian, int bit) { return ((littleEndian[bit >> 3] >> (bit & 7)) & 1) == 1; }

        /// <summary>
        /// Each ladder row carries `swap` (the lead's answer on #278). This engine follows TweetNaCl's order: it swaps the pair by the row's bit
        /// before the step and swaps it back after, so `swap` is the conditional-swap argument and equals the bit of the clamped scalar (Richard's
        /// shape). The bit comes from RFC 7748's scalar in the suite's vector file, clamped by section 5, not from the engine's isOne.
        /// </summary>
        [Clause("A19.host.x25519-rows-carry-swap")]
        public static string RowsCarrySwap(Ctx c)
        {
            VectorRecord v = c.Vectors("x25519-rfc7748.nsv", "x25519-dh")[0];
            using (HostProc h = A17.Host(c, "walk-x25519-swap"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                int checkedRows = 0;
                foreach (string step in new string[] { "alice-public", "bob-public" })
                {
                    Reply r = HostHttp.Get(h, Path + "?step=" + step);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P8)");
                    Check.True(r.Ok && r.Json != null, "OFF: GET " + Path + "?step=" + step + " got " + r);
                    List<object> rows = MiniJson.Arr(r.Json, "rows") ?? new List<object>();
                    if (rows.TrueForAll(o => !MiniJson.AsObject(o).ContainsKey("swap"))) throw new NotRunException("PRODUCT_MISSING", "the X25519 rows carry no swap field yet (#278)");
                    byte[] clamped = Clamp(Hex.Decode(step == "alice-public" ? v.Str("a") : v.Str("b")));
                    foreach (object o in rows)
                    {
                        Dictionary<string, object> row = MiniJson.AsObject(o);
                        int bit = (int)MiniJson.Num(row, "bit", -1);
                        Check.True(row.ContainsKey("swap") && row["swap"] is bool, step + ": row for bit " + bit + " has no bool swap");
                        Check.True((bool)row["swap"] == Bit(clamped, bit), step + ": bit " + bit + " has swap " + row["swap"] + ", and the clamped scalar's bit is " + Bit(clamped, bit));
                        checkedRows++;
                    }
                }
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF " + checkedRows + " ladder rows each carry swap equal to the clamped RFC 7748 scalar's bit (this engine's conditional-swap argument)";
            }
        }

        [Clause("A19.host.x25519-walk-open-and-rfc7748")]
        public static string LadderOpenAndRfc7748(Ctx c)
        {
            VectorRecord v = c.Vectors("x25519-rfc7748.nsv", "x25519-dh")[0];
            string a = v.Str("a").ToLowerInvariant(), b = v.Str("b").ToLowerInvariant(), aPub = v.Str("a_pub").ToLowerInvariant(), bPub = v.Str("b_pub").ToLowerInvariant(), k = v.Str("k").ToLowerInvariant();
            string nine = "09" + new string('0', 62);
            using (HostProc h = A17.Host(c, "walk-x25519"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                int rowsChecked = 0;
                foreach (string step in new string[] { "alice-public", "bob-public", "shared" })
                {
                    Reply r = HostHttp.Get(h, Path + "?step=" + step);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P8)");
                    Check.True(r.Ok && r.Json != null, "OFF: GET " + Path + "?step=" + step + " got " + r + ". The walk runs on RFC 7748's public scalars, so it stays open");
                    Check.Equal(step + ": keySource", "rfc7748", MiniJson.Str(r.Json, "keySource"));
                    string scalar = (MiniJson.Str(r.Json, "scalar") ?? "").ToLowerInvariant(), point = (MiniJson.Str(r.Json, "point") ?? "").ToLowerInvariant(), result = (MiniJson.Str(r.Json, "result") ?? "").ToLowerInvariant();
                    if (step == "alice-public") { Check.Equal("alice-public: scalar", a, scalar); Check.Equal("alice-public: point", nine, point); Check.Equal("alice-public: result is RFC 7748's Alice public key", aPub, result); }
                    else if (step == "bob-public") { Check.Equal("bob-public: scalar", b, scalar); Check.Equal("bob-public: point", nine, point); Check.Equal("bob-public: result is RFC 7748's Bob public key", bPub, result); }
                    else
                    {
                        Check.True((scalar == a && point == bPub) || (scalar == b && point == aPub), "shared: the walk should multiply one private scalar by the other side's public key, and shows scalar " + scalar + " and point " + point);
                        Check.Equal("shared: result is RFC 7748's shared secret K", k, result);
                    }
                    byte[] clamped = Clamp(Hex.Decode(scalar));
                    Check.Equal(step + ": the clamped scalar (RFC 7748 section 5)", Hex.Encode(clamped).ToLowerInvariant(), (MiniJson.Str(r.Json, "clamped") ?? "").ToLowerInvariant());
                    List<object> rows = MiniJson.Arr(r.Json, "rows");
                    Check.True(rows != null && rows.Count == 255, step + ": the ladder has " + (rows == null ? 0 : rows.Count) + " rows, and RFC 7748's ladder reads bits 254 down to 0, so 255");
                    for (int i = 0; i < rows.Count; i++)
                    {
                        Dictionary<string, object> row = MiniJson.AsObject(rows[i]);
                        int bit = (int)MiniJson.Num(row, "bit", -1);
                        Check.True(bit == 254 - i, step + ": row " + i + " reads bit " + bit + ", and the ladder goes from 254 down to 0");
                        Check.True(MiniJson.Bool(row, "isOne", false) == Bit(clamped, bit), step + ": row " + i + " (bit " + bit + ") says isOne " + MiniJson.Bool(row, "isOne", false) + ", and the clamped scalar's bit is " + Bit(clamped, bit));
                        rowsChecked++;
                    }
                }
                Reply bad = HostHttp.Get(h, Path + "?step=nope");
                Check.True(bad.Status == 400 && bad.Code == "WALK_BAD_ARGUMENT", "an unknown step should get 400 WALK_BAD_ARGUMENT, and got " + bad);
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF the 3 ladder walks answer: the results equal RFC 7748 section 6.1's 2 public keys and shared K, the clamp follows section 5, and " + rowsChecked + " ladder rows each read their bit of the clamped scalar, from 254 down";
            }
        }
    }
}
