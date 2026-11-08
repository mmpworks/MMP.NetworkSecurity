using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Acceptance
{
    /// <summary>
    /// The Diffie-Hellman walk (docs/sections-plan.md section 4, slice P7): GET /api/walk/dh?group=small|group14. It runs on public practice
    /// exponents, never a session's key, so it stays open with Show keys OFF. The suite recomputes every number with System.Numerics.BigInteger,
    /// which shares no code with the engine, and takes group 14's prime and generator from vectors/dh-group14-rfc3526.nsv.
    /// </summary>
    public static class DhWalkClauses
    {
        public const string Path = "/api/walk/dh";

        public static BigInteger FromHex(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return BigInteger.Zero;
            return BigInteger.Parse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        static BigInteger Num(Dictionary<string, object> parent, string field, string where)
        {
            Dictionary<string, object> n = MiniJson.Obj(parent, field);
            Check.True(n != null && !string.IsNullOrEmpty(MiniJson.Str(n, "hex")), where + ": no " + field + ".hex");
            BigInteger v = FromHex(MiniJson.Str(n, "hex"));
            Check.Equal(where + ": " + field + ".dec agrees with its hex", v.ToString(CultureInfo.InvariantCulture), MiniJson.Str(n, "dec"));
            return v;
        }

        static bool BitOf(BigInteger v, int bit) { return !(v >> bit).IsEven; }

        static int BitLength(BigInteger v) { int n = 0; while (v > 0) { v >>= 1; n++; } return n; }

        /// <summary>One modular power: base, exponent and result, and each row of left-to-right square and multiply, from the top set bit down to 0.</summary>
        static BigInteger Pow(Dictionary<string, object> pow, BigInteger p, BigInteger wantBase, BigInteger wantExponent, string where, ref int rows)
        {
            Check.True(pow != null, where + ": missing");
            Check.True(Num(pow, "base", where) == wantBase % p, where + ": the base is not the expected value");
            Check.True(Num(pow, "exponent", where) == wantExponent, where + ": the exponent is not the expected value");
            BigInteger result = Num(pow, "result", where);
            Check.True(result == BigInteger.ModPow(wantBase, wantExponent, p), where + ": the result is not base^exponent mod p");
            List<object> list = MiniJson.Arr(pow, "rows");
            int top = BitLength(wantExponent);
            Check.True(list != null && list.Count == top, where + ": " + (list == null ? 0 : list.Count) + " rows, and the exponent has " + top + " bits");
            BigInteger acc = BigInteger.One, b = wantBase % p;
            for (int i = 0; i < list.Count; i++)
            {
                Dictionary<string, object> r = MiniJson.AsObject(list[i]);
                int bit = (int)MiniJson.Num(r, "bit", -1);
                Check.True(bit == top - 1 - i, where + ": row " + i + " reads bit " + bit + ", and the rows go from bit " + (top - 1) + " down to 0");
                bool one = BitOf(wantExponent, bit);
                Check.True(MiniJson.Bool(r, "isOne", false) == one, where + ": row " + i + " (bit " + bit + ") says isOne " + MiniJson.Bool(r, "isOne", false));
                acc = acc * acc % p;
                Check.True(Num(r, "afterSquare", where + " row " + i) == acc, where + ": row " + i + " afterSquare is not the previous value squared mod p");
                if (one)
                {
                    acc = acc * b % p;
                    Check.True(Num(r, "afterMultiply", where + " row " + i) == acc, where + ": row " + i + " afterMultiply is not afterSquare times the base mod p");
                }
                else Check.True(MiniJson.Obj(r, "afterMultiply") == null, where + ": row " + i + " multiplies on a 0 bit");
                rows++;
            }
            Check.True(acc == result, where + ": the last row does not end on the result");
            return result;
        }

        [Clause("A19.host.dh-walk-open-and-modpow")]
        public static string DhOpenAndModPow(Ctx c)
        {
            VectorRecord rfc = c.Vectors("dh-group14-rfc3526.nsv", "dh-group14-params")[0];
            BigInteger p14 = FromHex(rfc.Str("p")), g14 = FromHex(rfc.Str("g"));
            int rows = 0;
            using (HostProc h = A17.Host(c, "walk-dh"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                foreach (string group in new string[] { "small", "group14" })
                {
                    Reply r = HostHttp.Get(h, Path + "?group=" + group);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P7)");
                    Check.True(r.Ok && r.Json != null, "OFF: GET " + Path + "?group=" + group + " got " + r + ". The walk runs on public practice exponents, so it stays open");
                    Check.Equal(group + ": keySource", "practice", MiniJson.Str(r.Json, "keySource"));
                    BigInteger p = Num(r.Json, "prime", group), g = Num(r.Json, "generator", group);
                    if (group == "group14") { Check.True(p == p14, "group14: the prime is not RFC 3526 group 14's"); Check.True(g == g14, "group14: the generator is not RFC 3526 group 14's"); }
                    else Check.True(p > 2 && g > 1 && g < p, "small: the prime and generator do not make a group");
                    Dictionary<string, object> cs = MiniJson.Obj(r.Json, "client"), ss = MiniJson.Obj(r.Json, "server");
                    Check.True(cs != null && ss != null, group + ": the walk needs a client and a server side");
                    BigInteger x = Num(cs, "private", group + " client"), y = Num(ss, "private", group + " server");
                    BigInteger cp = Pow(MiniJson.Obj(cs, "public"), p, g, x, group + " client public", ref rows);
                    BigInteger sp = Pow(MiniJson.Obj(ss, "public"), p, g, y, group + " server public", ref rows);
                    BigInteger ck = Pow(MiniJson.Obj(cs, "shared"), p, sp, x, group + " client shared", ref rows);
                    BigInteger sk = Pow(MiniJson.Obj(ss, "shared"), p, cp, y, group + " server shared", ref rows);
                    Check.True(ck == sk, group + ": the 2 sides reach different shared values");
                }
                Reply bad = HostHttp.Get(h, Path + "?group=nope");
                Check.True(bad.Status == 400 && bad.Code == "WALK_BAD_ARGUMENT", "an unknown group should get 400 WALK_BAD_ARGUMENT, and got " + bad);
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
            }
            return "with Show keys OFF both DH walks answer: group 14 uses RFC 3526's prime and generator, each public and shared value equals BigInteger.ModPow, both sides agree, and " + rows + " square-and-multiply rows each check against the row before";
        }
    }
}
