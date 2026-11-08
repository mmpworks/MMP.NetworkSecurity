using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// The ECDSA walk (docs/sections-plan.md section 4, slice P8b): GET /api/walk/ecdsa?message=sample|test, on RFC 6979 appendix A.2.5's
    /// P-256 test key only, so it stays open with Show keys OFF. The anchors are not the engine: the key, k, r and s come from the suite's
    /// vector file (vectors/ecdsa-rfc6979.nsv); the curve comes from .NET's own P-256 parameters; the suite runs its own affine P-256
    /// arithmetic on BigInteger to check the public key, every double-and-add row of k*G, R and the verify point; and both .NET's ECDsa and
    /// OpenSSL (dgst -sha256 -verify) accept the signature.
    /// </summary>
    public static class EcdsaWalkClauses
    {
        public const string Path = "/api/walk/ecdsa";

        // ---------------------------------------------------------------- P-256, from .NET's own parameters; null is the point at infinity

        public sealed class Pt { public BigInteger X, Y; public Pt(BigInteger x, BigInteger y) { X = x; Y = y; } }

        public sealed class Curve { public BigInteger P, A, B, N; public Pt G; }

        static BigInteger Be(byte[] b) { return new BigInteger(b, isUnsigned: true, isBigEndian: true); }

        public static Curve P256()
        {
            using (ECDsa e = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                ECParameters p = e.ExportExplicitParameters(false);
                return new Curve { P = Be(p.Curve.Prime), A = Be(p.Curve.A), B = Be(p.Curve.B), N = Be(p.Curve.Order), G = new Pt(Be(p.Curve.G.X), Be(p.Curve.G.Y)) };
            }
        }

        static BigInteger Mod(BigInteger v, BigInteger m) { BigInteger r = v % m; return r.Sign < 0 ? r + m : r; }

        public static BigInteger Inv(BigInteger v, BigInteger m) { return BigInteger.ModPow(Mod(v, m), m - 2, m); }

        public static Pt Add(Curve c, Pt p, Pt q)
        {
            if (p == null) return q;
            if (q == null) return p;
            if (p.X == q.X && Mod(p.Y + q.Y, c.P).IsZero) return null;
            BigInteger l = p.X == q.X && p.Y == q.Y ? Mod((3 * p.X * p.X + c.A) * Inv(2 * p.Y, c.P), c.P) : Mod((q.Y - p.Y) * Inv(q.X - p.X, c.P), c.P);
            BigInteger x = Mod(l * l - p.X - q.X, c.P);
            return new Pt(x, Mod(l * (p.X - x) - p.Y, c.P));
        }

        public static Pt Mul(Curve c, BigInteger k, Pt g)
        {
            Pt r = null;
            for (int bit = (int)k.GetBitLength() - 1; bit >= 0; bit--) { r = Add(c, r, r); if (!((k >> bit) & 1).IsZero) r = Add(c, r, g); }
            return r;
        }

        public static string H32(BigInteger v) { byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true); byte[] o = new byte[32]; Array.Copy(b, 0, o, 32 - b.Length, b.Length); return Hex.Encode(o).ToLowerInvariant(); }

        static BigInteger Num(Dictionary<string, object> d, string name, string where)
        {
            string s = MiniJson.Str(d, name);
            Check.True(!string.IsNullOrEmpty(s), where + ": no " + name);
            return Be(Hex.Decode(s));
        }

        static Pt ReadPt(object o, string where)
        {
            Dictionary<string, object> d = MiniJson.AsObject(o);
            if (d == null) return null;
            return new Pt(Num(d, "x", where), Num(d, "y", where));
        }

        static void SamePt(string where, Pt want, Pt got)
        {
            bool same = want == null ? got == null : got != null && want.X == got.X && want.Y == got.Y;
            Check.True(same, where + ": the walk shows " + (got == null ? "infinity" : "(" + H32(got.X) + ", " + H32(got.Y) + ")") + ", and P-256 gives " + (want == null ? "infinity" : "(" + H32(want.X) + ", " + H32(want.Y) + ")"));
        }

        static byte[] DerInt(BigInteger v)
        {
            byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            if ((b[0] & 0x80) != 0) { byte[] z = new byte[b.Length + 1]; Array.Copy(b, 0, z, 1, b.Length); b = z; }
            byte[] o = new byte[b.Length + 2]; o[0] = 0x02; o[1] = (byte)b.Length; Array.Copy(b, 0, o, 2, b.Length);
            return o;
        }

        /// <summary>OpenSSL's own verify of (r, s) over the message, with the public key as SubjectPublicKeyInfo DER.</summary>
        static void OpenSslVerifies(Ctx c, string where, byte[] msg, BigInteger ux, BigInteger uy, BigInteger r, BigInteger s)
        {
            string dir = A17.TempDir(c, "ecdsa-walk");
            string pubFile = System.IO.Path.Combine(dir, "pub.der"), sigFile = System.IO.Path.Combine(dir, "sig.der"), msgFile = System.IO.Path.Combine(dir, "msg.bin");
            using (ECDsa e = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = Hex.Decode(H32(ux)), Y = Hex.Decode(H32(uy)) } }))
                File.WriteAllBytes(pubFile, e.ExportSubjectPublicKeyInfo());
            byte[] ri = DerInt(r), si = DerInt(s), seq = new byte[ri.Length + si.Length + 2];
            seq[0] = 0x30; seq[1] = (byte)(ri.Length + si.Length); Array.Copy(ri, 0, seq, 2, ri.Length); Array.Copy(si, 0, seq, 2 + ri.Length, si.Length);
            File.WriteAllBytes(sigFile, seq);
            File.WriteAllBytes(msgFile, msg);
            string o;
            int code = Proc.Run(Referees.OpenSsl(c), "dgst -sha256 -keyform DER -verify \"" + pubFile + "\" -signature \"" + sigFile + "\" \"" + msgFile + "\"", dir, 30000, out o);
            Check.True(code == 0 && o.Contains("Verified OK"), where + ": OpenSSL does not verify the signature. Output: " + o);
        }

        [Clause("A19.host.ecdsa-walk-open-and-rfc6979")]
        public static string WalkOpenAndRfc6979(Ctx c)
        {
            List<VectorRecord> all = c.Vectors("ecdsa-rfc6979.nsv", "ecdsa-p256-sha256");
            Curve cv = P256();
            int rows = 0;
            using (HostProc h = A17.Host(c, "walk-ecdsa"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                foreach (VectorRecord v in all)
                {
                    string m = v.Str("message"), where = "message=" + m + " (RFC 6979 A.2.5, SHA-256)";
                    Reply r = HostHttp.Get(h, Path + "?message=" + m);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P8b)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + where + " got " + r + ". The walk runs on RFC 6979's published test key, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, where + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    Check.Equal(where + ": keySource", "rfc6979", MiniJson.Str(r.Json, "keySource"));
                    BigInteger x = Be(Hex.Decode(v.Str("x"))), ux = Be(Hex.Decode(v.Str("ux"))), uy = Be(Hex.Decode(v.Str("uy")));
                    BigInteger k = Be(Hex.Decode(v.Str("k"))), rr = Be(Hex.Decode(v.Str("r"))), ss = Be(Hex.Decode(v.Str("s")));
                    Pt u = new Pt(ux, uy);
                    SamePt(where + ": RFC 6979's public key is x*G on .NET's P-256", u, Mul(cv, x, cv.G));
                    Check.Equal(where + ": privateKey", H32(x), (MiniJson.Str(r.Json, "privateKey") ?? "").ToLowerInvariant());
                    SamePt(where + ": publicKey is RFC 6979's", u, ReadPt(MiniJson.Obj(r.Json, "publicKey"), where + " publicKey"));
                    byte[] msg = Encoding.ASCII.GetBytes(m), h1;
                    using (SHA256 sha = SHA256.Create()) h1 = sha.ComputeHash(msg);
                    Check.Equal(where + ": h1 is .NET's SHA-256 of the message", Hex.Encode(h1).ToLowerInvariant(), (MiniJson.Str(r.Json, "h1") ?? "").ToLowerInvariant());
                    BigInteger e = Mod(Be(h1), cv.N);
                    Check.Equal(where + ": e is h1 as a number mod n", H32(e), (MiniJson.Str(r.Json, "e") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": k is RFC 6979's", H32(k), (MiniJson.Str(r.Json, "k") ?? "").ToLowerInvariant());
                    // Every double-and-add row of k*G, against the suite's own arithmetic.
                    List<object> kg = MiniJson.Arr(r.Json, "kG") ?? new List<object>();
                    int top = (int)k.GetBitLength();
                    Check.True(kg.Count == top, where + ": kG has " + kg.Count + " rows, and k has " + top + " bits");
                    Pt acc = null;
                    for (int i = 0; i < kg.Count; i++)
                    {
                        Dictionary<string, object> row = MiniJson.AsObject(kg[i]);
                        int bit = top - 1 - i;
                        bool one = !((k >> bit) & 1).IsZero;
                        Check.True((int)MiniJson.Num(row, "bit", -1) == bit && MiniJson.Bool(row, "isOne", !one) == one, where + " kG row " + i + ": bit " + bit + " should be " + (one ? 1 : 0));
                        acc = Add(cv, acc, acc);
                        SamePt(where + " kG row " + i + " afterDouble", acc, ReadPt(row.ContainsKey("afterDouble") ? row["afterDouble"] : null, where));
                        if (one) { acc = Add(cv, acc, cv.G); SamePt(where + " kG row " + i + " afterAdd", acc, ReadPt(row["afterAdd"], where)); }
                        else Check.True(!row.ContainsKey("afterAdd") || row["afterAdd"] == null, where + " kG row " + i + ": a 0 bit has no afterAdd");
                        rows++;
                    }
                    SamePt(where + ": bigR is k*G", acc, ReadPt(MiniJson.Obj(r.Json, "bigR"), where + " bigR"));
                    Check.True(Mod(acc.X, cv.N) == rr, where + ": RFC 6979's r is R.x mod n");
                    Check.Equal(where + ": r", H32(rr), (MiniJson.Str(r.Json, "r") ?? "").ToLowerInvariant());
                    BigInteger kInv = Inv(k, cv.N);
                    Check.Equal(where + ": kInverse", H32(kInv), (MiniJson.Str(r.Json, "kInverse") ?? "").ToLowerInvariant());
                    Check.True(Mod(kInv * (e + rr * x), cv.N) == ss, where + ": RFC 6979's s is k^-1 (e + r x) mod n");
                    Check.Equal(where + ": s", H32(ss), (MiniJson.Str(r.Json, "s") ?? "").ToLowerInvariant());
                    Dictionary<string, object> vf = MiniJson.Obj(r.Json, "verify");
                    Check.True(vf != null && MiniJson.Bool(vf, "valid", false), where + ": verify.valid should be true");
                    BigInteger w = Inv(ss, cv.N), u1 = Mod(e * w, cv.N), u2 = Mod(rr * w, cv.N);
                    Check.Equal(where + ": verify.w", H32(w), (MiniJson.Str(vf, "w") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": verify.u1", H32(u1), (MiniJson.Str(vf, "u1") ?? "").ToLowerInvariant());
                    Check.Equal(where + ": verify.u2", H32(u2), (MiniJson.Str(vf, "u2") ?? "").ToLowerInvariant());
                    SamePt(where + ": verify.x is u1 G + u2 U, which is R", acc, ReadPt(vf["x"], where + " verify"));
                    byte[] p1363 = Hex.Decode(H32(rr) + H32(ss));
                    using (ECDsa ec = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = Hex.Decode(H32(ux)), Y = Hex.Decode(H32(uy)) } }))
                        Check.True(ec.VerifyData(msg, p1363, HashAlgorithmName.SHA256), where + ": .NET's ECDsa does not verify RFC 6979's signature");
                    OpenSslVerifies(c, where, msg, ux, uy, rr, ss);
                }
                foreach (string bad in new string[] { "", "?message=nope" })
                {
                    Reply r = HostHttp.Get(h, Path + bad);
                    Check.True(r.Status == 400 && r.Code == "WALK_BAD_ARGUMENT", Path + bad + " should get 400 WALK_BAD_ARGUMENT, and got " + r);
                }
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF both RFC 6979 A.2.5 messages answer: the key, k, r and s are the RFC's, the public key and all " + rows + " kG rows, R and the verify point follow the suite's P-256 arithmetic, and .NET and OpenSSL both verify; 2 bad messages get 400";
            }
        }
    }
}
