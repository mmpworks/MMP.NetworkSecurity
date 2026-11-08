using System;
using System.Collections.Generic;

namespace NetSec.Crypto
{
    /// <summary>One HMAC round of RFC 6979 section 3.2: which step it is, and K and V after it. A candidate round also names its k and whether it was kept.</summary>
    internal sealed class Rfc6979Round
    {
        public string Step;
        public byte[] K, V;
        public byte[] Candidate;
        public bool Kept;
    }

    /// <summary>The steps of one ECDSA P-256 signature and its verification, for the walk. Each field is filled by the engine as it runs.</summary>
    internal sealed class EcdsaTrace
    {
        /// <summary>Sign: SHA-256 of the message, e = its integer mod n, the RFC 6979 rounds, and k.</summary>
        public byte[] Hash;
        public BigUInt E, K;
        public List<Rfc6979Round> Rounds = new List<Rfc6979Round>();

        /// <summary>Sign: each bit of k*G (the bit, the point after the doubling, the point after the addition or null).</summary>
        public P256Step KG;

        /// <summary>Sign: R = k*G as affine x and y, r = Rx mod n, k^-1 mod n, and s = k^-1 (e + r*x) mod n.</summary>
        public BigUInt Rx, Ry, R, KInverse, S;

        /// <summary>Verify: w = s^-1 mod n, u1 = e*w, u2 = r*w, X = u1*G + u2*Q as affine x and y.</summary>
        public BigUInt W, U1, U2, Xx, Xy;
        public bool Valid;
    }

    /// <summary>
    /// ECDSA on P-256 with SHA-256 (FIPS 186-5), with k from RFC 6979 section 3.2 (HMAC-SHA-256), so a signature repeats for the same key and message.
    /// Built to show the parts, for the walk on RFC 6979 section A.2.5's public test key. Do not copy: it is not constant time.
    /// </summary>
    public static class EcdsaP256
    {
        static readonly BigUInt Two = BigUInt.FromUInt32(2);

        static BigUInt InvN(BigUInt a) { return a.ModPow(P256.N.Subtract(Two), P256.N); }

        static byte[] Sha256(byte[] m) { IHash h = Hashes.Sha256(); h.Update(m, 0, m.Length); return h.Finish(); }

        static byte[] Hmac(byte[] key, params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] part in parts) total += part.Length;
            byte[] data = new byte[total];
            int at = 0;
            foreach (byte[] part in parts) { Buffer.BlockCopy(part, 0, data, at, part.Length); at += part.Length; }
            return NetSec.Crypto.Hmac.Compute(Hashes.Sha256, key, data);
        }

        public static BigUInt PublicKey(BigUInt x, out BigUInt qy)
        {
            BigUInt qx;
            P256.ToAffine(P256.Multiply(x, P256.G), out qx, out qy);
            return qx;
        }

        /// <summary>RFC 6979 section 3.2 with qlen = hlen = 256, so bits2int is the plain integer of 32 bytes and bits2octets(h1) is (h1 mod n) in 32 bytes.</summary>
        internal static BigUInt DeterministicK(BigUInt x, byte[] hash, EcdsaTrace trace)
        {
            byte[] xo = x.ToBigEndian(32), ho = BigUInt.FromBytes(hash).Mod(P256.N).ToBigEndian(32);
            byte[] v = new byte[32], k = new byte[32];
            for (int i = 0; i < 32; i++) v[i] = 1;
            k = Hmac(k, v, new byte[] { 0 }, xo, ho); Note(trace, "d: K = HMAC_K(V || 0x00 || x || h1)", k, v);
            v = Hmac(k, v); Note(trace, "e: V = HMAC_K(V)", k, v);
            k = Hmac(k, v, new byte[] { 1 }, xo, ho); Note(trace, "f: K = HMAC_K(V || 0x01 || x || h1)", k, v);
            v = Hmac(k, v); Note(trace, "g: V = HMAC_K(V)", k, v);
            while (true)
            {
                v = Hmac(k, v);
                BigUInt candidate = BigUInt.FromBytes(v);
                bool kept = !candidate.IsZero && candidate.CompareTo(P256.N) < 0;
                if (trace != null)
                {
                    Rfc6979Round round = Note(trace, "h: T = V = HMAC_K(V), k = bits2int(T)", k, v);
                    round.Candidate = (byte[])v.Clone();
                    round.Kept = kept;
                }
                if (kept) return candidate;
                k = Hmac(k, v, new byte[] { 0 }); Note(trace, "h: K = HMAC_K(V || 0x00)", k, v);
                v = Hmac(k, v); Note(trace, "h: V = HMAC_K(V)", k, v);
            }
        }

        static Rfc6979Round Note(EcdsaTrace trace, string step, byte[] k, byte[] v)
        {
            if (trace == null) return null;
            Rfc6979Round round = new Rfc6979Round();
            round.Step = step;
            round.K = (byte[])k.Clone();
            round.V = (byte[])v.Clone();
            trace.Rounds.Add(round);
            return round;
        }

        public static void Sign(BigUInt x, byte[] message, out BigUInt r, out BigUInt s) { Sign(x, message, out r, out s, null); }

        internal static void Sign(BigUInt x, byte[] message, out BigUInt r, out BigUInt s, EcdsaTrace trace)
        {
            if (x.IsZero || x.CompareTo(P256.N) >= 0) throw new ArgumentException("a P-256 private key is from 1 to n - 1", "x");
            byte[] hash = Sha256(message);
            BigUInt e = BigUInt.FromBytes(hash).Mod(P256.N);
            BigUInt k = DeterministicK(x, hash, trace);
            BigUInt rx, ry;
            P256.ToAffine(P256.Multiply(k, P256.G, trace == null ? null : trace.KG), out rx, out ry);
            r = rx.Mod(P256.N);
            BigUInt kInverse = InvN(k);
            s = kInverse.Multiply(e.Add(r.Multiply(x))).Mod(P256.N);
            if (trace != null)
            {
                trace.Hash = hash; trace.E = e; trace.K = k;
                trace.Rx = rx; trace.Ry = ry; trace.R = r; trace.KInverse = kInverse; trace.S = s;
            }
        }

        public static bool Verify(BigUInt qx, BigUInt qy, byte[] message, BigUInt r, BigUInt s) { return Verify(qx, qy, message, r, s, null); }

        /// <summary>FIPS 186-5 section 6.4.2. The public key must lie on the curve, and r and s must be from 1 to n - 1.</summary>
        internal static bool Verify(BigUInt qx, BigUInt qy, byte[] message, BigUInt r, BigUInt s, EcdsaTrace trace)
        {
            if (!P256.IsOnCurve(qx, qy)) return false;
            if (r.IsZero || s.IsZero || r.CompareTo(P256.N) >= 0 || s.CompareTo(P256.N) >= 0) return false;
            BigUInt e = BigUInt.FromBytes(Sha256(message)).Mod(P256.N), w = InvN(s);
            BigUInt u1 = e.Multiply(w).Mod(P256.N), u2 = r.Multiply(w).Mod(P256.N);
            P256Point sum = P256.AddPoints(P256.Multiply(u1, P256.G), P256.Multiply(u2, new P256Point(qx, qy, BigUInt.One)));
            bool valid = false;
            BigUInt xx = null, xy = null;
            if (!sum.IsInfinity)
            {
                P256.ToAffine(sum, out xx, out xy);
                valid = xx.Mod(P256.N).CompareTo(r) == 0;
            }
            if (trace != null) { trace.W = w; trace.U1 = u1; trace.U2 = u2; trace.Xx = xx; trace.Xy = xy; trace.Valid = valid; }
            return valid;
        }
    }
}
