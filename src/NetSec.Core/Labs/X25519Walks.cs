using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>
    /// One ladder step, after the step: the pair (x2:z2, x3:z3), where x2/z2 is the running multiple and x3/z3 is that multiple plus u.
    /// Values are 32 little-endian bytes, the byte order RFC 7748 prints.
    /// </summary>
    public sealed class X25519LadderRow
    {
        /// <summary>The scalar bit this step read, 254 down to 0.</summary>
        public int Bit;

        /// <summary>The bit's value. On a 1 the step swaps the pair before and after its work, so the doubling falls on x3:z3.</summary>
        public bool IsOne;
        public byte[] X2, Z2, X3, Z3;

        /// <summary>The affine u-coordinates x2/z2 and x3/z3. Null when z is 0, which is the point at infinity.</summary>
        public byte[] U2, U3;

        /// <summary>
        /// The conditional-swap argument of this step. This engine uses TweetNaCl's order: it swaps the pair by the bit before the step's work
        /// and swaps it back after, so Swap equals IsOne. RFC 7748 section 5 writes the same ladder with swap = k_t XOR k_(t+1) and one swap per step. acceptance/CONTRACT.md, the `swap` row, pins this field as k_t.
        /// </summary>
        public bool Swap;
    }

    public sealed class X25519Walk
    {
        /// <summary>Which RFC 7748 section 6.1 step: alice-public, bob-public, or shared.</summary>
        public string Step;

        /// <summary>The scalar as given, and after RFC 7748's clamp: the low 3 bits cleared, bit 255 cleared, bit 254 set.</summary>
        public byte[] Scalar, Clamped;

        /// <summary>The input u-coordinate, and the output.</summary>
        public byte[] Point, Result;
        public X25519LadderRow[] Rows;
    }

    /// <summary>
    /// The X25519 Montgomery ladder (RFC 7748 section 5), step by step, on the public test scalars of RFC 7748 section 6.1 (docs/sections-plan.md,
    /// section 4, slice P8). Pure. Each row comes from the engine's own ladder, read through its step observer. The result is then compared with
    /// X25519.Mult, so a walk that differs from the real path throws X25519_WALK_DIVERGED and shows nothing.
    /// </summary>
    public static class X25519Walks
    {
        // RFC 7748 section 6.1: Alice's and Bob's private keys. Public test values.
        static readonly string AlicePrivateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        static readonly string BobPrivateHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

        public static readonly string[] Steps = new string[] { "alice-public", "bob-public", "shared" };

        public static X25519Walk Rfc7748(string step)
        {
            byte[] a = Hex.Decode(AlicePrivateHex), b = Hex.Decode(BobPrivateHex), nine = new byte[32];
            nine[0] = 9;
            if (step == "alice-public") return Walk(step, a, nine);
            if (step == "bob-public") return Walk(step, b, nine);
            if (step == "shared") return Walk(step, a, X25519.MultBase(b));
            throw new ArgumentException("step must be alice-public, bob-public or shared", "step");
        }

        static X25519Walk Walk(string step, byte[] scalar, byte[] point)
        {
            byte[] k = X25519.Clamp(scalar);
            long[] u = Fe25519.New();
            Fe25519.Unpack(u, point, 0);
            List<X25519LadderRow> rows = new List<X25519LadderRow>();
            long[] x2, z2;
            X25519.Ladder(k, u, out x2, out z2, delegate(int bit, int value, long[] sx2, long[] sz2, long[] sx3, long[] sz3)
            {
                X25519LadderRow row = new X25519LadderRow();
                row.Bit = bit;
                row.IsOne = value == 1;
                row.Swap = value == 1;
                row.X2 = Pack(sx2);
                row.Z2 = Pack(sz2);
                row.X3 = Pack(sx3);
                row.Z3 = Pack(sz3);
                row.U2 = Affine(sx2, sz2);
                row.U3 = Affine(sx3, sz3);
                rows.Add(row);
            });

            X25519Walk walk = new X25519Walk();
            walk.Step = step;
            walk.Scalar = (byte[])scalar.Clone();
            walk.Clamped = k;
            walk.Point = (byte[])point.Clone();
            walk.Result = Affine(x2, z2);
            walk.Rows = rows.ToArray();
            RequireSame(X25519.Mult(scalar, point), walk.Result);
            return walk;
        }

        static byte[] Pack(long[] fe)
        {
            byte[] o = new byte[32];
            Fe25519.Pack(o, 0, fe);
            return o;
        }

        /// <summary>x/z as 32 bytes, or null when z is 0. The inverse is the engine's own Fe25519.Invert.</summary>
        static byte[] Affine(long[] x, long[] z)
        {
            byte[] packedZ = Pack(z);
            bool zero = true;
            for (int i = 0; i < packedZ.Length && zero; i++) zero = packedZ[i] == 0;
            if (zero) return null;
            long[] inverse = Fe25519.New(), product = Fe25519.New();
            Fe25519.Invert(inverse, z);
            Fe25519.Mul(product, x, inverse);
            return Pack(product);
        }

        internal static void RequireSame(byte[] real, byte[] walked)
        {
            bool same = real != null && walked != null && real.Length == walked.Length;
            for (int i = 0; same && i < real.Length; i++) same = real[i] == walked[i];
            if (!same) throw new NetSecException(NetSecError.Of(ErrorCodes.X25519WalkDiverged, "The walk differs from the real X25519 path."));
        }
    }
}
