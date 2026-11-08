using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Ssh;

namespace NetSec.Labs
{
    /// <summary>One bit of a modular power, read from the top bit down: square, then multiply when the bit is 1.</summary>
    public sealed class DhPowRow
    {
        /// <summary>The bit's position, counting from 0 at the low end.</summary>
        public int Bit;
        public bool IsOne;
        public byte[] AfterSquare;

        /// <summary>Null when the bit is 0, because no multiply runs.</summary>
        public byte[] AfterMultiply;
    }

    /// <summary>base^exponent mod modulus, row by row.</summary>
    public sealed class DhPowWalk
    {
        public byte[] Base, Exponent, Result;
        public DhPowRow[] Rows;
    }

    /// <summary>What one side holds and makes.</summary>
    public sealed class DhSideWalk
    {
        public byte[] Private;

        /// <summary>g^private mod p: the value this side sends.</summary>
        public DhPowWalk Public;

        /// <summary>peer's public^private mod p: the shared secret this side makes.</summary>
        public DhPowWalk Shared;
    }

    public sealed class DhWalk
    {
        /// <summary>"small" or "group14".</summary>
        public string Group;
        public byte[] Prime, Generator;
        public DhSideWalk Client, Server;

        /// <summary>The exponent size lesson 8's legacy exchange draws, in bits (SshKex.DhPrivateSize). The walk's own exponents are short practice values,
        /// so the screen can say how far they are from the real ones, from the code's own number.</summary>
        public int RealExponentBits;
    }

    /// <summary>
    /// The Diffie-Hellman walk (docs/sections-plan.md, section 4, slice P7). Pure. It runs on public practice exponents, never a session's key,
    /// so nothing in it is a secret. Each row uses BigUInt's own multiply and mod. A guard then compares each result with the real path:
    /// DhGroup14.Public and Shared for group 14 (the code lesson 8's legacy SSH exchange runs), BigUInt.ModPow for the small prime.
    /// A walk that differs from the real path throws DH_WALK_DIVERGED and shows nothing. The screen's paint chips are not engine data.
    /// </summary>
    public static class DhWalks
    {
        /// <summary>A small safe prime, 467 = 2 x 233 + 1, with 5 a primitive root, so every number fits in a sentence.</summary>
        public const uint SmallPrime = 467, SmallGenerator = 5, SmallClientPrivate = 153, SmallServerPrivate = 197;

        public static DhWalk Small()
        {
            BigUInt p = BigUInt.FromUInt32(SmallPrime), g = BigUInt.FromUInt32(SmallGenerator);
            byte[] a = BigUInt.FromUInt32(SmallClientPrivate).ToBigEndian(), b = BigUInt.FromUInt32(SmallServerPrivate).ToBigEndian();
            DhWalk walk = Exchange("small", p, g, a, b);
            RequireSame(g.ModPow(BigUInt.FromBytes(a), p), walk.Client.Public.Result);
            RequireSame(g.ModPow(BigUInt.FromBytes(b), p), walk.Server.Public.Result);
            RequireSame(BigUInt.FromBytes(walk.Server.Public.Result).ModPow(BigUInt.FromBytes(a), p), walk.Client.Shared.Result);
            return walk;
        }

        public static DhWalk Group14()
        {
            BigUInt p = BigUInt.FromBytes(DhGroup14.Prime), g = BigUInt.FromBytes(DhGroup14.GeneratorBytes);
            byte[] a = PracticeExponent("client"), b = PracticeExponent("server");
            DhWalk walk = Exchange("group14", p, g, a, b);
            // The real path, as lesson 8 runs it. Results are compared at the group's full 256-byte width.
            RequireSame(DhGroup14.Public(a), Pad(walk.Client.Public.Result));
            RequireSame(DhGroup14.Public(b), Pad(walk.Server.Public.Result));
            RequireSame(DhGroup14.Shared(a, Pad(walk.Server.Public.Result)), Pad(walk.Client.Shared.Result));
            RequireSame(DhGroup14.Shared(b, Pad(walk.Client.Public.Result)), Pad(walk.Server.Shared.Result));
            return walk;
        }

        /// <summary>A public 32-bit practice exponent from a label, by SHAKE256, as AesPractice makes its key. Its top bit is set, so the walk has 32 rows.</summary>
        public static byte[] PracticeExponent(string side)
        {
            byte[] input = Encoding.UTF8.GetBytes("MMP.NetworkSecurity DH practice " + side);
            Shake shake = Shake.New256();
            shake.Absorb(input, 0, input.Length);
            byte[] x = new byte[4];
            shake.Squeeze(x, 0, 4);
            x[0] |= 0x80;
            return x;
        }

        static DhWalk Exchange(string group, BigUInt p, BigUInt g, byte[] a, byte[] b)
        {
            DhWalk walk = new DhWalk();
            walk.Group = group;
            walk.Prime = p.ToBigEndian();
            walk.Generator = g.ToBigEndian();
            walk.Client = new DhSideWalk();
            walk.Server = new DhSideWalk();
            walk.Client.Private = a;
            walk.Server.Private = b;
            walk.RealExponentBits = SshKex.DhPrivateSize * 8;
            walk.Client.Public = Pow(g, a, p);
            walk.Server.Public = Pow(g, b, p);
            walk.Client.Shared = Pow(BigUInt.FromBytes(walk.Server.Public.Result), a, p);
            walk.Server.Shared = Pow(BigUInt.FromBytes(walk.Client.Public.Result), b, p);
            RequireSame(walk.Client.Shared.Result, walk.Server.Shared.Result);
            return walk;
        }

        /// <summary>Left-to-right square and multiply. The rows read the exponent from its top set bit down to bit 0.</summary>
        static DhPowWalk Pow(BigUInt baseValue, byte[] exponent, BigUInt p)
        {
            BigUInt e = BigUInt.FromBytes(exponent), acc = BigUInt.One, b = baseValue.Mod(p);
            List<DhPowRow> rows = new List<DhPowRow>();
            for (int bit = e.BitLength - 1; bit >= 0; bit--)
            {
                DhPowRow row = new DhPowRow();
                row.Bit = bit;
                row.IsOne = BitAt(exponent, bit);
                acc = acc.Multiply(acc).Mod(p);
                row.AfterSquare = acc.ToBigEndian();
                if (row.IsOne)
                {
                    acc = acc.Multiply(b).Mod(p);
                    row.AfterMultiply = acc.ToBigEndian();
                }
                rows.Add(row);
            }
            DhPowWalk walk = new DhPowWalk();
            walk.Base = b.ToBigEndian();
            walk.Exponent = e.ToBigEndian();
            walk.Result = acc.ToBigEndian();
            walk.Rows = rows.ToArray();
            return walk;
        }

        static bool BitAt(byte[] bigEndian, int bit)
        {
            int index = bigEndian.Length - 1 - bit / 8;
            return index >= 0 && ((bigEndian[index] >> (bit % 8)) & 1) == 1;
        }

        static byte[] Pad(byte[] value)
        {
            return BigUInt.FromBytes(value).ToBigEndian(256);
        }

        static void RequireSame(BigUInt real, byte[] walked)
        {
            RequireSame(real.ToBigEndian(), walked);
        }

        internal static void RequireSame(byte[] real, byte[] walked)
        {
            bool same = real != null && walked != null && real.Length == walked.Length;
            for (int i = 0; same && i < real.Length; i++) same = real[i] == walked[i];
            if (!same) throw new NetSecException(NetSecError.Of(ErrorCodes.DhWalkDiverged, "The walk differs from the real Diffie-Hellman path."));
        }
    }
}
