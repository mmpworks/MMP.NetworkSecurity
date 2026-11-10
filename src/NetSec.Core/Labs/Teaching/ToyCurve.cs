using System;
using System.Collections.Generic;

namespace NetSec.Labs.Teaching
{
    /// <summary>A point on the toy curve, or O, the point at infinity. Immutable.</summary>
    public sealed class ToyPoint
    {
        public static readonly ToyPoint Infinity = new ToyPoint(0, 0, true);

        public readonly int X, Y;
        public readonly bool IsInfinity;

        ToyPoint(int x, int y, bool infinity) { X = x; Y = y; IsInfinity = infinity; }

        public static ToyPoint At(int x, int y) { return new ToyPoint(x, y, false); }

        public bool SameAs(ToyPoint other)
        {
            if (IsInfinity || other.IsInfinity) return IsInfinity == other.IsInfinity;
            return X == other.X && Y == other.Y;
        }

        public override string ToString() { return IsInfinity ? "O" : "(" + X + ", " + Y + ")"; }
    }

    /// <summary>One step of the extended Euclid algorithm on (a, b): a = quotient * b + remainder. T is the running coefficient of the value to invert.</summary>
    public sealed class EuclidRow
    {
        public int A, B, Quotient, Remainder, T;
    }

    /// <summary>The inverse of Of modulo Modulus, with the extended Euclid steps that found it.</summary>
    public sealed class ToyInverse
    {
        public int Of, Modulus, Value;
        public EuclidRow[] Rows;
    }

    /// <summary>
    /// One point addition. Kind is "add" (P and Q differ), "double" (P equals Q), "identity" (P or Q is O), or "opposite" (Q is -P, so the sum is O).
    /// Only add and double have a slope: lambda = numerator / denominator, with the denominator's inverse. The other kinds leave Inverse null.
    /// RPrime is the third point where the line meets the curve, before the flip to Result (issue #374). On add and double it lies on the line,
    /// and Result is RPrime reflected, (x, -y mod 17). On opposite the line is vertical, so RPrime is O. On identity one point is O, no line
    /// exists, and RPrime is null.
    /// </summary>
    public sealed class ToyStep
    {
        public string Kind;
        public ToyPoint P, Q, Result, RPrime;
        public int Numerator, Denominator, Lambda;
        public ToyInverse Inverse;
    }

    /// <summary>
    /// The curve y^2 = x^3 + 2x + 2 over GF(17), from video 4Tfmwxr0I34 (docs/sections-plan.md, R7 and slice P8a). It has 18 points plus O, 19 in all,
    /// and 19 is prime, so every point except O generates the group. Teaching code: a group of 19 falls to a search by hand, and no handshake offers it.
    /// </summary>
    public static class ToyCurve
    {
        public const int Prime = 17, A = 2, B = 2, Order = 19;

        /// <summary>The generator the walk uses, (5, 1), the textbook point for this curve.</summary>
        public static readonly ToyPoint G = ToyPoint.At(5, 1);

        public static int Mod(int value, int modulus)
        {
            int r = value % modulus;
            return r < 0 ? r + modulus : r;
        }

        public static bool IsOnCurve(ToyPoint p)
        {
            if (p.IsInfinity) return true;
            return Mod(p.Y * p.Y, Prime) == Mod(p.X * p.X * p.X + A * p.X + B, Prime);
        }

        /// <summary>Every affine point, x from 0 to 16, and for each x the smaller y first. O is not in the list.</summary>
        public static ToyPoint[] Points()
        {
            List<ToyPoint> points = new List<ToyPoint>();
            for (int x = 0; x < Prime; x++)
                for (int y = 0; y < Prime; y++)
                {
                    ToyPoint p = ToyPoint.At(x, y);
                    if (IsOnCurve(p)) points.Add(p);
                }
            return points.ToArray();
        }

        /// <summary>The inverse of value modulo modulus by the extended Euclid algorithm. The modulus must be prime and value must not be 0 modulo it.</summary>
        public static ToyInverse Inverse(int value, int modulus)
        {
            int of = Mod(value, modulus);
            if (of == 0) throw new ArgumentException("0 has no inverse", "value");
            List<EuclidRow> rows = new List<EuclidRow>();
            int a = modulus, b = of, tPrevious = 0, t = 1;
            while (b != 0)
            {
                EuclidRow row = new EuclidRow();
                row.A = a;
                row.B = b;
                row.Quotient = a / b;
                row.Remainder = a % b;
                row.T = t;
                rows.Add(row);
                int tNext = tPrevious - row.Quotient * t;
                tPrevious = t;
                t = tNext;
                a = b;
                b = row.Remainder;
            }
            ToyInverse inverse = new ToyInverse();
            inverse.Of = of;
            inverse.Modulus = modulus;
            inverse.Value = Mod(tPrevious, modulus);
            inverse.Rows = rows.ToArray();
            return inverse;
        }

        public static ToyStep Add(ToyPoint p, ToyPoint q)
        {
            ToyStep step = new ToyStep();
            step.P = p;
            step.Q = q;
            if (p.IsInfinity || q.IsInfinity)
            {
                step.Kind = "identity";
                step.Result = p.IsInfinity ? q : p;
                return step;
            }
            if (p.X == q.X && Mod(p.Y + q.Y, Prime) == 0)
            {
                step.Kind = "opposite";
                step.Result = ToyPoint.Infinity;
                return step;
            }
            bool doubling = p.SameAs(q);
            step.Kind = doubling ? "double" : "add";
            step.Numerator = doubling ? Mod(3 * p.X * p.X + A, Prime) : Mod(q.Y - p.Y, Prime);
            step.Denominator = doubling ? Mod(2 * p.Y, Prime) : Mod(q.X - p.X, Prime);
            step.Inverse = Inverse(step.Denominator, Prime);
            step.Lambda = Mod(step.Numerator * step.Inverse.Value, Prime);
            int x = Mod(step.Lambda * step.Lambda - p.X - q.X, Prime);
            step.Result = ToyPoint.At(x, Mod(step.Lambda * (p.X - x) - p.Y, Prime));
            return step;
        }

        /// <summary>k times p by repeated addition, k at least 0. The walk uses it as the plain reference for the faster methods.</summary>
        public static ToyPoint Times(int k, ToyPoint p)
        {
            ToyPoint sum = ToyPoint.Infinity;
            for (int i = 0; i < k; i++) sum = Add(sum, p).Result;
            return sum;
        }
    }
}
