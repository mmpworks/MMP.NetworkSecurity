using System;

namespace NetSec.Labs.Teaching
{
    public sealed class RealPoint
    {
        public readonly double X, Y;

        public RealPoint(double x, double y) { X = x; Y = y; }
    }

    /// <summary>
    /// One chord or tangent example. The line through P and Q (or the tangent at P) meets the curve again at RPrime, and the sum R is RPrime
    /// reflected across the x-axis. For a tangent, Q is P.
    /// </summary>
    public sealed class RealLineExample
    {
        public string Kind;
        public RealPoint P, Q, RPrime, R;
        public double Lambda;
    }

    public sealed class RealCurveSample
    {
        public double A, B, Root;

        /// <summary>The upper branch from the root to XMax, and the lower branch as its mirror, point for point. The app draws both as given.</summary>
        public RealPoint[] Upper, Lower;
        public double XMax;
        public RealLineExample Chord, Tangent;

        /// <summary>More picks for the screen: 3 chords and 1 tangent. Each R' lies inside the drawn range, so the screen can draw every pick.</summary>
        public RealLineExample[] Samples;
    }

    /// <summary>
    /// y^2 = x^3 + 2x + 2 over the real numbers, the picture video 4Tfmwxr0I34 opens with (docs/sections-plan.md, R7 and slice P8a). Pure.
    /// 4a^3 + 27b^2 = 140 > 0, so the cubic has one real root and the curve is one connected piece: one sampled branch pair draws it whole.
    /// The app draws these decimals and computes nothing (R5).
    /// </summary>
    public static class RealCurveSamples
    {
        public const double A = 2, B = 2, XMax = 3;
        public const int Samples = 120;

        public static RealCurveSample Build()
        {
            RealCurveSample s = new RealCurveSample();
            s.A = A;
            s.B = B;
            s.XMax = XMax;
            s.Root = Root();
            s.Upper = new RealPoint[Samples + 1];
            s.Lower = new RealPoint[Samples + 1];
            for (int i = 0; i <= Samples; i++)
            {
                // Squared spacing puts more samples near the root, where the curve turns vertical.
                double t = (double)i / Samples, x = s.Root + (XMax - s.Root) * t * t, y = i == 0 ? 0 : Math.Sqrt(Math.Max(0, Cubic(x)));
                s.Upper[i] = new RealPoint(x, y);
                s.Lower[i] = new RealPoint(x, -y);
            }
            s.Chord = Line("chord", OnCurve(-0.5), OnCurve(1));
            s.Tangent = Line("tangent", OnCurve(0), OnCurve(0));
            s.Samples = new RealLineExample[]
            {
                Line("chord", OnCurve(0), OnCurve(2)),
                Line("chord", OnCurve(-0.5), Lower(1.5)),
                Line("chord", OnCurve(-0.25), OnCurve(0.75)),
                Line("tangent", OnCurve(1), OnCurve(1)),
            };
            foreach (RealLineExample e in s.Samples)
                if (e.RPrime.X < s.Root || e.RPrime.X > XMax) throw new InvalidOperationException("a sample's R' falls outside the drawn range");
            return s;
        }

        public static double Cubic(double x) { return x * x * x + A * x + B; }

        static RealPoint OnCurve(double x) { return new RealPoint(x, Math.Sqrt(Cubic(x))); }

        /// <summary>The point at x on the lower branch.</summary>
        static RealPoint Lower(double x) { return new RealPoint(x, -Math.Sqrt(Cubic(x))); }

        /// <summary>The one real root of x^3 + 2x + 2, by bisection on [-1, 0], where the cubic changes sign.</summary>
        static double Root()
        {
            double low = -1, high = 0;
            for (int i = 0; i < 80; i++)
            {
                double middle = (low + high) / 2;
                if (Cubic(middle) < 0) low = middle; else high = middle;
            }
            return (low + high) / 2;
        }

        static RealLineExample Line(string kind, RealPoint p, RealPoint q)
        {
            RealLineExample e = new RealLineExample();
            e.Kind = kind;
            e.P = p;
            e.Q = q;
            e.Lambda = kind == "tangent" ? (3 * p.X * p.X + A) / (2 * p.Y) : (q.Y - p.Y) / (q.X - p.X);
            double x = e.Lambda * e.Lambda - p.X - q.X, yOnLine = p.Y + e.Lambda * (x - p.X);
            e.RPrime = new RealPoint(x, yOnLine);
            e.R = new RealPoint(x, -yOnLine);
            return e;
        }
    }
}
