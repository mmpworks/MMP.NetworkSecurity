using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using NetSec.Errors;
using NetSec.Labs.Teaching;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Slice P8a's toy-curve walk. The referee is brute force with System.Numerics.BigInteger, written here and sharing no code with ToyCurve:
    /// every point by trying each x and y, each sum by the chord and tangent formulas with a Fermat inverse, and the order by repeated addition.
    /// </summary>
    public class ToyCurveWalkTests
    {
        const int P = 17, N = 19;

        /// <summary>A point as (x, y), or null for O.</summary>
        static (int X, int Y)? Pt(ToyPoint p) { return p.IsInfinity ? null : ((int, int)?)(p.X, p.Y); }

        static int M(BigInteger v, int m) { BigInteger r = v % m; return (int)(r < 0 ? r + m : r); }

        static int Inv(int v, int m) { return M(BigInteger.ModPow(M(v, m), m - 2, m), m); }

        static (int X, int Y)? RefAdd((int X, int Y)? a, (int X, int Y)? b)
        {
            if (a == null) return b;
            if (b == null) return a;
            if (a.Value.X == b.Value.X && M(a.Value.Y + b.Value.Y, P) == 0) return null;
            int lambda = a.Value.Equals(b.Value)
                ? M((3 * a.Value.X * a.Value.X + 2) * (BigInteger)Inv(2 * a.Value.Y, P), P)
                : M((b.Value.Y - a.Value.Y) * (BigInteger)Inv(b.Value.X - a.Value.X, P), P);
            int x = M(lambda * lambda - a.Value.X - b.Value.X, P);
            return (x, M(lambda * (a.Value.X - x) - a.Value.Y, P));
        }

        static (int X, int Y)? RefTimes(int k, (int X, int Y)? p)
        {
            (int X, int Y)? sum = null;
            for (int i = 0; i < k; i++) sum = RefAdd(sum, p);
            return sum;
        }

        static readonly ToyCurveWalk W = ToyCurveWalks.Build();

        [Fact]
        public void The_scatter_is_every_point_found_by_trying_each_x_and_y_and_the_group_has_19()
        {
            var brute = new List<(int, int)>();
            for (int x = 0; x < P; x++)
                for (int y = 0; y < P; y++)
                    if (M((BigInteger)y * y, P) == M((BigInteger)x * x * x + 2 * x + 2, P)) brute.Add((x, y));
            Assert.Equal(brute, W.Points.Select(p => (p.X, p.Y)));
            Assert.Equal(18, W.Points.Length);
            Assert.Contains((5, 1), brute);
            // The order by repeated addition: 19·G is O and no smaller multiple is.
            for (int k = 1; k < N; k++) Assert.NotNull(RefTimes(k, (5, 1)));
            Assert.Null(RefTimes(N, (5, 1)));
        }

        [Fact]
        public void Every_hop_matches_the_reference_and_the_cycle_closes_at_19()
        {
            Assert.Equal(N, W.Hops.Length);
            Assert.Null(W.Hops[0].Step);
            for (int i = 0; i < N; i++)
            {
                Assert.Equal(i + 1, W.Hops[i].K);
                Assert.Equal(RefTimes(i + 1, (5, 1)), Pt(W.Hops[i].Point));
            }
            Assert.Equal("double", W.Hops[1].Step.Kind);
            Assert.Equal("opposite", W.Hops[N - 1].Step.Kind);
        }

        [Fact]
        public void Each_slope_shows_its_numerator_denominator_inverse_and_lambda_and_the_euclid_rows_hold()
        {
            foreach (ToyStep s in new[] { W.AddExample, W.DoubleExample }.Concat(W.Hops.Skip(1).Select(h => h.Step)).Where(s => s.Inverse != null))
            {
                Assert.Equal(Inv(s.Denominator, P), s.Inverse.Value);
                Assert.Equal(M((BigInteger)s.Numerator * Inv(s.Denominator, P), P), s.Lambda);
                Assert.Equal(RefAdd(Pt(s.P), Pt(s.Q)), Pt(s.Result));
                foreach (EuclidRow r in s.Inverse.Rows) Assert.Equal(r.A, r.Quotient * r.B + r.Remainder);
                Assert.Equal(1, s.Inverse.Rows.Last().B);
            }
            Assert.Equal("double", W.DoubleExample.Kind);
            Assert.Equal("add", W.AddExample.Kind);
        }

        [Fact]
        public void Double_and_add_and_the_ladder_both_reach_13G_and_the_ladder_keeps_R1_minus_R0_equal_to_G()
        {
            Assert.Equal(13, W.K);
            var target = RefTimes(13, (5, 1));
            Assert.Equal(((int, int)?)(16, 4), target);
            Assert.Equal(new[] { true, true, false, true }, W.DoubleAndAdd.Select(r => r.IsOne));
            Assert.All(W.DoubleAndAdd, r => Assert.Equal(r.IsOne, r.AddStep != null));
            Assert.Equal(target, Pt(W.DoubleAndAdd.Last().After));
            Assert.Equal(target, Pt(W.Ladder.Last().R0));
            int k = 0;
            foreach (ToyLadderRow r in W.Ladder)
            {
                k = 2 * k + (r.IsOne ? 1 : 0);
                Assert.NotNull(r.AddStep);
                Assert.NotNull(r.DoubleStep);
                Assert.Equal(RefTimes(k, (5, 1)), Pt(r.R0));
                Assert.Equal(RefTimes(k + 1, (5, 1)), Pt(r.R1));
            }
        }

        [Fact]
        public void Ecdh_both_sides_reach_the_same_point()
        {
            Assert.Equal(RefTimes(3 * 7, (5, 1)), Pt(W.Ecdh.AliceShared));
            Assert.Equal(Pt(W.Ecdh.AliceShared), Pt(W.Ecdh.BobShared));
        }

        [Fact]
        public void Ecdsa_signs_and_verifies_and_a_reused_nonce_gives_away_the_private_key()
        {
            // The video's values: d = 7, Q = 7G = (0, 6), z = 8, nonce k = 3, k^-1 = 13 mod 19.
            Assert.Equal(7, W.SignerPrivate);
            Assert.Equal(((int, int)?)(0, 6), Pt(W.SignerPublic));
            Assert.Equal(RefTimes(7, (5, 1)), Pt(W.SignerPublic));
            Assert.Equal(8, W.First.Z);
            Assert.Equal(13, W.First.NonceInverse.Value);
            Assert.Equal(10, W.First.SmallR);
            Assert.Equal(7, W.First.S);
            Assert.NotEqual(8 % N, W.Second.Z % N);
            foreach (ToySignature s in new[] { W.First, W.Second })
            {
                Assert.Equal(3, s.Nonce);
                Assert.Equal(RefTimes(3, (5, 1)), Pt(s.R));
                Assert.Equal(s.R.X % N, s.SmallR);
                Assert.Equal(M((BigInteger)Inv(3, N) * (s.Z + s.SmallR * 7), N), s.S);
            }
            Assert.True(W.FirstVerify.Valid);
            Assert.True(W.SecondVerify.Valid);
            Assert.Equal(W.First.SmallR, W.Second.SmallR);
            Assert.Equal(3, W.Recovery.RecoveredNonce);
            Assert.Equal(7, W.Recovery.RecoveredPrivate);
        }

        [Fact]
        public void Every_one_of_the_361_picks_matches_the_reference_and_names_its_result()
        {
            ToyPoint[] list = ToyCurveWalks.PickList();
            Assert.Equal(N, list.Length);
            Assert.True(list[18].IsInfinity);
            for (int i = 0; i < N; i++)
                for (int j = 0; j < N; j++)
                {
                    ToyPick pick = ToyCurveWalks.Pick(i, j);
                    var expected = RefAdd(Pt(list[i]), Pt(list[j]));
                    Assert.Equal(expected, Pt(pick.Step.Result));
                    Assert.Equal(expected, Pt(list[pick.ResultIndex]));
                    if (i == j && i < 18) Assert.Equal("double", pick.Step.Kind);
                    if (i == 18 || j == 18) Assert.Equal("identity", pick.Step.Kind);
                }
            Assert.Throws<ArgumentOutOfRangeException>(() => ToyCurveWalks.Pick(19, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => ToyCurveWalks.Pick(0, -1));
        }

        [Fact]
        public void The_real_curve_samples_lie_on_their_lines_and_on_the_curve_inside_the_drawn_range()
        {
            RealCurveSample s = RealCurveSamples.Build();
            Assert.Equal(new[] { "chord", "chord", "chord", "tangent" }, s.Samples.Select(e => e.Kind));
            foreach (RealLineExample e in s.Samples)
            {
                Assert.True(Math.Abs(e.RPrime.Y * e.RPrime.Y - RealCurveSamples.Cubic(e.RPrime.X)) < 1e-9, e.Kind + ": R' is on the curve");
                Assert.True(Math.Abs(e.RPrime.Y - (e.P.Y + e.Lambda * (e.RPrime.X - e.P.X))) < 1e-9, e.Kind + ": R' is on the line");
                Assert.True(Math.Abs(e.Q.Y - (e.P.Y + e.Lambda * (e.Q.X - e.P.X))) < 1e-9, e.Kind + ": Q is on the line");
                Assert.InRange(e.RPrime.X, s.Root, s.XMax);
                Assert.Equal(-e.RPrime.Y, e.R.Y);
            }
        }

        [Fact]
        public void The_guard_names_its_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => ToyCurveWalks.Require(false));
            Assert.Equal(ErrorCodes.ToyCurveWalkDiverged, e.Error.Code);
        }

        [Fact]
        public void The_real_curve_examples_lie_on_their_lines_and_on_the_curve()
        {
            RealCurveSample s = RealCurveSamples.Build();
            Assert.True(Math.Abs(RealCurveSamples.Cubic(s.Root)) < 1e-9);
            for (int i = 0; i < s.Upper.Length; i++)
            {
                Assert.True(Math.Abs(s.Upper[i].Y * s.Upper[i].Y - RealCurveSamples.Cubic(s.Upper[i].X)) < 1e-9);
                Assert.Equal(s.Upper[i].X, s.Lower[i].X);
                Assert.Equal(-s.Upper[i].Y, s.Lower[i].Y);
            }
            foreach (RealLineExample e in new[] { s.Chord, s.Tangent })
            {
                Assert.True(Math.Abs(e.RPrime.Y * e.RPrime.Y - RealCurveSamples.Cubic(e.RPrime.X)) < 1e-9, e.Kind + ": R' is on the curve");
                Assert.True(Math.Abs(e.RPrime.Y - (e.P.Y + e.Lambda * (e.RPrime.X - e.P.X))) < 1e-9, e.Kind + ": R' is on the line");
                Assert.Equal(-e.RPrime.Y, e.R.Y);
            }
            Assert.True(Math.Abs(s.Chord.Q.Y - (s.Chord.P.Y + s.Chord.Lambda * (s.Chord.Q.X - s.Chord.P.X))) < 1e-9, "Q is on the chord");
        }

        /// <summary>The toy curve is never offered in a handshake: no protocol or crypto file names it (docs/sections-plan.md, P8a constraint 1).</summary>
        [Fact]
        public void No_protocol_or_crypto_file_names_the_teaching_curves()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !Directory.Exists(Path.Combine(dir, "src", "NetSec.Core"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "src/NetSec.Core was not found above the test folder");
            var hits = new List<string>();
            int scanned = 0;
            foreach (string folder in new[] { "Tls11", "Tls13", "Ssh", "Crypto", "Pki" })
                foreach (string file in Directory.GetFiles(Path.Combine(dir, "src", "NetSec.Core", folder), "*.cs", SearchOption.AllDirectories))
                {
                    scanned++;
                    string text = File.ReadAllText(file);
                    if (text.Contains("ToyCurve") || text.Contains("RealCurveSample") || text.Contains("Labs.Teaching")) hits.Add(file);
                }
            Assert.True(scanned > 20, "the scan found only " + scanned + " files");
            Assert.Empty(hits);
        }
    }
}
