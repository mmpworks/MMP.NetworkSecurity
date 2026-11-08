using System;
using System.Collections.Generic;
using NetSec.Errors;

namespace NetSec.Labs.Teaching
{
    /// <summary>One hop of k·G: the point K·G, and the addition (K-1)·G + G that reached it. Hop 1 is G itself and has no step.</summary>
    public sealed class ToyHop
    {
        public int K;
        public ToyPoint Point;
        public ToyStep Step;
    }

    /// <summary>One bit of double-and-add: double the running point, then add G only when the bit is 1. AddStep is null on a 0.</summary>
    public sealed class ToyDoubleAddRow
    {
        public int Bit;
        public bool IsOne;
        public ToyStep DoubleStep, AddStep;
        public ToyPoint After;
    }

    /// <summary>
    /// One bit of the Montgomery ladder. Every bit does the same steps, one addition and one doubling, whatever its value. The same steps
    /// are not the same time: ToyCurve.Add takes shorter branches for O. Constant time is the X25519 walk's and lesson 11's point.
    /// On a 0: R1 = R0 + R1, then R0 = 2·R0. On a 1: R0 = R0 + R1, then R1 = 2·R1. R1 - R0 stays G.
    /// </summary>
    public sealed class ToyLadderRow
    {
        public int Bit;
        public bool IsOne;
        public ToyStep AddStep, DoubleStep;
        public ToyPoint R0, R1;
    }

    public sealed class ToyEcdh
    {
        public int AlicePrivate, BobPrivate;
        public ToyPoint AlicePublic, BobPublic, AliceShared, BobShared;
    }

    /// <summary>An ECDSA signature on the toy curve: R = k·G, r = R.x mod 19, s = k^-1 (z + r·d) mod 19. Z is the message hash as a toy number.</summary>
    public sealed class ToySignature
    {
        public int Z, Nonce, SmallR, S;
        public ToyPoint R;
        public ToyInverse NonceInverse;
    }

    /// <summary>Verify: w = s^-1, u1 = z·w, u2 = r·w, X = u1·G + u2·Q, and the signature holds when X.x mod 19 equals r.</summary>
    public sealed class ToyVerify
    {
        public ToyInverse SInverse;
        public int U1, U2;
        public ToyPoint X;
        public bool Valid;
    }

    /// <summary>Two signatures with one nonce: k = (z1 - z2) / (s1 - s2) and d = (s1·k - z1) / r, all mod 19.</summary>
    public sealed class ToyNonceReuse
    {
        public ToyInverse SDifferenceInverse, RInverse;
        public int RecoveredNonce, RecoveredPrivate;
    }

    /// <summary>One learner pick: two indexes into the 19-point list (ToyCurveWalks.PickList) and the addition the engine did for them.</summary>
    public sealed class ToyPick
    {
        public int PIndex, QIndex, ResultIndex;
        public ToyStep Step;
    }

    public sealed class ToyCurveWalk
    {
        public ToyPoint[] Points;
        public ToyStep AddExample, DoubleExample;
        public ToyHop[] Hops;
        public int K;
        public ToyDoubleAddRow[] DoubleAndAdd;
        public ToyLadderRow[] Ladder;
        public ToyEcdh Ecdh;
        public int SignerPrivate;
        public ToyPoint SignerPublic;
        public ToySignature First, Second;
        public ToyVerify FirstVerify, SecondVerify;
        public ToyNonceReuse Recovery;
    }

    /// <summary>
    /// The toy-curve walk in the order of video 4Tfmwxr0I34 (docs/sections-plan.md, R7 and slice P8a). Pure. Every value is public and fixed.
    /// Each method's result is checked against the plain repeated-addition path, so a walk that disagrees with itself throws TOY_CURVE_WALK_DIVERGED.
    /// </summary>
    public static class ToyCurveWalks
    {
        public const int K = 13, AlicePrivate = 3, BobPrivate = 7, SignerPrivate = 7, ReusedNonce = 3, FirstHash = 8, SecondHash = 11;

        public static ToyCurveWalk Build()
        {
            ToyCurveWalk w = new ToyCurveWalk();
            w.Points = ToyCurve.Points();
            Require(w.Points.Length + 1 == ToyCurve.Order);
            ToyPoint g = ToyCurve.G, twoG = ToyCurve.Add(g, g).Result;
            w.DoubleExample = ToyCurve.Add(g, g);
            w.AddExample = ToyCurve.Add(g, twoG);
            w.Hops = Hops();
            w.K = K;
            w.DoubleAndAdd = DoubleAndAdd(K);
            w.Ladder = Ladder(K);
            ToyPoint kG = ToyCurve.Times(K, g);
            Require(w.Hops[K - 1].Point.SameAs(kG));
            Require(w.DoubleAndAdd[w.DoubleAndAdd.Length - 1].After.SameAs(kG));
            Require(w.Ladder[w.Ladder.Length - 1].R0.SameAs(kG));
            w.Ecdh = Ecdh();
            w.SignerPrivate = SignerPrivate;
            w.SignerPublic = ToyCurve.Times(SignerPrivate, g);
            w.First = Sign(FirstHash, ReusedNonce);
            w.Second = Sign(SecondHash, ReusedNonce);
            w.FirstVerify = Verify(w.First, w.SignerPublic);
            w.SecondVerify = Verify(w.Second, w.SignerPublic);
            Require(w.FirstVerify.Valid && w.SecondVerify.Valid);
            w.Recovery = Recover(w.First, w.Second);
            Require(w.Recovery.RecoveredNonce == ReusedNonce && w.Recovery.RecoveredPrivate == SignerPrivate);
            return w;
        }

        static int N(int value) { return ToyCurve.Mod(value, ToyCurve.Order); }

        static ToyHop[] Hops()
        {
            List<ToyHop> hops = new List<ToyHop>();
            ToyHop first = new ToyHop();
            first.K = 1;
            first.Point = ToyCurve.G;
            hops.Add(first);
            for (int k = 2; k <= ToyCurve.Order; k++)
            {
                ToyHop hop = new ToyHop();
                hop.K = k;
                hop.Step = ToyCurve.Add(hops[k - 2].Point, ToyCurve.G);
                hop.Point = hop.Step.Result;
                hops.Add(hop);
            }
            Require(hops[ToyCurve.Order - 1].Point.IsInfinity);
            return hops.ToArray();
        }

        static int TopBit(int k)
        {
            int top = 0;
            while ((k >> (top + 1)) != 0) top++;
            return top;
        }

        static ToyDoubleAddRow[] DoubleAndAdd(int k)
        {
            List<ToyDoubleAddRow> rows = new List<ToyDoubleAddRow>();
            ToyPoint running = ToyPoint.Infinity;
            for (int bit = TopBit(k); bit >= 0; bit--)
            {
                ToyDoubleAddRow row = new ToyDoubleAddRow();
                row.Bit = bit;
                row.IsOne = ((k >> bit) & 1) == 1;
                row.DoubleStep = ToyCurve.Add(running, running);
                running = row.DoubleStep.Result;
                if (row.IsOne)
                {
                    row.AddStep = ToyCurve.Add(running, ToyCurve.G);
                    running = row.AddStep.Result;
                }
                row.After = running;
                rows.Add(row);
            }
            return rows.ToArray();
        }

        static ToyLadderRow[] Ladder(int k)
        {
            List<ToyLadderRow> rows = new List<ToyLadderRow>();
            ToyPoint r0 = ToyPoint.Infinity, r1 = ToyCurve.G;
            for (int bit = TopBit(k); bit >= 0; bit--)
            {
                ToyLadderRow row = new ToyLadderRow();
                row.Bit = bit;
                row.IsOne = ((k >> bit) & 1) == 1;
                row.AddStep = ToyCurve.Add(r0, r1);
                row.DoubleStep = row.IsOne ? ToyCurve.Add(r1, r1) : ToyCurve.Add(r0, r0);
                if (row.IsOne) { r0 = row.AddStep.Result; r1 = row.DoubleStep.Result; }
                else { r1 = row.AddStep.Result; r0 = row.DoubleStep.Result; }
                row.R0 = r0;
                row.R1 = r1;
                rows.Add(row);
            }
            return rows.ToArray();
        }

        static ToyEcdh Ecdh()
        {
            ToyEcdh e = new ToyEcdh();
            e.AlicePrivate = AlicePrivate;
            e.BobPrivate = BobPrivate;
            e.AlicePublic = ToyCurve.Times(AlicePrivate, ToyCurve.G);
            e.BobPublic = ToyCurve.Times(BobPrivate, ToyCurve.G);
            e.AliceShared = ToyCurve.Times(AlicePrivate, e.BobPublic);
            e.BobShared = ToyCurve.Times(BobPrivate, e.AlicePublic);
            Require(e.AliceShared.SameAs(e.BobShared) && !e.AliceShared.IsInfinity);
            return e;
        }

        static ToySignature Sign(int z, int nonce)
        {
            ToySignature s = new ToySignature();
            s.Z = z;
            s.Nonce = nonce;
            s.R = ToyCurve.Times(nonce, ToyCurve.G);
            s.SmallR = N(s.R.X);
            s.NonceInverse = ToyCurve.Inverse(nonce, ToyCurve.Order);
            s.S = N(s.NonceInverse.Value * (z + s.SmallR * SignerPrivate));
            Require(s.SmallR != 0 && s.S != 0);
            return s;
        }

        static ToyVerify Verify(ToySignature s, ToyPoint signerPublic)
        {
            ToyVerify v = new ToyVerify();
            v.SInverse = ToyCurve.Inverse(s.S, ToyCurve.Order);
            v.U1 = N(s.Z * v.SInverse.Value);
            v.U2 = N(s.SmallR * v.SInverse.Value);
            v.X = ToyCurve.Add(ToyCurve.Times(v.U1, ToyCurve.G), ToyCurve.Times(v.U2, signerPublic)).Result;
            v.Valid = !v.X.IsInfinity && N(v.X.X) == s.SmallR;
            return v;
        }

        static ToyNonceReuse Recover(ToySignature first, ToySignature second)
        {
            Require(first.SmallR == second.SmallR && first.S != second.S);
            ToyNonceReuse r = new ToyNonceReuse();
            r.SDifferenceInverse = ToyCurve.Inverse(first.S - second.S, ToyCurve.Order);
            r.RecoveredNonce = N((first.Z - second.Z) * r.SDifferenceInverse.Value);
            r.RInverse = ToyCurve.Inverse(first.SmallR, ToyCurve.Order);
            r.RecoveredPrivate = N((first.S * r.RecoveredNonce - first.Z) * r.RInverse.Value);
            return r;
        }

        /// <summary>The 19 points a learner can pick: the 18 affine points in ToyCurve.Points order (indexes 0 to 17), then O (index 18).</summary>
        public static ToyPoint[] PickList()
        {
            ToyPoint[] affine = ToyCurve.Points();
            ToyPoint[] all = new ToyPoint[affine.Length + 1];
            Array.Copy(affine, all, affine.Length);
            all[affine.Length] = ToyPoint.Infinity;
            return all;
        }

        /// <summary>
        /// Adds the two picked points with ToyCurve.Add, which shows the slope, the inverse and the result. The same index twice is a double.
        /// The set is finite and public, so any pair is safe. An index outside 0 to 18 throws ArgumentOutOfRangeException, which the route refuses by name.
        /// </summary>
        public static ToyPick Pick(int pIndex, int qIndex)
        {
            ToyPoint[] all = PickList();
            if (pIndex < 0 || pIndex >= all.Length) throw new ArgumentOutOfRangeException("pIndex");
            if (qIndex < 0 || qIndex >= all.Length) throw new ArgumentOutOfRangeException("qIndex");
            ToyPick pick = new ToyPick();
            pick.PIndex = pIndex;
            pick.QIndex = qIndex;
            pick.Step = ToyCurve.Add(all[pIndex], all[qIndex]);
            pick.ResultIndex = -1;
            for (int i = 0; i < all.Length; i++) if (all[i].SameAs(pick.Step.Result)) pick.ResultIndex = i;
            Require(pick.ResultIndex >= 0);
            return pick;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.ToyCurveWalkDiverged, "The toy-curve walk disagrees with the plain repeated-addition path."));
        }
    }
}
