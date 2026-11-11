using System;

namespace Acceptance.AoStandIn
{
    /// <summary>Stand-in types with the shape of PRD 7.3 item 15, so AoStreamBind runs before the product has CbcChain and CtrCounter.</summary>
    public sealed class StandInKey { }

    public sealed class StandInChain
    {
        /// <summary>What the bound delegates called, in order.</summary>
        public static string Trace = "";
        public void Init(byte[] b, int offset) { Trace += "Init(" + b.Length + "," + offset + ");"; }
        public void Clear() { Trace += "Clear();"; }
    }

    /// <summary>Not sealed: item 15 says "public sealed class".</summary>
    public class OpenChain
    {
        public void Init(byte[] b, int offset) { }
        public void Clear() { }
    }

    /// <summary>Sealed, with no Clear.</summary>
    public sealed class NoClearChain
    {
        public void Init(byte[] b, int offset) { }
    }

    public static class StandInModes
    {
        public static void CbcEncrypt(StandInKey k, StandInChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            if (k == null) throw new ArgumentNullException("k");
            if (chain == null) throw new ArgumentNullException("chain");
            StandInChain.Trace += "CbcEncrypt(" + inOffset + "," + count + "," + outOffset + ");";
            Buffer.BlockCopy(input, inOffset, output, outOffset, count);
        }

        /// <summary>The right parameters, and a return value.</summary>
        public static int Ctr(StandInKey k, StandInChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset) { return count; }

        public static void WithOpenChain(StandInKey k, OpenChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset) { }
        public static void WithNoClearChain(StandInKey k, NoClearChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset) { }
    }
}

namespace Acceptance
{
    using Acceptance.AoStandIn;

    public static class SelfAoStreamBind
    {
        static string NotRunReason(string what, Type state, string method)
        {
            try { AoStreamBind.TryBind(typeof(StandInModes), new StandInKey(), state, method); }
            catch (NotRunException e) { return e.Reason; }
            throw new FailException(what + " was bound; it must read NOT RUN SIGNATURE_NOT_CONFIRMED");
        }

        [Clause("SELF.ao-stream-bind-runs-on-stand-in-types")]
        public static string BindRuns(Ctx c)
        {
            StandInKey k = new StandInKey();
            StandInChain.Trace = "";
            AoStreamSeam s = AoStreamBind.TryBind(typeof(StandInModes), k, typeof(StandInChain), "CbcEncrypt");
            if (s == null) throw new FailException("the stand-in overload was not found");
            byte[] input = { 1, 2, 3, 4, 5, 6 }, output = new byte[8];
            s.Init(new byte[20], 3);
            s.Call(input, 1, 4, output, 2);
            s.Clear();
            const string want = "Init(20,3);CbcEncrypt(1,4,2);Clear();";
            if (StandInChain.Trace != want) throw new FailException("the bound delegates called " + StandInChain.Trace + ", wanted " + want);
            if (!Hex.Eq(output, new byte[] { 0, 0, 2, 3, 4, 5, 0, 0 })) throw new FailException("the bound call wrote " + Hex.Encode(output));

            Action<byte[], int, int, byte[], int> nullState = AoStreamBind.TryBindNullState(typeof(StandInModes), k, typeof(StandInChain), "CbcEncrypt");
            if (nullState == null) throw new FailException("the null-state form was not bound");
            string got = "no exception";
            try { nullState(input, 1, 4, output, 2); }
            catch (ArgumentNullException e) { got = "ArgumentNullException " + e.ParamName; }
            if (got != "ArgumentNullException chain") throw new FailException("the null-state call gave " + got);

            if (AoStreamBind.TryBind(typeof(StandInModes), k, typeof(StandInChain), "NoSuchMethod") != null) throw new FailException("a missing overload was bound");
            if (AoStreamBind.TryBind(typeof(StandInModes), k, null, "CbcEncrypt") != null) throw new FailException("a missing state type was bound");

            string[] reasons = {
                NotRunReason("an overload that returns a value", typeof(StandInChain), "Ctr"),
                NotRunReason("a state class that is not sealed", typeof(OpenChain), "WithOpenChain"),
                NotRunReason("a state class with no Clear", typeof(NoClearChain), "WithNoClearChain"),
            };
            foreach (string r in reasons) if (r != "SIGNATURE_NOT_CONFIRMED") throw new FailException("a wrong shape read NOT RUN " + r);
            return "bound: Init, the overload and Clear called in order on one state object; the null-state form throws ArgumentNullException; " +
                   "a missing overload and a missing state type read as missing; a value return, a class that is not sealed and a class with no Clear read SIGNATURE_NOT_CONFIRMED";
        }
    }
}
