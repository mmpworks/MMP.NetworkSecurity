using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using NetSec.Bench.Files;

namespace NetSec.Bench;

/// <summary>The sink the linked case adapters write to, so the JIT cannot drop the work.</summary>
static class Cases
{
    public static object Sink;
}

/// <summary>
/// The block cases on the .NET Framework 3.5 desktop runtime (CLR 2.0): the frozen 5c5d4a4 copy against the product, both CF binaries.
/// Timing is the main bench's engine (<see cref="Measure"/>, linked): the fastest core pinned, a pre-warm of every case, alternating
/// round pairs with a full GC before each round, the median of the pair ratios, and the same-code band. CLR 2.0 has no allocation
/// counter, so bytes per call come from a separate pass (<see cref="BytesPerCall"/>).
/// Usage: NetSec.Bench.Clr2.exe [--same-code true]. A same-code ratio outside the band exits 6; outside load over the MachineLoad ceiling exits 8.
/// </summary>
static class Program
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    static readonly TimeSpan Round = TimeSpan.FromMilliseconds(150), PreWarmEach = TimeSpan.FromMilliseconds(500);

    sealed class Case
    {
        public string Id;
        public int Units, Payload;   // payload bytes per call, for GC collections per MB (0 for key setup)
        public Action Original, New;
    }

    /// <summary>The runtime line the linked report sections print. CLR 2.0 has no RuntimeInformation, so it is Environment.Version and the process width.</summary>
    public static string Machine() => "CLR " + Environment.Version + ", " + (IntPtr.Size * 8) + "-bit process, " + Environment.ProcessorCount + " logical processors";

    static int Main(string[] args)
    {
        Dictionary<string, string> a = new Dictionary<string, string>();
        for (int i = 0; i + 1 < args.Length; i += 2) a[args[i].TrimStart('-')] = args[i + 1];
        string build = "cf-binaries-on-net35-clr2-" + (IntPtr.Size == 4 ? "x86" : "x64");
        if (a.ContainsKey("mode") && a["mode"] == "footprint")
            return Footprint.Run(a, new Run { Build = build, Head = a.ContainsKey("head") ? a["head"] : "", Priority = "normal (footprint does no timing)", CfLine = "CF ARM speed: UNMEASURED" });
        bool sameCode = a.ContainsKey("same-code") && a["same-code"] == "true";
        // --part TAG [--pairs N] --out DIR --head SHA: one part of the balanced crossover; the tag sets the swap and the JIT order (CrossoverPart).
        string part = a.ContainsKey("part") ? a["part"] : null;
        if (part != null && (!CrossoverPart.IsTag(part) || !a.ContainsKey("out") || !a.ContainsKey("head"))) { Console.Error.WriteLine("BENCH_USAGE: --part (" + string.Join(", ", CrossoverPart.Tags) + ") needs --out DIR --head SHA"); return 2; }
        bool swap = part != null && CrossoverPart.Swapped(part);
        int pairs = a.ContainsKey("pairs") ? int.Parse(a["pairs"], Inv) : Measure.Rounds;
        Console.WriteLine("RUNTIME CLR " + Environment.Version + ", " + (IntPtr.Size * 8) + "-bit process");
        Console.WriteLine("NETSEC_CORE " + typeof(NetSec.Crypto.AesKey).Assembly.FullName);
        Console.WriteLine("FROZEN " + typeof(Acceptance.Frozen.Crypto.AesKey).Assembly.FullName);
        string priority = Measure.RaisePriority(null);
        string timing = pairs + " round pairs of at least " + Round.TotalMilliseconds + " ms per copy, pre-warm " + PreWarmEach.TotalMilliseconds + " ms per copy per case";
        Console.WriteLine("PRIORITY " + priority);
        Console.WriteLine("TIMING " + timing);

        FrozenCode frozen = new FrozenCode();
        ProductCode product = new ProductCode();
        List<Case> cases = swap ? All(product, frozen) : All(frozen, product);
        if (swap) Console.WriteLine("BENCH_SWAP original = product, new = frozen copy");
        if (part != null)
        {
            // Compile one copy first: one call of every case on it, then on the other. In a swapped part the product is "original".
            bool productFirst = CrossoverPart.JitFirst(part) == "product";
            bool originalFirst = productFirst == swap;
            foreach (Case c in cases) (originalFirst ? c.Original : c.New)();
            foreach (Case c in cases) (originalFirst ? c.New : c.Original)();
            Console.WriteLine("BENCH_JIT_FIRST " + CrossoverPart.JitFirst(part));
        }
        Measure.PreWarm(cases.Select(c => new[] { c.Original, c.New }), PreWarmEach);
        if (!MachineLoad.Settle()) return MachineLoad.BusyExit;
        List<double> ratios = new List<double>(), busy = new List<double>(), coreBusy = new List<double>();
        List<string> detail = new List<string>();
        List<PartRow> partRows = new List<PartRow>();
        foreach (Case c in cases)
        {
            Pair p = Measure.Run(c.Original, c.New, Round, pairs);
            if (part != null) partRows.Add(CrossoverPart.FromPair(c.Id, "unit", c.Units, c.Payload, p, swap, BytesPerCall(c.Original), BytesPerCall(c.New)));
            ratios.Add(p.MedianRatio);
            busy.Add(p.OtherBusy);
            coreBusy.Add(p.CoreBusy);
            detail.Add(c.Id + ": " + p.TopOutside);
            Console.WriteLine(string.Format(Inv, "{0,-22} original {1,10:F1} new {2,10:F1} ns per unit  ratio {3:F3} ({4:F3} to {5:F3})  original {6,8:F1} new {7,8:F1} B per unit  load {8:P1} core {9:P1} cpu {10}>{11}",
                c.Id, p.Original.MedianNs / c.Units, p.New.MedianNs / c.Units, p.MedianRatio, p.Ratios.Min(), p.Ratios.Max(),
                BytesPerCall(c.Original) / c.Units, BytesPerCall(c.New) / c.Units, p.OtherBusy, p.CoreBusy, p.CpuStart, p.CpuEnd));
            if (c.Payload > 0)
            {
                // Steve's measure: garbage collections per megabyte processed, over the timed rounds of each copy.
                double mb = (double)p.CallsPerRound * pairs * c.Payload / 1048576.0;
                Console.WriteLine(string.Format(Inv, "  GC per MB  {0,-22} original gen0 {1:F3} gen1 {2:F4} gen2 {3:F4}   new gen0 {4:F3} gen1 {5:F4} gen2 {6:F4}   ({7:F1} MB per copy)",
                    c.Id, p.Original.Gen0 / mb, p.Original.Gen1 / mb, p.Original.Gen2 / mb, p.New.Gen0 / mb, p.New.Gen1 / mb, p.New.Gen2 / mb, mb));
            }
        }
        Console.WriteLine("BENCH_NOISE " + NoiseBand.Describe(ratios.ToArray()));
        Console.WriteLine("CF ARM speed: UNMEASURED");
        int load = MachineLoad.Exit(busy.ToArray(), detail.ToArray(), coreBusy.ToArray());
        if (part != null)
        {
            // One crossover part: the band does not apply to one arrangement; the net10 combine judges the code ratio.
            Dictionary<string, string> header = new Dictionary<string, string>
            {
                { "head", a["head"] }, { "machine", Machine() }, { "priority", priority }, { "allocation", "GC.GetTotalMemory pass outside the timed rounds (CLR 2.0 has no allocation counter)" },
                { "timing", timing }, { "cf", "CF ARM speed: UNMEASURED" },
            };
            CrossoverPart.Write(a["out"], build, part, header, partRows);
            Console.WriteLine("BENCH_PART_DONE " + build + " " + part + " " + partRows.Count + " cases");
            return load;
        }
        if (load != 0) return load;
        if (!sameCode || NoiseBand.Inside(ratios.ToArray())) return 0;
        Console.WriteLine("BENCH_NOISE_OUTSIDE_BAND: the two copies are the same code, so a ratio outside the target band is harness or machine noise");
        return 6;
    }

    static List<Case> All(IBlockCases o, IBlockCases n) => new List<Case>
    {
        New("aes128.encrypt-block", 1, 16, x => x.AesEncryptBlock(Key(16), Block(), new byte[16]), o, n),
        New("aes128.decrypt-block", 1, 16, x => x.AesDecryptBlock(Key(16), Block(), new byte[16]), o, n),
        New("aes128.key-setup", 1, 0, x => x.AesKeySetup(Key(16)), o, n),
        New("aes128.cbc-encrypt", 64, 1024, x => x.CbcEncrypt(Key(16), new byte[16], Msg()), o, n),
        New("aes128.ctr", 64, 1024, x => x.Ctr(Key(16), new byte[16], Msg()), o, n),
        New("aes128.gcm-seal", 64, 1024, x => x.GcmSeal(Key(16), new byte[12], new byte[0], Msg()), o, n),
        New("aes128.cmac", 64, 1024, x => x.Cmac(Key(16), Msg()), o, n),
        New("sha256.update", 64, 4096, x => x.HashUpdate("sha256", 64), o, n),
        New("hmac-sha256", 1, 1024, x => x.HmacSha256(Key(32), Msg()), o, n),
        New("tdes.encrypt-block", 1, 8, x => x.TdesEncryptBlock(Key(24), Block(), new byte[16]), o, n),
        SmallMessage((ICodeUnderTest)o, (ICodeUnderTest)n),
    };

    /// <summary>The S1 baseline for the static GCM wrapper budget: one AES-128 key setup plus one GCM seal of 64 bytes, as one call (AO-9 rule 6).</summary>
    static Case SmallMessage(ICodeUnderTest o, ICodeUnderTest n)
    {
        byte[] key = Key(16), nonce = new byte[12], aad = new byte[0], plain = new byte[64];
        return new Case
        {
            Id = "gcm.key-setup+seal64", Units = 1, Payload = 64,
            Original = () => Cases.Sink = o.KeySetupAndSeal(key, nonce, aad, plain),
            New = () => Cases.Sink = n.KeySetupAndSeal(key, nonce, aad, plain),
        };
    }

    static Case New(string id, int units, int payload, Func<IBlockCases, Action> make, IBlockCases o, IBlockCases n) =>
        new Case { Id = id, Units = units, Payload = payload, Original = make(o), New = make(n) };

    /// <summary>
    /// Bytes per call from GC.GetTotalMemory after a forced collection, around a call count small enough that no gen-0 collection runs
    /// in between (the count halves from 256 until GC.CollectionCount(0) does not move). NaN when even one call collects.
    /// </summary>
    static double BytesPerCall(Action call)
    {
        for (int count = 256; count >= 1; count /= 2)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            int gen0 = GC.CollectionCount(0);
            long before = GC.GetTotalMemory(false);
            for (int i = 0; i < count; i++) call();
            long after = GC.GetTotalMemory(false);
            if (GC.CollectionCount(0) == gen0) return (double)(after - before) / count;
        }
        return double.NaN;
    }

    static byte[] Key(int n) { byte[] b = new byte[n]; for (int i = 0; i < n; i++) b[i] = (byte)(0x10 + i); return b; }
    static byte[] Block() { byte[] b = new byte[16]; for (int i = 0; i < 16; i++) b[i] = (byte)(0x80 + i); return b; }
    static byte[] Msg() { byte[] b = new byte[1024]; for (int i = 0; i < b.Length; i++) b[i] = (byte)(0x40 + i); return b; }
}
