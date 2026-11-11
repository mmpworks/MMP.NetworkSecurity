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
/// Usage: NetSec.Bench.Clr2.exe [--same-code true]. A same-code ratio outside the band exits 6.
/// </summary>
static class Program
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    static readonly TimeSpan Round = TimeSpan.FromMilliseconds(150), PreWarmEach = TimeSpan.FromMilliseconds(500);

    sealed class Case
    {
        public string Id;
        public int Units;
        public Action Original, New;
    }

    static int Main(string[] args)
    {
        bool sameCode = args.Length >= 2 && args[0] == "--same-code" && args[1] == "true";
        Console.WriteLine("RUNTIME CLR " + Environment.Version + ", " + (IntPtr.Size * 8) + "-bit process");
        Console.WriteLine("NETSEC_CORE " + typeof(NetSec.Crypto.AesKey).Assembly.FullName);
        Console.WriteLine("FROZEN " + typeof(Acceptance.Frozen.Crypto.AesKey).Assembly.FullName);
        Console.WriteLine("PRIORITY " + Measure.RaisePriority(null));
        Console.WriteLine("TIMING " + Measure.Rounds + " round pairs of at least " + Round.TotalMilliseconds + " ms per copy, pre-warm " + PreWarmEach.TotalMilliseconds + " ms per copy per case");

        List<Case> cases = All(new FrozenCode(), new ProductCode());
        Measure.PreWarm(cases.Select(c => new[] { c.Original, c.New }), PreWarmEach);
        List<double> ratios = new List<double>();
        foreach (Case c in cases)
        {
            Pair p = Measure.Run(c.Original, c.New, Round);
            ratios.Add(p.MedianRatio);
            Console.WriteLine(string.Format(Inv, "{0,-22} original {1,10:F1} new {2,10:F1} ns per unit  ratio {3:F3} ({4:F3} to {5:F3})  original {6,8:F1} new {7,8:F1} B per unit",
                c.Id, p.Original.MedianNs / c.Units, p.New.MedianNs / c.Units, p.MedianRatio, p.Ratios.Min(), p.Ratios.Max(),
                BytesPerCall(c.Original) / c.Units, BytesPerCall(c.New) / c.Units));
        }
        Console.WriteLine("BENCH_NOISE " + NoiseBand.Describe(ratios.ToArray()));
        Console.WriteLine("CF ARM speed: UNMEASURED");
        if (!sameCode || NoiseBand.Inside(ratios.ToArray())) return 0;
        Console.WriteLine("BENCH_NOISE_OUTSIDE_BAND: the two copies are the same code, so a ratio outside the target band is harness or machine noise");
        return 6;
    }

    static List<Case> All(IBlockCases o, IBlockCases n) => new List<Case>
    {
        New("aes128.encrypt-block", 1, x => x.AesEncryptBlock(Key(16), Block(), new byte[16]), o, n),
        New("aes128.decrypt-block", 1, x => x.AesDecryptBlock(Key(16), Block(), new byte[16]), o, n),
        New("aes128.key-setup", 1, x => x.AesKeySetup(Key(16)), o, n),
        New("aes128.cbc-encrypt", 64, x => x.CbcEncrypt(Key(16), new byte[16], Msg()), o, n),
        New("aes128.ctr", 64, x => x.Ctr(Key(16), new byte[16], Msg()), o, n),
        New("aes128.gcm-seal", 64, x => x.GcmSeal(Key(16), new byte[12], new byte[0], Msg()), o, n),
        New("aes128.cmac", 64, x => x.Cmac(Key(16), Msg()), o, n),
        New("sha256.update", 64, x => x.HashUpdate("sha256", 64), o, n),
        New("hmac-sha256", 1, x => x.HmacSha256(Key(32), Msg()), o, n),
        New("tdes.encrypt-block", 1, x => x.TdesEncryptBlock(Key(24), Block(), new byte[16]), o, n),
    };

    static Case New(string id, int units, Func<IBlockCases, Action> make, IBlockCases o, IBlockCases n) =>
        new Case { Id = id, Units = units, Original = make(o), New = make(n) };

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
