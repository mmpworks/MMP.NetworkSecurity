using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NetSec.Crypto;

namespace NetSec.Bench;

/// <summary>
/// Runs every case in <see cref="Cases"/> and writes bench-&lt;build&gt;.json and bench-&lt;build&gt;.md to the --out folder.
/// Usage: NetSec.Bench --out DIR --head SHA [--filter TEXT], or with --mode files --files DIR for the AO-9 file benchmark (<see cref="Files.FilesMode"/>).
/// The head comes from the caller, so the report names the code it timed.
/// The run refuses to start on a Debug build or with a debugger attached, and when the AES-128 known answer of FIPS-197 C.1 fails.
/// </summary>
static class Program
{
    const string CfLine = "CF ARM speed: UNMEASURED";

    /// <summary>Warm-up time for each call on each copy before the first measurement (<see cref="Measure.PreWarm"/>).</summary>
    public static readonly TimeSpan PreWarmEach = TimeSpan.FromMilliseconds(500);

    static int Main(string[] args)
    {
        Dictionary<string, string> a = ParseArgs(args);
        if (!a.ContainsKey("out") || !a.ContainsKey("head")) { Console.Error.WriteLine("BENCH_USAGE: --out DIR --head SHA [--filter TEXT]"); return 2; }
        string refusal = Refusal();
        if (refusal != null) { Console.Error.WriteLine(refusal); return 3; }

        a.TryGetValue("mode", out string mode);
        if (mode == "ao-merge") return AoParts.Merge(a);
        if (mode == "settle") return SettleCheck(a);
        Run run = new Run { Build = BuildName(), Head = a["head"], Priority = Measure.RaisePriority(a.TryGetValue("core", out string core) ? int.Parse(core) : (int?)null), CfLine = CfLine };
        bool sameCode = a.TryGetValue("same-code", out string sc) && sc == "true";
        if (mode == "files") return Files.FilesMode.Run(a, run, sameCode);
        if (mode == "ao5") { AoAlloc.JsonRows(new Files.ProductCode()); return 0; }
        if (mode == "sizes") return Sizes.Run(a);
        if (mode == "footprint") return Footprint.Run(a, run);
        string filter = a.TryGetValue("filter", out string f) ? f : "";

        // --swap true times the product as "original" and the frozen copy as "new": a harness symmetry check. A bias that follows the
        // position is the harness; a bias that follows the copy is the code or its placement.
        bool swap = a.TryGetValue("swap", out string sw) && sw == "true";
        List<BenchCase> original = Cases.All(swap ? (IBlockCases)new Files.ProductCode() : new Files.FrozenCode()), current = Cases.All(swap ? (IBlockCases)new Files.FrozenCode() : new Files.ProductCode());
        if (swap) Console.WriteLine("BENCH_SWAP original = product, new = frozen copy (symmetry check; not a publishable run)");
        List<int> picked = Enumerable.Range(0, current.Count).Where(i => current[i].Id.Contains(filter)).ToList();
        Measure.PreWarm(picked.Select(i => new[] { original[i].Op, current[i].Op }), PreWarmEach);
        if (!MachineLoad.Settle()) return MachineLoad.BusyExit;
        List<CaseResult> results = new List<CaseResult>();
        for (int i = 0; i < current.Count; i++)
        {
            if (!current[i].Id.Contains(filter)) continue;
            results.Add(new CaseResult(current[i], Measure.Run(original[i].Op, current[i].Op, Report.BlockRound)));
            Console.WriteLine(Row(results[results.Count - 1]));
        }

        Directory.CreateDirectory(a["out"]);
        File.WriteAllText(Path.Combine(a["out"], "bench-" + run.Build + ".json"), Report.Json(run, results));
        File.WriteAllText(Path.Combine(a["out"], "bench-" + run.Build + ".md"), Report.Markdown(run, results));
        if (run.Build == "net10" && filter.Length == 0)
        {
            AoParts.Write(a["out"], "net10-blocks", Report.AoBlockRows(results));
            AoParts.Write(a["out"], "net10-alloc", AoAlloc.JsonRows(new Files.ProductCode()));
        }
        double[] ratios = results.Select(r => r.Pair.MedianRatio).ToArray();
        Console.WriteLine("BENCH_NOISE " + NoiseBand.Describe(ratios));
        Console.WriteLine(CfLine);
        Console.WriteLine("BENCH_DONE " + run.Build + " " + results.Count + " cases");
        int busy = MachineLoad.Exit(results.Select(r => r.Pair.OtherBusy).ToArray());
        int band = SameCodeExit(sameCode, ratios);
        return busy != 0 ? busy : band;
    }

    /// <summary>With --same-code true (an S0 run, where both copies are the 5c5d4a4 code), a ratio outside the target band fails the run.</summary>
    public static int SameCodeExit(bool sameCode, double[] ratios)
    {
        if (!sameCode || NoiseBand.Inside(ratios)) return 0;
        Console.WriteLine("BENCH_NOISE_OUTSIDE_BAND: the two copies are the same code, so a ratio outside the target band is harness or machine noise");
        return 6;
    }

    /// <summary>The build this process times: net10.0, or the CF binaries on the .NET Framework 4.8 desktop JIT.</summary>
    public static string BuildName()
    {
#if NETFRAMEWORK
        return "cf-binaries-on-net48";
#else
        return "net10";
#endif
    }

    static string Refusal()
    {
#if DEBUG
        return "BENCH_REFUSED: a Debug build gives no usable numbers. Run with -c Release.";
#else
        if (Debugger.IsAttached) return "BENCH_REFUSED: a debugger is attached.";
        if (!Stopwatch.IsHighResolution) return "BENCH_REFUSED: Stopwatch is not high resolution on this machine.";
        return AesKnownAnswer() ? null : "BENCH_REFUSED: the AES-128 known answer of FIPS-197 C.1 failed, so the code under test is wrong.";
#endif
    }

    static bool AesKnownAnswer()
    {
        byte[] key = new byte[16], plain = new byte[16], o = new byte[16];
        for (int i = 0; i < 16; i++) { key[i] = (byte)i; plain[i] = (byte)(i * 0x11); }
        new AesKey(key).EncryptBlock(plain, 0, o, 0);
        return BitConverter.ToString(o).Replace("-", "") == "69C4E0D86A7B0430D8CDB78070B4C55A";
    }

    static string Row(CaseResult r) => string.Format(CultureInfo.InvariantCulture,
        "{0,-34} original {1,10:F1} new {2,10:F1} ns/{3,-10} ratio {4,6:F3} ({5:F3} to {6:F3})  new {7,9:F1} B/{3}  load {8:P1} core {9:P1}",
        r.Case.Id, r.OriginalNsPerUnit, r.NewNsPerUnit, r.Case.Unit, r.Pair.MedianRatio, r.Pair.Ratios.Min(), r.Pair.Ratios.Max(), r.NewBytesPerUnit, r.Pair.OtherBusy, r.Pair.CoreBusy);

    /// <summary>The load check alone, for a run script and its self-check: settle, then with --hold N read N seconds and apply the pair rule.</summary>
    static int SettleCheck(Dictionary<string, string> a)
    {
        if (!MachineLoad.Settle()) return MachineLoad.BusyExit;
        int hold = a.TryGetValue("hold", out string h) ? int.Parse(h, CultureInfo.InvariantCulture) : 0;
        if (hold == 0) return 0;
        Console.WriteLine("PRIORITY " + Measure.RaisePriority(null));
        MachineLoad.Sample from = MachineLoad.Now();
        System.Threading.Thread.Sleep(TimeSpan.FromSeconds(hold));
        MachineLoad.Sample to = MachineLoad.Now();
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "BENCH_HOLD {0} s: load {1:P1}, core pair [{2}] {3:P1}",
            hold, MachineLoad.OtherBusy(from, to), string.Join(",", MachineLoad.CorePair.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToArray()), MachineLoad.CoreBusy(from, to)));
        return MachineLoad.Exit(new[] { MachineLoad.OtherBusy(from, to) });
    }

    static Dictionary<string, string> ParseArgs(string[] args)
    {
        Dictionary<string, string> a = new Dictionary<string, string>();
        for (int i = 0; i + 1 < args.Length; i += 2)
            if (args[i].StartsWith("--", StringComparison.Ordinal)) a[args[i].Substring(2)] = args[i + 1];
        return a;
    }

    public static string Machine() => string.Format(CultureInfo.InvariantCulture, "{0}; {1}; {2} logical processors; {3}",
        RuntimeInformation.OSDescription, RuntimeInformation.ProcessArchitecture, Environment.ProcessorCount, RuntimeInformation.FrameworkDescription);
}
