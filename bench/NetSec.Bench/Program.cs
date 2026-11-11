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

    static int Main(string[] args)
    {
        Dictionary<string, string> a = ParseArgs(args);
        if (!a.ContainsKey("out") || !a.ContainsKey("head")) { Console.Error.WriteLine("BENCH_USAGE: --out DIR --head SHA [--filter TEXT]"); return 2; }
        string refusal = Refusal();
        if (refusal != null) { Console.Error.WriteLine(refusal); return 3; }

        string build = BuildName();
        a.TryGetValue("mode", out string mode);
        if (mode == "files") return Files.FilesMode.Run(a, build, CfLine);
        if (mode == "ao-merge") return AoParts.Merge(a);
        string filter = a.TryGetValue("filter", out string f) ? f : "";

        // Each case runs on the frozen copy, then at once on the product, so a slow spell on the machine hits both columns alike.
        List<BenchCase> original = Cases.All(new Files.FrozenCode()), current = Cases.All(new Files.ProductCode());
        List<CaseResult> baseline = new List<CaseResult>(), results = new List<CaseResult>();
        for (int i = 0; i < current.Count; i++)
        {
            if (!current[i].Id.Contains(filter)) continue;
            baseline.Add(Measure.Run(original[i]));
            results.Add(Measure.Run(current[i]));
            Console.WriteLine(Row(results[results.Count - 1]) + string.Format(CultureInfo.InvariantCulture, "   original {0,10:F1} ns", baseline[baseline.Count - 1].MedianNsPerUnit));
        }

        Directory.CreateDirectory(a["out"]);
        File.WriteAllText(Path.Combine(a["out"], "bench-" + build + ".json"), Report.Json(build, a["head"], results, CfLine));
        File.WriteAllText(Path.Combine(a["out"], "bench-" + build + ".md"), Report.Markdown(build, a["head"], baseline, results, CfLine));
        if (build == "net10") AoParts.Write(a["out"], "net10-blocks", Report.AoBlockRows(baseline, results));
        Console.WriteLine(CfLine);
        Console.WriteLine("BENCH_DONE " + build + " " + results.Count + " cases");
        return 0;
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
        "{0,-34} {1,10:F1} ns/{2,-10} {3,9:F1} B/{2,-10} {4,9:F1} MB/s",
        r.Case.Id, r.MedianNsPerUnit, r.Case.Unit, r.BytesAllocatedPerUnit, r.MegabytesPerSecond);

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
