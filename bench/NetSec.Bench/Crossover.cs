using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// The balanced crossover: position x JIT order, for every timing host. Two same-code checks (2026-11-11) found two harness effects:
/// the copy timed as "new" ran AES encrypt-block about 12% faster on net10 whichever copy it was (position), and on the non-tiering
/// JITs the copy compiled second ran SHA-256 faster (JIT order: about 5% on net48, about 36% on 32-bit CLR 2.0). Each run is four
/// processes, normal1 / swapped1 / normal2 / swapped2 (CrossoverPart sets the arrangement from the tag), combined here.
/// A position ratio is original ns over new ns, so with c = frozen ns / product ns (above 1: the product is faster):
///   N = sqrt(N1 x N2), S = sqrt(S1 x S2)   (each holds one part of each JIT order, so a multiplicative JIT effect cancels)
///   code ratio = sqrt(N / S), position bias = sqrt(N x S)
/// Pair k (normal k with swapped k) gives its own bias sqrt(Nk x Sk); drift = pair bias 1 / pair bias 2. A drift outside the same-code
/// band means the effects do not multiply out, so the crossover cannot cancel them, and the run fails (exit 10, BENCH_BIAS_DRIFT).
/// The band and the AO rows read the code ratio only.
/// </summary>
static class Crossover
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    public const int DriftExit = 10, PartExit = 11;

    const string Formula = "N = sqrt(N1 x N2) and S = sqrt(S1 x S2), where a position ratio is original ns over new ns and a swapped part times "
        + "the product as \"original\"; normal1 and swapped1 compile the frozen copy first, normal2 and swapped2 the product. "
        + "Code ratio = sqrt(N / S) (above 1: the product is faster); position bias = sqrt(N x S). Pair bias k = sqrt(Nk x Sk); "
        + "drift = pair bias 1 / pair bias 2, and a drift outside the same-code band fails the run.";

    sealed class Combined
    {
        public string Id, Unit;
        public int UnitsPerOp, BytesPerOp;
        public double N1, S1, N2, S2, Code, Bias, Pair1, Pair2, Drift, FrozenNs, ProductNs, FrozenBytes, ProductBytes, MaxLoad, MaxCore;
        public string Cpus;

        public string Line() => string.Format(Inv,
            "{0,-34} normal {1:F3} {2:F3} swapped {3:F3} {4:F3}  code {5:F3} bias {6:F3}  NxS {7:F3} {8:F3} drift {9:F3}  frozen {10:F1} product {11:F1} ns/{12}  load max {13:P1} cpu {14}",
            Id, N1, N2, S1, S2, Code, Bias, Pair1, Pair2, Drift, FrozenNs, ProductNs, Unit, MaxLoad, Cpus);
    }

    /// <summary>
    /// --mode crossover --build NAME --out DIR [--same-code true]. NAME is the build of the parts: net10 and cf-binaries-on-net48 (blocks),
    /// net10-files and cf-binaries-on-net48-files (files), cf-binaries-on-net35-clr2-x86 and -x64 (CLR 2.0). Writes bench-NAME.json and
    /// .md; on exit 0 also the AO part of that build (AO-6 blocks and AO-5 alloc for net10, AO-9 for a files build).
    /// Exit 11 for a missing or mismatched part or a failed self-check, 10 for drift, 6 for a code ratio outside the band, else 0.
    /// </summary>
    public static int Combine(Dictionary<string, string> a)
    {
        string selfCheck = SelfCheck();
        if (selfCheck != null) { Console.WriteLine("BENCH_CROSSOVER_SELFCHECK_FAIL " + selfCheck); return PartExit; }
        if (!a.ContainsKey("build")) { Console.Error.WriteLine("BENCH_USAGE: --mode crossover --build NAME --out DIR [--same-code true]"); return 2; }
        string build = a["build"], folder = a["out"];
        bool sameCode = a.TryGetValue("same-code", out string sc) && sc == "true";
        List<PartFile> parts = new List<PartFile>();
        foreach (string tag in CrossoverPart.Tags)
        {
            string path = Path.Combine(folder, CrossoverPart.FileName(build, tag));
            if (!File.Exists(path)) { Console.WriteLine("BENCH_CROSSOVER_PART_MISSING " + path); return PartExit; }
            parts.Add(CrossoverPart.Read(tag, File.ReadAllLines(path)));
        }
        string mismatch = Mismatch(parts, build);
        if (mismatch != null) { Console.WriteLine("BENCH_CROSSOVER_PART_MISMATCH " + mismatch); return PartExit; }

        List<Combined> rows = new List<Combined>();
        for (int i = 0; i < parts[0].Rows.Count; i++)
        {
            Combined c = Combine(parts.Select(p => p.Rows[i]).ToArray());
            rows.Add(c);
            Console.WriteLine(c.Line());
        }
        double[] codes = rows.Select(r => r.Code).ToArray();
        List<string> drifted = rows.Where(r => !(r.Drift >= NoiseBand.Low && r.Drift <= NoiseBand.High)).Select(r => r.Id).ToList();
        Console.WriteLine("BENCH_NOISE crossover code ratio " + NoiseBand.Describe(codes));
        Console.WriteLine(string.Format(Inv, "BENCH_BIAS position bias {0:F3} to {1:F3}; pair-bias drift {2:F3} to {3:F3}; drift target {4:F2} to {5:F2}; rows drifting: {6}",
            rows.Min(r => r.Bias), rows.Max(r => r.Bias), rows.Min(r => r.Drift), rows.Max(r => r.Drift), NoiseBand.Low, NoiseBand.High, drifted.Count));
        File.WriteAllText(Path.Combine(folder, "bench-" + build + ".json"), Json(parts[0], rows));
        File.WriteAllText(Path.Combine(folder, "bench-" + build + ".md"), Markdown(parts[0], rows, codes));

        int exit;
        if (drifted.Count > 0)
        {
            Console.WriteLine("BENCH_BIAS_DRIFT: the bias moved between process pairs, so the crossover does not cancel it: " + string.Join(", ", drifted.ToArray()));
            exit = DriftExit;
        }
        else exit = Program.SameCodeExit(sameCode, codes);
        if (exit == 0) exit = WriteAo(folder, build, rows);
        Console.WriteLine("BENCH_CROSSOVER_DONE " + build + " " + rows.Count + " cases, exit " + exit);
        return exit;
    }

    /// <summary>The AO part of a build, from the code ratios. Returns non-zero when a needed input (the thread part) is missing.</summary>
    static int WriteAo(string folder, string build, List<Combined> rows)
    {
        if (build == "net10")
        {
            AoParts.Write(folder, "net10-blocks", AoBlockRows(rows));
            AoParts.Write(folder, "net10-alloc", AoAlloc.JsonRows(new Files.ProductCode()));
        }
        else if (build.EndsWith("-files", StringComparison.Ordinal))
        {
            string runtime = build.Substring(0, build.Length - "-files".Length);
            if (!Files.AoFileRows.AllOps.All(op => rows.Any(r => r.Id.EndsWith("|" + op, StringComparison.Ordinal))))
            {
                Console.WriteLine("BENCH_AO_SKIPPED " + build + ": the parts hold only some AO-9 operations (an --ops check), so no AO-9 part is written");
                return 0;
            }
            string threadsPath = Path.Combine(folder, Files.FilesMode.ThreadPartName(build));
            if (!File.Exists(threadsPath)) { Console.WriteLine("BENCH_CROSSOVER_PART_MISSING " + threadsPath); return PartExit; }
            List<Files.ThreadRow> threads = Files.FilesMode.ReadThreads(File.ReadAllLines(threadsPath));
            Func<string[], (double, double)> sums = ops =>
            {
                List<Combined> picked = rows.Where(r => ops.Contains(r.Id.Split('|')[1])).ToList();
                return (picked.Sum(r => r.FrozenNs), picked.Sum(r => r.FrozenNs / r.Code));
            };
            Combined small = rows.Single(r => r.Id == Files.FilesMode.SmallId);
            int files = rows.Where(r => r.Id != Files.FilesMode.SmallId).Select(r => r.Id.Split('|')[0]).Distinct().Count();
            AoParts.Write(folder, runtime + "-files", Files.AoFileRows.Rows(runtime, sums, files, small.FrozenNs, small.FrozenNs / small.Code, threads));
        }
        return 0;
    }

    /// <summary>The pure combine for one case: parts in the order normal1, swapped1, normal2, swapped2.</summary>
    static Combined Combine(PartRow[] r)
    {
        double n = Math.Sqrt(r[0].Ratio * r[2].Ratio), s = Math.Sqrt(r[1].Ratio * r[3].Ratio);
        double p1 = r[0].Ratio * r[1].Ratio, p2 = r[2].Ratio * r[3].Ratio;
        return new Combined
        {
            Id = r[0].Id, Unit = r[0].Unit, UnitsPerOp = r[0].UnitsPerOp, BytesPerOp = r[0].BytesPerOp,
            N1 = r[0].Ratio, S1 = r[1].Ratio, N2 = r[2].Ratio, S2 = r[3].Ratio,
            Code = Math.Sqrt(n / s), Bias = Math.Sqrt(n * s), Pair1 = p1, Pair2 = p2, Drift = Math.Sqrt(p1) / Math.Sqrt(p2),
            FrozenNs = GeoMean(r.Select(x => x.FrozenNs)), ProductNs = GeoMean(r.Select(x => x.ProductNs)),
            // -1 when a part could not measure bytes (the CLR 2.0 GC pass gives NaN when one call collects); JSON has no NaN.
            FrozenBytes = Measured(r.Average(x => x.FrozenBytes)), ProductBytes = Measured(r.Average(x => x.ProductBytes)),
            MaxLoad = r.Max(x => x.Load), MaxCore = r.Max(x => x.Core),
            Cpus = string.Join(",", r.Select(x => x.CpuStart + ">" + x.CpuEnd).ToArray()),
        };
    }

    /// <summary>
    /// The combine on synthetic parts with a known answer. Position bias 1.12, JIT factor 1.36 (the second-compiled copy faster) and code
    /// 1.05: normal1 (frozen first) = 1.12 x 1.36 x 1.05, swapped1 (frozen first, so the product, compiled second, sits in "original") =
    /// 1.12 / 1.36 / 1.05, normal2 = 1.12 / 1.36 x 1.05, swapped2 = 1.12 x 1.36 / 1.05. The combine must return code 1.05, bias 1.12 and
    /// drift 1; a second pair with bias 1.30 must show drift 1.12 / 1.30. Null when every value holds.
    /// </summary>
    static string SelfCheck()
    {
        PartRow R(double ratio) => new PartRow { Id = "x", Unit = "u", Ratio = ratio, FrozenNs = 1, ProductNs = 1 };
        double b = 1.12, j = 1.36, c = 1.05, b2 = 1.30;
        Combined steady = Combine(new[] { R(b * j * c), R(b / j / c), R(b / j * c), R(b * j / c) });
        Combined moved = Combine(new[] { R(b * j * c), R(b / j / c), R(b2 / j * c), R(b2 * j / c) });
        bool ok = Math.Abs(steady.Code - c) < 1e-12 && Math.Abs(steady.Bias - b) < 1e-12 && Math.Abs(steady.Drift - 1) < 1e-12
            && Math.Abs(moved.Drift - b / b2) < 1e-12 && Math.Abs(moved.Code - c) < 1e-12;
        return ok ? null : string.Format(Inv, "steady code {0} bias {1} drift {2}; moved drift {3} code {4}", steady.Code, steady.Bias, steady.Drift, moved.Drift, moved.Code);
    }

    static double Measured(double v) => double.IsNaN(v) ? -1 : v;

    static double GeoMean(IEnumerable<double> v) => Math.Exp(v.Select(x => Math.Log(x)).Average());

    /// <summary>Null when the four parts are one crossover: the build asked for, one head, the arrangement each tag sets, and the same cases in the same order.</summary>
    static string Mismatch(List<PartFile> parts, string build)
    {
        foreach (PartFile p in parts)
        {
            string H(string k) => p.Header.TryGetValue(k, out string v) ? v : "(none)";
            if (H("build") != build) return p.Tag + " build " + H("build") + ", wants " + build;
            if (H("order") != (CrossoverPart.Swapped(p.Tag) ? "swapped" : "normal")) return p.Tag + " order " + H("order");
            if (H("jit-first") != CrossoverPart.JitFirst(p.Tag)) return p.Tag + " jit-first " + H("jit-first") + ", wants " + CrossoverPart.JitFirst(p.Tag);
            if (H("head") != parts[0].Header["head"]) return p.Tag + " head " + H("head") + " differs from " + parts[0].Header["head"];
            if (p.Rows.Count == 0) return p.Tag + " has no rows";
            if (!p.Rows.Select(r => r.Id).SequenceEqual(parts[0].Rows.Select(r => r.Id))) return p.Tag + " has other cases than " + parts[0].Tag;
        }
        return null;
    }

    /// <summary>AO-6 rows (acceptance/ao-bench-schema.md): baseline = frozen ns (geometric mean of the four parts), new = baseline / code
    /// ratio, so the suite's ratio is the code ratio.</summary>
    static List<string> AoBlockRows(List<Combined> rows)
    {
        List<string> ao = new List<string>();
        foreach (Combined c in rows)
        {
            if (!Cases.AoId.TryGetValue(c.Id, out var id)) continue;
            ao.Add(string.Format(Inv, "{{ \"id\": \"AO-6.{0}.net10\", \"baselineNsPerOp\": {1:F2}, \"newNsPerOp\": {2:F2}, \"op\": {3} }}",
                id.Row, c.FrozenNs, c.FrozenNs / c.Code, Report.Quote(id.Op)));
        }
        return ao;
    }

    static string Json(PartFile first, List<Combined> rows)
    {
        StringBuilder s = new StringBuilder("{\n");
        void Field(string name, string value) => s.Append("  ").Append(Report.Quote(name)).Append(": ").Append(Report.Quote(value)).Append(",\n");
        Field("schema", "netsec-bench/4-crossover");
        foreach (string k in new[] { "build", "head", "machine", "priority", "allocation", "timing", "cf" }) Field(k, first.Header.TryGetValue(k, out string v) ? v : "");
        Field("utc", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", Inv));
        Field("crossover", "4 processes: " + string.Join(", ", CrossoverPart.Tags) + ". " + Formula);
        Field("noiseBand", NoiseBand.Describe(rows.Select(r => r.Code).ToArray()));
        s.Append("  \"cases\": [\n");
        for (int i = 0; i < rows.Count; i++)
        {
            Combined c = rows[i];
            s.Append(string.Format(Inv,
                "    {{\"id\": {0}, \"unit\": {1}, \"unitsPerOp\": {2}, \"bytesPerOp\": {3}, \"normal\": [{4:F4}, {5:F4}], \"swapped\": [{6:F4}, {7:F4}], "
                + "\"ratio\": {8:F4}, \"positionBias\": {9:F4}, \"normalTimesSwapped\": [{10:F4}, {11:F4}], \"biasDrift\": {12:F4}, "
                + "\"originalNsPerUnit\": {13:F2}, \"newNsPerUnit\": {14:F2}, \"originalBytesPerUnit\": {15:F2}, \"newBytesPerUnit\": {16:F2}, "
                + "\"maxOutsideLoad\": {17:F4}, \"maxCoreLoad\": {18:F4}, \"cpu\": {19}}}",
                Report.Quote(c.Id), Report.Quote(c.Unit), c.UnitsPerOp, c.BytesPerOp, c.N1, c.N2, c.S1, c.S2, c.Code, c.Bias, c.Pair1, c.Pair2, c.Drift,
                c.FrozenNs, c.ProductNs, c.FrozenBytes, c.ProductBytes, c.MaxLoad, c.MaxCore, Report.Quote(c.Cpus)));
            s.Append(i + 1 < rows.Count ? ",\n" : "\n");
        }
        s.Append("  ]\n}\n");
        return s.ToString();
    }

    static string Markdown(PartFile first, List<Combined> rows, double[] codes)
    {
        StringBuilder s = new StringBuilder();
        string H(string k) => first.Header.TryGetValue(k, out string v) ? v : "";
        s.AppendLine("# Benchmark: " + H("build") + " (crossover)");
        s.AppendLine();
        s.AppendLine("- Head: `" + H("head") + "`");
        s.AppendLine("- Machine: " + H("machine"));
        s.AppendLine("- Timing per process: " + H("timing"));
        s.AppendLine("- Priority: " + H("priority"));
        s.AppendLine("- Allocation counter: " + H("allocation"));
        s.AppendLine("- Crossover: 4 processes (" + string.Join(", ", CrossoverPart.Tags) + "). " + Formula);
        s.AppendLine("- Noise (code ratio): " + NoiseBand.Describe(codes));
        s.AppendLine("- " + H("cf"));
        s.AppendLine();
        s.AppendLine("Frozen is Echo's frozen 5c5d4a4 copy; product is the code at the head. Frozen and product ns are the geometric mean over the four processes.");
        s.AppendLine();
        s.AppendLine("| Case | Unit | Normal N1, N2 | Swapped S1, S2 | Code ratio | Position bias | N x S per pair | Bias drift | Frozen ns per unit | Product ns per unit | Product B per unit | Max outside load | CPU (start>end per part) |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|");
        foreach (Combined c in rows)
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F3}, {3:F3} | {4:F3}, {5:F3} | {6:F3} | {7:F3} | {8:F3}, {9:F3} | {10:F3} | {11:F1} | {12:F1} | {13:F1} | {14:P1} | {15} |",
                c.Id, c.Unit, c.N1, c.N2, c.S1, c.S2, c.Code, c.Bias, c.Pair1, c.Pair2, c.Drift, c.FrozenNs, c.ProductNs, c.ProductBytes, c.MaxLoad, c.Cpus));
        return s.ToString();
    }
}
