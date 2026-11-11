using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// The crossover for the block cases. A same-code swap check (2026-11-11) showed the harness position itself is worth about 12% on AES
/// encrypt-block: the copy timed as "new" ran faster whichever copy it was. So each block run is four processes in the order normal,
/// swapped, normal, swapped (--part normal1 / swapped1 / normal2 / swapped2; swapped times the product as "original"), and this step
/// combines them. A position ratio is original ns over new ns, so:
///   normal  N = bias x code          (code = frozen ns / product ns; above 1 means the product is faster)
///   swapped S = bias / code
///   code ratio    = sqrt(N / S)      with N = sqrt(N1 x N2) and S = sqrt(S1 x S2)
///   position bias = sqrt(N x S)
/// The bias of each normal/swapped process pair is sqrt(Nk x Sk). If the two pair biases differ by more than the same-code band
/// (their ratio outside NoiseBand.Low to High), the bias is not a fixed factor, the crossover does not cancel it, and the run fails
/// (exit 10, BENCH_BIAS_DRIFT). The band and the AO-6 rows read the code ratio only. Files and the CLR 2.0 hosts run one order.
/// </summary>
static class Crossover
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    public static readonly string[] Parts = { "normal1", "swapped1", "normal2", "swapped2" };
    public const int DriftExit = 10, PartExit = 11;

    public const string OneOrderNote = "The files mode and the CLR 2.0 hosts run one order. The position bias was measured on the net10 block "
        + "cases, where both copies run under the tiered JIT; CLR 2.0 has no tiered JIT, and the file rows time 250 ms rounds over whole files. "
        + "If the same-code band of either fails, it gets the crossover too.";

    sealed class Row
    {
        public string Id, Unit;
        public int UnitsPerOp, BytesPerOp;
        public double Ratio, FrozenNs, ProductNs, FrozenBytes, ProductBytes, Load, Core;
        public int CpuStart, CpuEnd;
    }

    sealed class Part
    {
        public string Tag;
        public Dictionary<string, string> Header = new Dictionary<string, string>();
        public List<Row> Rows = new List<Row>();
    }

    /// <summary>Writes one process's block rows as cross-&lt;build&gt;-&lt;tag&gt;.tsv. In a swapped part "original" is the product.</summary>
    public static void WritePart(string folder, Run run, string tag, bool swap, int pairs, IList<CaseResult> results)
    {
        StringBuilder s = new StringBuilder();
        s.Append("# head\t").Append(run.Head).Append('\n');
        s.Append("# build\t").Append(run.Build).Append('\n');
        s.Append("# order\t").Append(swap ? "swapped" : "normal").Append('\n');
        s.Append("# machine\t").Append(Program.Machine()).Append('\n');
        s.Append("# priority\t").Append(run.Priority).Append('\n');
        s.Append("# allocation\t").Append(Allocated.Method).Append('\n');
        s.Append("# timing\t").Append(Report.Settings(Report.BlockRound, pairs)).Append('\n');
        s.Append("# cf\t").Append(run.CfLine).Append('\n');
        s.Append("id\tunit\tunitsPerOp\tbytesPerOp\tpositionRatio\tfrozenNsPerUnit\tproductNsPerUnit\tfrozenBytesPerUnit\tproductBytesPerUnit\toutsideLoad\tcoreLoad\tcpuStart\tcpuEnd\n");
        foreach (CaseResult r in results)
        {
            double frozenNs = swap ? r.NewNsPerUnit : r.OriginalNsPerUnit, productNs = swap ? r.OriginalNsPerUnit : r.NewNsPerUnit;
            double frozenB = swap ? r.NewBytesPerUnit : r.OriginalBytesPerUnit, productB = swap ? r.OriginalBytesPerUnit : r.NewBytesPerUnit;
            s.Append(string.Format(Inv, "{0}\t{1}\t{2}\t{3}\t{4:R}\t{5:R}\t{6:R}\t{7:R}\t{8:R}\t{9:R}\t{10:R}\t{11}\t{12}\n",
                r.Case.Id, r.Case.Unit, r.Case.UnitsPerOp, r.Case.BytesPerOp, r.Pair.MedianRatio, frozenNs, productNs, frozenB, productB,
                r.Pair.OtherBusy, double.IsNaN(r.Pair.CoreBusy) ? -1 : r.Pair.CoreBusy, r.Pair.CpuStart, r.Pair.CpuEnd));
        }
        File.WriteAllText(Path.Combine(folder, "cross-" + run.Build + "-" + tag + ".tsv"), s.ToString());
    }

    /// <summary>
    /// --mode crossover --build NAME --out DIR [--same-code true]: reads the four parts, prints and writes bench-&lt;build&gt;.json and .md,
    /// and for net10 the AO-6 block part and the AO-5 alloc part. Exit 11 for a missing or mismatched part, 10 for bias drift, 6 for a
    /// code ratio outside the band (with --same-code true), else 0. The AO parts are written only on exit 0.
    /// </summary>
    public static int Combine(Dictionary<string, string> a)
    {
        if (!a.ContainsKey("build")) { Console.Error.WriteLine("BENCH_USAGE: --mode crossover --build NAME --out DIR [--same-code true]"); return 2; }
        string selfCheck = SelfCheck();
        if (selfCheck != null) { Console.WriteLine("BENCH_CROSSOVER_SELFCHECK_FAIL " + selfCheck); return PartExit; }
        string build = a["build"], folder = a["out"];
        bool sameCode = a.TryGetValue("same-code", out string sc) && sc == "true";
        List<Part> parts = new List<Part>();
        foreach (string tag in Parts)
        {
            string path = Path.Combine(folder, "cross-" + build + "-" + tag + ".tsv");
            if (!File.Exists(path)) { Console.WriteLine("BENCH_CROSSOVER_PART_MISSING " + path); return PartExit; }
            parts.Add(Read(tag, File.ReadAllLines(path)));
        }
        string mismatch = Mismatch(parts);
        if (mismatch != null) { Console.WriteLine("BENCH_CROSSOVER_PART_MISMATCH " + mismatch); return PartExit; }

        List<string> lines = new List<string>(), drifted = new List<string>();
        List<double> codes = new List<double>();
        List<Combined> rows = new List<Combined>();
        for (int i = 0; i < parts[0].Rows.Count; i++)
        {
            Combined c = Combine(parts.Select(p => p.Rows[i]).ToArray());
            rows.Add(c);
            codes.Add(c.Code);
            Console.WriteLine(c.Line());
            if (!(c.Drift >= NoiseBand.Low && c.Drift <= NoiseBand.High)) drifted.Add(c.Id);
        }

        Console.WriteLine("BENCH_NOISE crossover code ratio " + NoiseBand.Describe(codes.ToArray()));
        Console.WriteLine(string.Format(Inv, "BENCH_BIAS position bias {0:F3} to {1:F3}; pair-bias drift {2:F3} to {3:F3}; drift target {4:F2} to {5:F2}; rows drifting: {6}",
            rows.Min(r => r.Bias), rows.Max(r => r.Bias), rows.Min(r => r.Drift), rows.Max(r => r.Drift), NoiseBand.Low, NoiseBand.High, drifted.Count));
        File.WriteAllText(Path.Combine(folder, "bench-" + build + ".json"), Json(parts[0], rows));
        File.WriteAllText(Path.Combine(folder, "bench-" + build + ".md"), Markdown(parts[0], rows, codes.ToArray()));

        int exit = 0;
        if (drifted.Count > 0)
        {
            Console.WriteLine("BENCH_BIAS_DRIFT: the position bias moved between process pairs, so the crossover does not cancel it: " + string.Join(", ", drifted.ToArray()));
            exit = DriftExit;
        }
        else
        {
            exit = Program.SameCodeExit(sameCode, codes.ToArray());
        }
        if (exit == 0 && build == "net10")
        {
            AoParts.Write(folder, "net10-blocks", AoRows(rows));
            AoParts.Write(folder, "net10-alloc", AoAlloc.JsonRows(new Files.ProductCode()));
        }
        Console.WriteLine("BENCH_CROSSOVER_DONE " + build + " " + rows.Count + " cases, exit " + exit);
        return exit;
    }

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

    /// <summary>The pure combine for one case: parts in the order normal1, swapped1, normal2, swapped2.</summary>
    static Combined Combine(Row[] r)
    {
        double n = Math.Sqrt(r[0].Ratio * r[2].Ratio), s = Math.Sqrt(r[1].Ratio * r[3].Ratio);
        double p1 = r[0].Ratio * r[1].Ratio, p2 = r[2].Ratio * r[3].Ratio;
        return new Combined
        {
            Id = r[0].Id, Unit = r[0].Unit, UnitsPerOp = r[0].UnitsPerOp, BytesPerOp = r[0].BytesPerOp,
            N1 = r[0].Ratio, S1 = r[1].Ratio, N2 = r[2].Ratio, S2 = r[3].Ratio,
            Code = Math.Sqrt(n / s), Bias = Math.Sqrt(n * s), Pair1 = p1, Pair2 = p2, Drift = Math.Sqrt(p1) / Math.Sqrt(p2),
            FrozenNs = GeoMean(r.Select(x => x.FrozenNs)), ProductNs = GeoMean(r.Select(x => x.ProductNs)),
            FrozenBytes = r.Average(x => x.FrozenBytes), ProductBytes = r.Average(x => x.ProductBytes),
            MaxLoad = r.Max(x => x.Load), MaxCore = r.Max(x => x.Core),
            Cpus = string.Join(",", r.Select(x => x.CpuStart + ">" + x.CpuEnd).ToArray()),
        };
    }

    /// <summary>
    /// The combine math on synthetic parts with a known answer: bias 1.12 and code 1.05 give N = 1.176 and S = 1.0667, so the combine must
    /// return code 1.05, bias 1.12 and drift 1; a second pair with bias 1.30 must show drift 1.12 / 1.30. Null when every value holds.
    /// </summary>
    static string SelfCheck()
    {
        Row R(double ratio) => new Row { Id = "x", Unit = "u", Ratio = ratio, FrozenNs = 1, ProductNs = 1 };
        double b = 1.12, c = 1.05, b2 = 1.30;
        Combined steady = Combine(new[] { R(b * c), R(b / c), R(b * c), R(b / c) });
        Combined moved = Combine(new[] { R(b * c), R(b / c), R(b2 * c), R(b2 / c) });
        bool ok = Math.Abs(steady.Code - c) < 1e-12 && Math.Abs(steady.Bias - b) < 1e-12 && Math.Abs(steady.Drift - 1) < 1e-12
            && Math.Abs(moved.Drift - b / b2) < 1e-12 && Math.Abs(moved.Code - c) < 1e-12;
        return ok ? null : string.Format(Inv, "steady code {0} bias {1} drift {2}; moved drift {3} code {4}", steady.Code, steady.Bias, steady.Drift, moved.Drift, moved.Code);
    }

    static double GeoMean(IEnumerable<double> v) => Math.Exp(v.Select(x => Math.Log(x)).Average());

    static Part Read(string tag, string[] lines)
    {
        Part p = new Part { Tag = tag };
        foreach (string line in lines)
        {
            if (line.Length == 0 || line.StartsWith("id\t", StringComparison.Ordinal)) continue;
            string[] f = line.Split('\t');
            if (line.StartsWith("# ", StringComparison.Ordinal)) { p.Header[f[0].Substring(2)] = f.Length > 1 ? f[1] : ""; continue; }
            p.Rows.Add(new Row
            {
                Id = f[0], Unit = f[1], UnitsPerOp = int.Parse(f[2], Inv), BytesPerOp = int.Parse(f[3], Inv),
                Ratio = D(f[4]), FrozenNs = D(f[5]), ProductNs = D(f[6]), FrozenBytes = D(f[7]), ProductBytes = D(f[8]),
                Load = D(f[9]), Core = D(f[10]), CpuStart = int.Parse(f[11], Inv), CpuEnd = int.Parse(f[12], Inv),
            });
        }
        return p;
    }

    static double D(string v) => double.Parse(v, Inv);

    /// <summary>Null when the four parts are one crossover: one head and build, the expected order per tag, and the same cases in the same order.</summary>
    static string Mismatch(List<Part> parts)
    {
        foreach (Part p in parts)
        {
            string want = p.Tag.StartsWith("normal", StringComparison.Ordinal) ? "normal" : "swapped";
            if (!p.Header.TryGetValue("order", out string order) || order != want) return p.Tag + " has order " + order + ", wants " + want;
            if (p.Header["head"] != parts[0].Header["head"]) return p.Tag + " head " + p.Header["head"] + " differs from " + parts[0].Header["head"];
            if (p.Header["build"] != parts[0].Header["build"]) return p.Tag + " build differs";
            if (p.Rows.Count == 0) return p.Tag + " has no rows";
            if (!p.Rows.Select(r => r.Id).SequenceEqual(parts[0].Rows.Select(r => r.Id))) return p.Tag + " has other cases than " + parts[0].Tag;
        }
        return null;
    }

    /// <summary>AO-6 rows (acceptance/ao-bench-schema.md). baseline is the frozen ns (geometric mean of the four parts); new is
    /// baseline / code ratio, so the suite's ratio is the code ratio and carries no position bias.</summary>
    static List<string> AoRows(List<Combined> rows)
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

    const string Formula = "normal N = bias x code; swapped S = bias / code; code ratio = sqrt(N / S) and position bias = sqrt(N x S), "
        + "with N = sqrt(N1 x N2) and S = sqrt(S1 x S2). A position ratio is original ns over new ns; a swapped part times the product as "
        + "\"original\". Code ratio above 1 means the product is faster. Pair bias k = sqrt(Nk x Sk); drift = pair bias 1 / pair bias 2, "
        + "and a drift outside the same-code band fails the run.";

    static string Json(Part first, List<Combined> rows)
    {
        StringBuilder s = new StringBuilder("{\n");
        void Field(string name, string value) => s.Append("  ").Append(Report.Quote(name)).Append(": ").Append(Report.Quote(value)).Append(",\n");
        Field("schema", "netsec-bench/3-crossover");
        foreach (string k in new[] { "build", "head", "machine", "priority", "allocation", "timing", "cf" }) Field(k, first.Header.TryGetValue(k, out string v) ? v : "");
        Field("utc", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", Inv));
        Field("crossover", "4 processes: " + string.Join(", ", Parts) + ". " + Formula);
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

    static string Markdown(Part first, List<Combined> rows, double[] codes)
    {
        StringBuilder s = new StringBuilder();
        string H(string k) => first.Header.TryGetValue(k, out string v) ? v : "";
        s.AppendLine("# Benchmark: " + H("build") + " (crossover)");
        s.AppendLine();
        s.AppendLine("- Head: `" + H("head") + "`");
        s.AppendLine("- Machine: " + H("machine"));
        s.AppendLine("- Timing per process: " + H("timing"));
        s.AppendLine("- Priority: " + H("priority"));
        s.AppendLine("- Allocation counter: " + H("allocation") + ". Allocated bytes cover the timed rounds only.");
        s.AppendLine("- Crossover: 4 processes (" + string.Join(", ", Parts) + "). " + Formula);
        s.AppendLine("- Noise (code ratio): " + NoiseBand.Describe(codes));
        s.AppendLine("- " + OneOrderNote);
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
