using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// Writes the block results as JSON (for a check to read) and as Markdown (for a person). Both carry the provenance: the build, the head,
/// the machine, the timing settings, the priority, the allocation counter, the same-code band, and the CF line. The JSON is written by hand
/// because the net48 build has no JSON serializer in its base library, and this project adds no package.
/// </summary>
static class Report
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    public static readonly TimeSpan BlockRound = TimeSpan.FromMilliseconds(150);

    public static string Json(Run run, IList<CaseResult> results)
    {
        StringBuilder s = new StringBuilder();
        s.Append("{\n");
        Field(s, "schema", "netsec-bench/2");
        Field(s, "build", run.Build);
        Field(s, "head", run.Head);
        Field(s, "utc", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", Inv));
        Field(s, "machine", Program.Machine());
        Field(s, "allocationCounter", Allocated.Method);
        Field(s, "timing", Settings(BlockRound, Measure.Rounds));
        Field(s, "priority", run.Priority);
        Field(s, "noiseBand", NoiseBand.Describe(results.Select(r => r.Pair.MedianRatio).ToArray()));
        Field(s, "cfArm", run.CfLine);
        s.Append("  \"cases\": [\n");
        for (int i = 0; i < results.Count; i++)
        {
            CaseResult r = results[i];
            s.Append("    {");
            s.AppendFormat(Inv, "\"id\": {0}, \"unit\": {1}, \"unitsPerOp\": {2}, \"bytesPerOp\": {3}, \"callsPerRound\": {4}, ",
                Quote(r.Case.Id), Quote(r.Case.Unit), r.Case.UnitsPerOp, r.Case.BytesPerOp, r.Pair.CallsPerRound);
            s.AppendFormat(Inv, "\"originalNsPerUnit\": {0:F2}, \"newNsPerUnit\": {1:F2}, \"ratio\": {2:F4}, \"originalBytesPerUnit\": {3:F2}, \"newBytesPerUnit\": {4:F2}, ",
                r.OriginalNsPerUnit, r.NewNsPerUnit, r.Pair.MedianRatio, r.OriginalBytesPerUnit, r.NewBytesPerUnit);
            s.AppendFormat(Inv, "\"ratioRounds\": [{0}]", string.Join(", ", r.Pair.Ratios.Select(v => v.ToString("F4", Inv))));
            s.Append(i + 1 < results.Count ? "},\n" : "}\n");
        }
        s.Append("  ]\n}\n");
        return s.ToString();
    }

    /// <summary>
    /// The AO-6 rows of acceptance/ao-bench-schema.md: frozen and product ns per operation, for each case in <see cref="Cases.AoId"/>.
    /// Numbers only; the suite judges them. <see cref="AoParts"/> writes them. The AO-5 rows come from <see cref="AoAlloc"/>.
    /// </summary>
    public static List<string> AoBlockRows(IList<CaseResult> results)
    {
        List<string> rows = new List<string>();
        foreach (CaseResult r in results)
        {
            if (!Cases.AoId.TryGetValue(r.Case.Id, out var ao)) continue;
            rows.Add(string.Format(Inv, "{{ \"id\": \"AO-6.{0}.net10\", \"baselineNsPerOp\": {1:F2}, \"newNsPerOp\": {2:F2}, \"op\": {3} }}",
                ao.Row, r.OriginalNsPerUnit, r.NewNsPerUnit, Quote(ao.Op)));
        }
        return rows;
    }

    /// <summary>CPU name and logical processor count, as the schema asks. The machine name is left out, because the report is public.</summary>
    public static string Cpu() => (Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "unknown CPU") + "; " + Environment.ProcessorCount + " logical processors";

    /// <summary>The provenance lines both Markdown reports start with.</summary>
    public static void Header(StringBuilder s, Run run, TimeSpan round, int rounds, string noise)
    {
        s.AppendLine("- Head: `" + run.Head + "`");
        s.AppendLine("- Machine: " + Program.Machine());
        s.AppendLine("- Timing: " + Settings(round, rounds));
        s.AppendLine("- Priority: " + run.Priority);
        s.AppendLine("- Allocation counter: " + Allocated.Method + ". Allocated bytes and GC counts cover the timed rounds only.");
        s.AppendLine("- Noise: " + noise);
        s.AppendLine("- " + run.CfLine);
        s.AppendLine();
        s.AppendLine("Original is Echo's frozen 5c5d4a4 copy; new is the product at the head. Ratio is the median of the per-round-pair ratios "
            + "(original ns over new ns), so above 1 means the new code is faster.");
        s.AppendLine();
    }

    public static string Markdown(Run run, IList<CaseResult> results)
    {
        StringBuilder s = new StringBuilder();
        s.AppendLine("# Benchmark: " + run.Build);
        s.AppendLine();
        Header(s, run, BlockRound, Measure.Rounds, NoiseBand.Describe(results.Select(r => r.Pair.MedianRatio).ToArray()));
        s.AppendLine("| Case | Unit | Original ns per unit | New ns per unit | Ratio | Ratio spread of round pairs | New spread ns | Original B per unit | New B per unit | New MB/s |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|");
        foreach (CaseResult r in results)
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F1} | {3:F1} | {4:F3} | {5:F3} to {6:F3} | {7:F1} to {8:F1} | {9:F1} | {10:F1} | {11} |",
                r.Case.Id, r.Case.Unit, r.OriginalNsPerUnit, r.NewNsPerUnit, r.Pair.MedianRatio, r.Pair.Ratios.Min(), r.Pair.Ratios.Max(),
                r.NewLowNsPerUnit, r.NewHighNsPerUnit, r.OriginalBytesPerUnit, r.NewBytesPerUnit,
                r.Case.BytesPerOp == 0 ? "n/a" : r.NewMegabytesPerSecond.ToString("F1", Inv)));
        return s.ToString();
    }

    public static string Settings(TimeSpan round, int rounds) => string.Format(Inv,
        "warm-up {0} ms per copy, then {1} round pairs of at least {2} ms per copy; original and new alternate (O,N then N,O); a full GC before each timed round; Stopwatch {3} ticks/s",
        Measure.WarmTarget.TotalMilliseconds, rounds, round.TotalMilliseconds, System.Diagnostics.Stopwatch.Frequency);

    static void Field(StringBuilder s, string name, string value) => s.Append("  ").Append(Quote(name)).Append(": ").Append(Quote(value)).Append(",\n");

    public static string Quote(string v)
    {
        StringBuilder q = new StringBuilder("\"");
        foreach (char c in v)
        {
            if (c == '"' || c == '\\') q.Append('\\').Append(c);
            else if (c < 0x20) q.AppendFormat(Inv, "\\u{0:x4}", (int)c);
            else q.Append(c);
        }
        return q.Append('"').ToString();
    }
}
