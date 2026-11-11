using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// Writes the results as JSON (for a check to read) and as Markdown (for a person). Both carry the provenance: the build, the head,
/// the machine, the timing settings, the allocation counter, and the CF line. The JSON is written by hand because the net48 build has no
/// JSON serializer in its base library, and this project adds no package.
/// </summary>
static class Report
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Json(string build, string head, IList<CaseResult> results, string cfLine)
    {
        StringBuilder s = new StringBuilder();
        s.Append("{\n");
        Field(s, "schema", "netsec-bench/1");
        Field(s, "build", build);
        Field(s, "head", head);
        Field(s, "utc", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", Inv));
        Field(s, "machine", Program.Machine());
        Field(s, "allocationCounter", Allocated.Method);
        Field(s, "timing", Settings());
        Field(s, "cfArm", cfLine);
        s.Append("  \"cases\": [\n");
        for (int i = 0; i < results.Count; i++)
        {
            CaseResult r = results[i];
            s.Append("    {");
            s.AppendFormat(Inv, "\"id\": {0}, \"unit\": {1}, \"unitsPerOp\": {2}, \"bytesPerOp\": {3}, ",
                Quote(r.Case.Id), Quote(r.Case.Unit), r.Case.UnitsPerOp, r.Case.BytesPerOp);
            s.AppendFormat(Inv, "\"nsPerUnit\": {0:F2}, \"bytesAllocatedPerUnit\": {1:F2}, \"bytesAllocatedPerOp\": {2:F2}, \"mbPerSecond\": {3:F2}, ",
                r.MedianNsPerUnit, r.BytesAllocatedPerUnit, r.BytesAllocatedPerOp, r.MegabytesPerSecond);
            s.AppendFormat(Inv, "\"opsPerRound\": {0}, \"nsPerOpRounds\": [{1}]", r.OpsPerRound,
                string.Join(", ", r.NsPerOpRounds.Select(v => v.ToString("F2", Inv))));
            s.Append(i + 1 < results.Count ? "},\n" : "}\n");
        }
        s.Append("  ]\n}\n");
        return s.ToString();
    }

    /// <summary>
    /// The AO-5 and AO-6 rows of acceptance/ao-bench-schema.md: one AO-5 row (bytes per operation, product) and one AO-6 row (frozen and
    /// product ns per operation) for each case in <see cref="Cases.AoId"/>. Numbers only; the suite judges them. <see cref="AoParts"/> writes them.
    /// </summary>
    public static List<string> AoBlockRows(IList<CaseResult> baseline, IList<CaseResult> results)
    {
        List<string> rows = new List<string>();
        for (int i = 0; i < results.Count; i++)
        {
            if (!Cases.AoId.TryGetValue(results[i].Case.Id, out var ao)) continue;
            if (ao.Row != "aes-key-setup")
                rows.Add(string.Format(Inv, "{{ \"id\": \"AO-5.{0}.net10\", \"bytesPerOp\": {1:F2}, \"op\": {2} }}", ao.Row, results[i].BytesAllocatedPerUnit, Quote(ao.Op)));
            rows.Add(string.Format(Inv, "{{ \"id\": \"AO-6.{0}.net10\", \"baselineNsPerOp\": {1:F2}, \"newNsPerOp\": {2:F2}, \"op\": {3} }}",
                ao.Row, baseline[i].MedianNsPerUnit, results[i].MedianNsPerUnit, Quote(ao.Op)));
        }
        return rows;
    }

    /// <summary>CPU name and logical processor count, as the schema asks. The machine name is left out, because the report is public.</summary>
    public static string Cpu() => (Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "unknown CPU") + "; " + Environment.ProcessorCount + " logical processors";

    public static string Markdown(string build, string head, IList<CaseResult> baseline, IList<CaseResult> results, string cfLine)
    {
        StringBuilder s = new StringBuilder();
        s.AppendLine("# Benchmark: " + build);
        s.AppendLine();
        s.AppendLine("- Head: `" + head + "`");
        s.AppendLine("- Machine: " + Program.Machine());
        s.AppendLine("- Timing: " + Settings());
        s.AppendLine("- Allocation counter: " + Allocated.Method);
        s.AppendLine("- " + cfLine);
        s.AppendLine();
        s.AppendLine("Original is Echo's frozen 5c5d4a4 copy; new is the product at the head. Ratio is original ns over new ns, so above 1 means the new code is faster.");
        s.AppendLine();
        s.AppendLine("| Case | Unit | Original ns per unit | New ns per unit | Ratio | New spread of rounds | Original B per unit | New B per unit | New MB/s |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|");
        for (int i = 0; i < results.Count; i++)
        {
            CaseResult o = baseline[i], r = results[i];
            double lo = r.NsPerOpRounds.Min() / r.Case.UnitsPerOp, hi = r.NsPerOpRounds.Max() / r.Case.UnitsPerOp;
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F1} | {3:F1} | {4:F2} | {5:F1} to {6:F1} | {7:F1} | {8:F1} | {9} |",
                r.Case.Id, r.Case.Unit, o.MedianNsPerUnit, r.MedianNsPerUnit, o.MedianNsPerUnit / r.MedianNsPerUnit, lo, hi,
                o.BytesAllocatedPerUnit, r.BytesAllocatedPerUnit, r.Case.BytesPerOp == 0 ? "n/a" : r.MegabytesPerSecond.ToString("F1", Inv)));
        }
        return s.ToString();
    }

    static string Settings() => string.Format(Inv, "warm-up {0} ms, {1} rounds of about {2} ms, median round reported, Stopwatch {3} ticks/s",
        Measure.WarmupTarget.TotalMilliseconds, Measure.Rounds, Measure.RoundTarget.TotalMilliseconds, System.Diagnostics.Stopwatch.Frequency);

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
