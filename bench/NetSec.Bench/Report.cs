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

    public static string Markdown(string build, string head, IList<CaseResult> results, string cfLine)
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
        s.AppendLine("| Case | Unit | ns per unit (median) | Spread of rounds | B allocated per unit | B allocated per op | MB/s |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|");
        foreach (CaseResult r in results)
        {
            double lo = r.NsPerOpRounds.Min() / r.Case.UnitsPerOp, hi = r.NsPerOpRounds.Max() / r.Case.UnitsPerOp;
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F1} | {3:F1} to {4:F1} | {5:F1} | {6:F0} | {7} |",
                r.Case.Id, r.Case.Unit, r.MedianNsPerUnit, lo, hi, r.BytesAllocatedPerUnit, r.BytesAllocatedPerOp,
                r.Case.BytesPerOp == 0 ? "n/a" : r.MegabytesPerSecond.ToString("F1", Inv)));
        }
        return s.ToString();
    }

    static string Settings() => string.Format(Inv, "warm-up {0} ms, {1} rounds of about {2} ms, median round reported, Stopwatch {3} ticks/s",
        Measure.WarmupTarget.TotalMilliseconds, Measure.Rounds, Measure.RoundTarget.TotalMilliseconds, System.Diagnostics.Stopwatch.Frequency);

    static void Field(StringBuilder s, string name, string value) => s.Append("  ").Append(Quote(name)).Append(": ").Append(Quote(value)).Append(",\n");

    static string Quote(string v)
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
