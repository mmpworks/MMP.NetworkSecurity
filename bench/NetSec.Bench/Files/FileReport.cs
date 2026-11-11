using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NetSec.Bench.Files;

/// <summary>
/// The AO-9 report: one Markdown table with a row for each file and operation (file, operation, original, new, ratio, then the memory
/// columns), the thread run below it, and the provenance at the top. Ratio is new MB/s over original MB/s, so above 1 means the new code is faster.
/// </summary>
static class FileReport
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Markdown(string build, string head, string original, IList<FileRow> rows, IList<ThreadRow> threads, string cfLine)
    {
        StringBuilder s = new StringBuilder();
        s.AppendLine("# AO-9 file benchmark: " + build);
        s.AppendLine();
        s.AppendLine("- Head: `" + head + "`");
        s.AppendLine("- Original: " + original);
        s.AppendLine("- Machine: " + Program.Machine());
        s.AppendLine(string.Format(Inv, "- Timing: warm-up, then {0} runs of about {1} ms each; MB/s from the median run; spread is the slowest and fastest run",
            FileBench.Runs, FileBench.RunTarget.TotalMilliseconds));
        s.AppendLine("- Allocation counter: " + Allocated.Method);
        s.AppendLine("- GC counts and allocated bytes cover the timed runs of the row. Peak working set is the process peak after the row.");
        s.AppendLine("- " + cfLine);
        s.AppendLine();
        s.AppendLine("| File | Operation | Original MB/s | New MB/s | Ratio | Original spread | New spread | Original B/call | New B/call | Original gen 0/1/2 | New gen 0/1/2 | Peak working set MB |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        foreach (var pair in rows.GroupBy(r => r.File + "\u0000" + r.Operation))
        {
            FileRow o = pair.First(r => r.Code == "original"), n = pair.First(r => r.Code == "new");
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F1} | {3:F1} | {4:F2} | {5} | {6} | {7:F0} | {8:F0} | {9} | {10} | {11:F1} |",
                o.File, o.Operation, o.MegabytesPerSecond, n.MegabytesPerSecond, n.MegabytesPerSecond / o.MegabytesPerSecond,
                Spread(o), Spread(n), o.BytesAllocatedPerCall, n.BytesAllocatedPerCall, Gens(o), Gens(n), Math.Max(o.PeakWorkingSet, n.PeakWorkingSet) / 1048576.0));
        }
        s.AppendLine();
        s.AppendLine("Small-message rows (`64-byte message`) time one key setup plus one 64-byte seal as one call, so MB/s there counts the 64 payload bytes.");
        s.AppendLine();
        s.AppendLine("## Shared key on pool threads");
        s.AppendLine();
        s.AppendLine("| Code | File | Workers | Seals per worker | Total MB/s | Mismatches | Peak working set MB | Pool cap |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---|");
        foreach (ThreadRow t in threads)
            s.AppendLine(string.Format(Inv, "| {0} | `{1}` | {2} | {3} | {4:F1} | {5} | {6:F1} | {7} |",
                t.Code, t.File, t.Workers, t.CallsPerWorker, t.TotalMegabytesPerSecond, t.Mismatches, t.PeakWorkingSet / 1048576.0, t.PoolCap));
        return s.ToString();
    }

    /// <summary>The slowest and the fastest run, in MB/s.</summary>
    static string Spread(FileRow r) => string.Format(Inv, "{0:F1} to {1:F1}",
        r.BytesPerCall / r.NsPerCallRuns.Max() * 1e9 / 1048576, r.BytesPerCall / r.NsPerCallRuns.Min() * 1e9 / 1048576);

    static string Gens(FileRow r) => r.Gen0 + "/" + r.Gen1 + "/" + r.Gen2;
}
