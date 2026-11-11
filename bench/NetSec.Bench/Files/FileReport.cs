using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NetSec.Bench.Files;

/// <summary>
/// The AO-9 report: one Markdown table with a row for each file and operation (file, operation, original, new, ratio, then the spread
/// and memory columns), the shared-key thread runs below it, and the provenance at the top. Ratio is the median of the per-round-pair
/// ratios, original ns over new ns, so above 1 means the new code is faster.
/// </summary>
static class FileReport
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Markdown(Run run, string original, IList<FileRow> rows, IList<ThreadRow> threads)
    {
        StringBuilder s = new StringBuilder();
        s.AppendLine("# AO-9 file benchmark: " + run.Build);
        s.AppendLine();
        s.AppendLine("- Original: " + original);
        Report.Header(s, run, FileBench.Round, NoiseBand.Describe(rows.Select(r => r.Pair.MedianRatio).ToArray()));
        s.AppendLine("Peak working set is the process peak after the row. Small-message rows (`64-byte message`) time one key setup plus one 64-byte seal "
            + "as one call, so MB/s there counts the 64 payload bytes.");
        s.AppendLine();
        s.AppendLine("| File | Operation | Original MB/s | New MB/s | Ratio | Ratio spread of round pairs | Original B/call | New B/call | Original gen 0/1/2 | New gen 0/1/2 | Calls per round | Peak working set MB |");
        s.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        foreach (FileRow r in rows)
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2:F1} | {3:F1} | {4:F3} | {5:F3} to {6:F3} | {7:F0} | {8:F0} | {9} | {10} | {11} | {12:F1} |",
                r.File, r.Operation, r.MegabytesPerSecond(r.Pair.Original), r.MegabytesPerSecond(r.Pair.New), r.Pair.MedianRatio,
                r.Pair.Ratios.Min(), r.Pair.Ratios.Max(), r.Pair.Original.BytesPerCall, r.Pair.New.BytesPerCall,
                Gens(r.Pair.Original), Gens(r.Pair.New), r.Pair.CallsPerRound, r.Pair.PeakWorkingSet / 1048576.0));
        s.AppendLine();
        s.AppendLine("## Shared key on pool threads");
        s.AppendLine();
        s.AppendLine("The runs go original, new, new, original, with a full GC before each.");
        s.AppendLine();
        s.AppendLine("| Order | Code | File | Workers | Seals per worker | Total MB/s | Mismatches | Peak working set MB | Pool cap |");
        s.AppendLine("|---:|---|---|---:|---:|---:|---:|---:|---|");
        for (int i = 0; i < threads.Count; i++)
        {
            ThreadRow t = threads[i];
            s.AppendLine(string.Format(Inv, "| {0} | {1} | `{2}` | {3} | {4} | {5:F1} | {6} | {7:F1} | {8} |",
                i + 1, t.Code, t.File, t.Workers, t.CallsPerWorker, t.TotalMegabytesPerSecond, t.Mismatches, t.PeakWorkingSet / 1048576.0, t.PoolCap));
        }
        return s.ToString();
    }

    static string Gens(Side s) => s.Gen0 + "/" + s.Gen1 + "/" + s.Gen2;
}
