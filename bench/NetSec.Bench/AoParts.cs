using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace NetSec.Bench;

/// <summary>
/// The AO bench report (acceptance/ao-bench-schema.md) is one file, and its rows come from more than one process: the net10 block run
/// gives AO-5 and AO-6, and each build's file run gives its AO-9 rows (.net10 and .cf). So each run writes its rows as a part file,
/// ao-part-&lt;name&gt;.jsonl: a first line "# head &lt;sha&gt;" naming the commit the part measured, then one JSON row per line.
/// --mode ao-merge joins every part in the folder into ao-bench.json, and refuses a part whose head is missing or differs from --head,
/// so a report never mixes rows from two commits (Jared, #430 review N2). The commit is always the full 40-character id (N4).
/// </summary>
static class AoParts
{
    const string HeadPrefix = "# head ";
    public const int MixedHeadsExit = 12;
    static readonly Regex FullSha = new Regex("^(?<sha>[0-9a-f]{40})$");

    public static void Write(string folder, string name, string head, IEnumerable<string> rows)
    {
        if (!FullSha.IsMatch(head ?? "")) throw new ArgumentException("an AO part names its commit by the full 40-character id, not " + head, nameof(head));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "ao-part-" + name + ".jsonl"), HeadPrefix + head + "\n" + string.Join("\n", rows) + "\n", new UTF8Encoding(false));
    }

    public static int Merge(Dictionary<string, string> a)
    {
        string folder = a["out"], head = a["head"];
        if (!FullSha.IsMatch(head)) { Console.WriteLine("BENCH_AO_HEAD_NOT_FULL --head is " + head + "; ao-bench.json names the full 40-character id"); return MixedHeadsExit; }
        string[] parts = Directory.GetFiles(folder, "ao-part-*.jsonl").OrderBy(p => p, StringComparer.Ordinal).ToArray();
        List<string> rows = new List<string>();
        foreach (string part in parts)
        {
            string[] lines = File.ReadAllLines(part);
            string partHead = lines.Length > 0 && lines[0].StartsWith(HeadPrefix, StringComparison.Ordinal) ? lines[0].Substring(HeadPrefix.Length).Trim() : "(none)";
            if (partHead != head)
            {
                Console.WriteLine("BENCH_AO_MIXED_HEADS " + Path.GetFileName(part) + " measured " + partHead + ", the merge is for " + head + "; no ao-bench.json is written");
                return MixedHeadsExit;
            }
            rows.AddRange(lines.Skip(1).Where(l => l.Trim().Length > 0).Select(l => "    " + l.Trim()));
        }
        StringBuilder s = new StringBuilder();
        s.Append("{\n  \"schema\": 1,\n");
        s.Append("  \"commit\": ").Append(Report.Quote(head)).Append(",\n");
        s.Append("  \"mergeRuntime\": ").Append(Report.Quote(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription)).Append(",\n");
        s.Append("  \"machine\": ").Append(Report.Quote(Report.Cpu())).Append(",\n");
        s.Append("  \"rows\": [\n").Append(string.Join(",\n", rows)).Append("\n  ]\n}\n");
        File.WriteAllText(Path.Combine(folder, "ao-bench.json"), s.ToString(), new UTF8Encoding(false));
        Console.WriteLine("BENCH_AO_MERGED " + parts.Length + " parts, " + rows.Count + " rows at " + head + ": " + string.Join(", ", parts.Select(Path.GetFileName)));
        return parts.Length == 0 ? 5 : 0;
    }
}
