using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// The AO bench report (acceptance/ao-bench-schema.md) is one file, and its rows come from more than one process: the net10 block run
/// gives AO-5 and AO-6, and each build's file run gives its AO-9 rows (.net10 and .cf). So each run writes its rows as a part file,
/// ao-part-&lt;name&gt;.jsonl with one JSON row per line, and --mode ao-merge joins every part in the folder into ao-bench.json.
/// </summary>
static class AoParts
{
    public static void Write(string folder, string name, IEnumerable<string> rows)
    {
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "ao-part-" + name + ".jsonl"), string.Join("\n", rows) + "\n", new UTF8Encoding(false));
    }

    public static int Merge(Dictionary<string, string> a)
    {
        string folder = a["out"];
        string[] parts = Directory.GetFiles(folder, "ao-part-*.jsonl").OrderBy(p => p, StringComparer.Ordinal).ToArray();
        List<string> rows = parts.SelectMany(p => File.ReadAllLines(p)).Where(l => l.Trim().Length > 0).Select(l => "    " + l.Trim()).ToList();
        StringBuilder s = new StringBuilder();
        s.Append("{\n  \"schema\": 1,\n");
        s.Append("  \"commit\": ").Append(Report.Quote(a["head"])).Append(",\n");
        s.Append("  \"runtime\": ").Append(Report.Quote(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription)).Append(",\n");
        s.Append("  \"machine\": ").Append(Report.Quote(Report.Cpu())).Append(",\n");
        s.Append("  \"rows\": [\n").Append(string.Join(",\n", rows)).Append("\n  ]\n}\n");
        File.WriteAllText(Path.Combine(folder, "ao-bench.json"), s.ToString(), new UTF8Encoding(false));
        Console.WriteLine("BENCH_AO_MERGED " + parts.Length + " parts, " + rows.Count + " rows: " + string.Join(", ", parts.Select(Path.GetFileName)));
        return parts.Length == 0 ? 5 : 0;
    }
}
