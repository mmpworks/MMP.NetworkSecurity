using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace NetSec.Bench;

/// <summary>One timed row of one crossover part, in frozen/product terms (a swapped part times the product as "original").</summary>
sealed class PartRow
{
    public string Id, Unit;
    public int UnitsPerOp, BytesPerOp;
    public double Ratio, FrozenNs, ProductNs, FrozenBytes, ProductBytes, Load, Core;
    public int CpuStart, CpuEnd;
}

/// <summary>One part as read back: its header lines and rows.</summary>
sealed class PartFile
{
    public string Tag;
    public Dictionary<string, string> Header = new Dictionary<string, string>();
    public List<PartRow> Rows = new List<PartRow>();
}

/// <summary>
/// The part file of the balanced crossover, shared by every timing host (net10, net48 and the CLR 2.0 hosts, which link this file).
/// The tag alone sets the arrangement, so a script cannot pair them wrongly: normal1 and swapped1 compile the frozen copy first,
/// normal2 and swapped2 compile the product first, and swapped parts time the product as "original". So each of N = sqrt(N1 x N2) and
/// S = sqrt(S1 x S2) holds one part of each JIT order, and both the position bias and the JIT-order effect cancel (Crossover.Combine).
/// Format: "# key\tvalue" header lines, a column line, then one tab-separated row per timed case; numbers in the invariant culture.
/// </summary>
static class CrossoverPart
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    public static readonly string[] Tags = { "normal1", "swapped1", "normal2", "swapped2" };
    const string Columns = "id\tunit\tunitsPerOp\tbytesPerOp\tpositionRatio\tfrozenNsPerUnit\tproductNsPerUnit\tfrozenBytesPerUnit\tproductBytesPerUnit\toutsideLoad\tcoreLoad\tcpuStart\tcpuEnd";

    public static bool IsTag(string tag) => Array.IndexOf(Tags, tag) >= 0;

    /// <summary>The .NET SDK that built this bench binary ("10.0.204"), from the AssemblyDescription the project sets to
    /// "sdk $(NETCoreSdkVersion)"; "unknown" when the build did not set it.</summary>
    public static string BuildSdk()
    {
        object[] found = typeof(CrossoverPart).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyDescriptionAttribute), false);
        string text = found.Length > 0 ? ((System.Reflection.AssemblyDescriptionAttribute)found[0]).Description : "";
        return text.StartsWith("sdk ", StringComparison.Ordinal) && text.Length > 4 ? text.Substring(4) : "unknown";
    }

    public static bool Swapped(string tag) => tag.StartsWith("swapped", StringComparison.Ordinal);

    /// <summary>"frozen" for the first pair of parts, "product" for the second.</summary>
    public static string JitFirst(string tag) => tag.EndsWith("1", StringComparison.Ordinal) ? "frozen" : "product";

    /// <summary>A row from a paired measurement. <paramref name="originalBytes"/> and <paramref name="newBytes"/> are per op, by position.</summary>
    public static PartRow FromPair(string id, string unit, int unitsPerOp, int bytesPerOp, Pair p, bool swapped, double originalBytes, double newBytes)
    {
        double originalNs = p.Original.MedianNs / unitsPerOp, newNs = p.New.MedianNs / unitsPerOp;
        return new PartRow
        {
            Id = id, Unit = unit, UnitsPerOp = unitsPerOp, BytesPerOp = bytesPerOp, Ratio = p.MedianRatio,
            FrozenNs = swapped ? newNs : originalNs, ProductNs = swapped ? originalNs : newNs,
            FrozenBytes = (swapped ? newBytes : originalBytes) / unitsPerOp, ProductBytes = (swapped ? originalBytes : newBytes) / unitsPerOp,
            Load = p.OtherBusy, Core = double.IsNaN(p.CoreBusy) ? -1 : p.CoreBusy, CpuStart = p.CpuStart, CpuEnd = p.CpuEnd,
        };
    }

    /// <summary>Writes cross-&lt;build&gt;-&lt;tag&gt;.tsv. The header gets build, tag, order and jit-first beside the caller's lines.</summary>
    public static void Write(string folder, string build, string tag, IDictionary<string, string> header, IList<PartRow> rows)
    {
        StringBuilder s = new StringBuilder();
        Dictionary<string, string> all = new Dictionary<string, string>(header);
        all["build"] = build;
        all["tag"] = tag;
        all["order"] = Swapped(tag) ? "swapped" : "normal";
        all["jit-first"] = JitFirst(tag);
        all["sdk"] = BuildSdk();
        using (System.Diagnostics.Process self = System.Diagnostics.Process.GetCurrentProcess()) all["pid"] = self.Id.ToString(Inv);
        foreach (KeyValuePair<string, string> kv in all) s.Append("# ").Append(kv.Key).Append('\t').Append(kv.Value.Replace('\t', ' ')).Append('\n');
        s.Append(Columns).Append('\n');
        foreach (PartRow r in rows)
            s.Append(string.Format(Inv, "{0}\t{1}\t{2}\t{3}\t{4:R}\t{5:R}\t{6:R}\t{7:R}\t{8:R}\t{9:R}\t{10:R}\t{11}\t{12}\n",
                r.Id, r.Unit, r.UnitsPerOp, r.BytesPerOp, r.Ratio, r.FrozenNs, r.ProductNs, r.FrozenBytes, r.ProductBytes, r.Load, r.Core, r.CpuStart, r.CpuEnd));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, FileName(build, tag)), s.ToString());
    }

    public static string FileName(string build, string tag) => "cross-" + build + "-" + tag + ".tsv";

    public static PartFile Read(string tag, string[] lines)
    {
        PartFile p = new PartFile { Tag = tag };
        foreach (string line in lines)
        {
            if (line.Length == 0 || line.StartsWith("id\t", StringComparison.Ordinal)) continue;
            string[] f = line.Split('\t');
            if (line.StartsWith("# ", StringComparison.Ordinal)) { p.Header[f[0].Substring(2)] = f.Length > 1 ? f[1] : ""; continue; }
            p.Rows.Add(new PartRow
            {
                Id = f[0], Unit = f[1], UnitsPerOp = int.Parse(f[2], Inv), BytesPerOp = int.Parse(f[3], Inv),
                Ratio = D(f[4]), FrozenNs = D(f[5]), ProductNs = D(f[6]), FrozenBytes = D(f[7]), ProductBytes = D(f[8]),
                Load = D(f[9]), Core = D(f[10]), CpuStart = int.Parse(f[11], Inv), CpuEnd = int.Parse(f[12], Inv),
            });
        }
        return p;
    }

    static double D(string v) => double.Parse(v, Inv);
}
