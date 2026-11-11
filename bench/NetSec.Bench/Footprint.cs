using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// --mode footprint: memory the crypto code holds, apart from per-call garbage (the suite's AO-5 judges per-call bytes).
/// 1. Static tables: after each crypto type has run its type initializer, the bytes of every static array field it holds.
/// 2. Per key object: bytes still held per key after a full collection, over 1000 keys kept alive (GC.GetTotalMemory deltas).
/// 3. With --workload original|new: one fixed workload in a fresh process (GCM seal and open of every AO-9 file once), then the
///    process peak working set. Run once per copy, so neither copy's peak includes the other's.
/// </summary>
static class Footprint
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    const int Keys = 1000;

    public static int Run(Dictionary<string, string> a, Run run)
    {
        if (a.TryGetValue("workload", out string code)) return Workload(a, run, code);
        Assembly original = typeof(Acceptance.Frozen.Crypto.AesKey).Assembly, current = typeof(NetSec.Crypto.AesKey).Assembly;
        StringBuilder s = new StringBuilder();
        s.AppendLine("# Memory footprint: " + run.Build);
        s.AppendLine();
        s.AppendLine("- Head: `" + run.Head + "`");
        s.AppendLine("- Runtime: " + Program.Machine());
        s.AppendLine("- " + run.CfLine);
        s.AppendLine();
        s.AppendLine("## Static tables after first use");
        s.AppendLine();
        s.AppendLine("Data bytes are element count times element size. Held bytes add the array header of this process (" + IntPtr.Size * 3 + " B per array on a " + IntPtr.Size * 8 + "-bit runtime).");
        s.AppendLine();
        s.AppendLine("| Type | Original arrays | Original data B | Original held B | New arrays | New data B | New held B |");
        s.AppendLine("|---|---:|---:|---:|---:|---:|---:|");
        foreach (string t in Sizes.Types)
        {
            var o = StaticArrays(original, t);
            var n = StaticArrays(current, t);
            if (o.Count == 0 && n.Count == 0) continue;
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2} | {3} | {4} | {5} | {6} |", t, o.Count, o.Data, o.Held, n.Count, n.Data, n.Held));
        }
        s.AppendLine();
        s.AppendLine("## Bytes held per key object");
        s.AppendLine();
        s.AppendLine("Bytes still held after a full collection, per key, over " + Keys + " keys kept alive (the reference array is taken off).");
        s.AppendLine();
        s.AppendLine("| Key | Original B per key | New B per key |");
        s.AppendLine("|---|---:|---:|");
        byte[] k16 = new byte[16], k24 = new byte[24], k32 = new byte[32];
        Row(s, "AesKey, 16-byte key", () => new Acceptance.Frozen.Crypto.AesKey(k16), () => new NetSec.Crypto.AesKey(k16));
        Row(s, "AesKey, 32-byte key", () => new Acceptance.Frozen.Crypto.AesKey(k32), () => new NetSec.Crypto.AesKey(k32));
        Row(s, "TdesKey, 24-byte key", () => new Acceptance.Frozen.Crypto.TdesKey(k24), () => new NetSec.Crypto.TdesKey(k24));
        Directory.CreateDirectory(a["out"]);
        File.WriteAllText(Path.Combine(a["out"], "footprint-" + run.Build + ".md"), s.ToString());
        Console.Write(s.ToString());
        Console.WriteLine("BENCH_FOOTPRINT_DONE " + run.Build);
        return 0;
    }

    sealed class Arrays { public int Count; public long Data, Held; }

    static Arrays StaticArrays(Assembly assembly, string simpleName)
    {
        Arrays r = new Arrays();
        foreach (Type t in assembly.GetTypes().Where(x => x.Name == simpleName || (x.DeclaringType != null && x.DeclaringType.Name == simpleName)))
        {
            RuntimeHelpers.RunClassConstructor(t.TypeHandle);
            foreach (FieldInfo f in t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (f.GetValue(null) is Array arr) Add(r, arr);
            }
        }
        return r;
    }

    /// <summary>One array: a primitive array counts its bytes; an array of arrays counts its references and each inner array; any other element type counts references only.</summary>
    static void Add(Arrays r, Array arr)
    {
        Type element = arr.GetType().GetElementType();
        long data = element.IsPrimitive ? Buffer.ByteLength(arr) : (long)arr.Length * IntPtr.Size;
        r.Count++;
        r.Data += data;
        r.Held += (IntPtr.Size * 3 + data + 7) / 8 * 8;
        if (element.IsArray)
            foreach (object inner in arr)
                if (inner is Array a) Add(r, a);
    }

    static void Row(StringBuilder s, string name, Func<object> original, Func<object> current) =>
        s.AppendLine(string.Format(Inv, "| {0} | {1:F1} | {2:F1} |", name, HeldPerObject(original), HeldPerObject(current)));

    static double HeldPerObject(Func<object> make)
    {
        object[] keep = new object[Keys];
        make();
        long before = GC.GetTotalMemory(true);
        for (int i = 0; i < Keys; i++) keep[i] = make();
        long after = GC.GetTotalMemory(true);
        GC.KeepAlive(keep);
        return (double)(after - before) / Keys;
    }

    /// <summary>The fixed workload of rule 3, on one copy, then the peak working set of this process.</summary>
    static int Workload(Dictionary<string, string> a, Run run, string code)
    {
        Files.ICodeUnderTest copy = code == "original" ? new Files.FrozenCode() : (Files.ICodeUnderTest)new Files.ProductCode();
        List<Files.TestFile> files = Files.FileSet.Load(a["files"]);
        long peakBefore;
        using (Process p = Process.GetCurrentProcess()) peakBefore = p.PeakWorkingSet64;
        Files.IBoundCode b = copy.Bind(new byte[16], new byte[32]);
        byte[] nonce = new byte[12], aad = new byte[0];
        foreach (Files.TestFile f in files) Cases.Sink = b.GcmOpen(nonce, aad, b.GcmSeal(nonce, aad, f.Bytes));
        long peak;
        using (Process p = Process.GetCurrentProcess()) { p.Refresh(); peak = p.PeakWorkingSet64; }
        string line = string.Format(Inv, "BENCH_WORKLOAD {0} {1}: peak working set {2:F1} MB (before the workload {3:F1} MB); GCM seal and open of {4} files, {5} bytes in all",
            run.Build, code, peak / 1048576.0, peakBefore / 1048576.0, files.Count, files.Sum(f => (long)f.Bytes.Length));
        Console.WriteLine(line);
        Directory.CreateDirectory(a["out"]);
        File.AppendAllText(Path.Combine(a["out"], "workload-" + run.Build + ".txt"), line + Environment.NewLine);
        return 0;
    }
}
