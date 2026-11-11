using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace NetSec.Bench;

/// <summary>
/// --mode sizes (net10 build only): the file size of each built crypto assembly, and the IL bytes of each crypto type in it, read from
/// metadata (method body sizes summed per type, nested types included). Original is the frozen 5c5d4a4 copy (Acceptance.Frozen.dll,
/// the 30 crypto source files); new is the product (NetSec.Core.dll, the whole engine). So the file sizes compare like with like only
/// per type; the type table is the comparison, and the file sizes show what each build ships.
/// </summary>
static class Sizes
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>The crypto types the report names, by simple name. The same names exist in both copies.</summary>
    public static readonly string[] Types = { "AesKey", "Modes", "Gcm", "Gf128", "Cmac", "Des", "TdesKey", "Md5Hash", "Sha1Hash", "Sha256Hash", "Sha512Hash", "Sha3Hash", "Keccak", "Shake", "BlockHash", "Hmac", "Hkdf", "DukptDerivation", "PinBlock" };

    public static int Run(Dictionary<string, string> a)
    {
#if NETFRAMEWORK
        Console.Error.WriteLine("BENCH_USAGE: --mode sizes runs on the net10 build, which has System.Reflection.Metadata");
        return 2;
#else
        string root = a["repo"];
        (string Build, string Code, string Path)[] files =
        {
            ("net10", "new", Path.Combine(root, "src", "NetSec.Core", "bin", "Release", "net10.0", "NetSec.Core.dll")),
            ("cf", "new", Path.Combine(root, "src", "NetSec.Core.NetCF", "bin", "Release", "net35", "NetSec.Core.dll")),
            ("net10", "original", Path.Combine(root, "bench", "Frozen", "bin", "Release", "net10.0", "Acceptance.Frozen.dll")),
            ("cf", "original", Path.Combine(root, "bench", "Frozen.NetCF", "bin", "Release", "net35", "Acceptance.Frozen.dll")),
        };
        StringBuilder s = new StringBuilder();
        s.AppendLine("## File size");
        s.AppendLine();
        s.AppendLine("| Build | Code | Assembly | Bytes |");
        s.AppendLine("|---|---|---|---:|");
        foreach (var f in files) s.AppendLine(string.Format(Inv, "| {0} | {1} | `{2}` | {3} |", f.Build, f.Code, System.IO.Path.GetFileName(f.Path), new FileInfo(f.Path).Length));
        s.AppendLine();
        s.AppendLine("## IL bytes per crypto type");
        s.AppendLine();
        s.AppendLine("Method body bytes summed per type, nested types included. Ratio is original over new, so above 1 means the new type is smaller.");
        s.AppendLine();
        s.AppendLine("| Type | net10 original | net10 new | net10 ratio | CF original | CF new | CF ratio |");
        s.AppendLine("|---|---:|---:|---:|---:|---:|---:|");
        var il = files.Select(f => IlBytes(f.Path)).ToArray();
        foreach (string t in Types)
        {
            long n10 = Get(il[0], t), cf = Get(il[1], t), o10 = Get(il[2], t), ocf = Get(il[3], t);
            s.AppendLine(string.Format(Inv, "| `{0}` | {1} | {2} | {3} | {4} | {5} | {6} |", t, o10, n10, Ratio(o10, n10), ocf, cf, Ratio(ocf, cf)));
        }
        Directory.CreateDirectory(a["out"]);
        File.WriteAllText(Path.Combine(a["out"], "sizes.md"), s.ToString());
        Console.Write(s.ToString());
        Console.WriteLine("BENCH_SIZES_DONE");
        return 0;
#endif
    }

    static string Ratio(long original, long current) => current == 0 ? "n/a" : ((double)original / current).ToString("F3", Inv);

    static long Get(Dictionary<string, long> il, string type) => il.TryGetValue(type, out long v) ? v : 0;

#if !NETFRAMEWORK
    /// <summary>IL body bytes per top-level type simple name. A nested type's bytes count toward its outermost type.</summary>
    static Dictionary<string, long> IlBytes(string path)
    {
        Dictionary<string, long> bytes = new Dictionary<string, long>();
        using FileStream stream = File.OpenRead(path);
        using var pe = new System.Reflection.PortableExecutable.PEReader(stream);
        var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
        foreach (var h in md.TypeDefinitions)
        {
            var t = md.GetTypeDefinition(h);
            var outer = t;
            while (outer.IsNested) outer = md.GetTypeDefinition(outer.GetDeclaringType());
            string name = md.GetString(outer.Name);
            long sum = 0;
            foreach (var mh in t.GetMethods())
            {
                var m = md.GetMethodDefinition(mh);
                if (m.RelativeVirtualAddress != 0) sum += System.Reflection.Metadata.PEReaderExtensions.GetMethodBody(pe, m.RelativeVirtualAddress).Size;
            }
            bytes[name] = (bytes.TryGetValue(name, out long prior) ? prior : 0) + sum;
        }
        return bytes;
    }
#endif
}
