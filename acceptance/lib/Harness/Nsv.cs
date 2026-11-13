using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>One vector record: a section name, the source line above it, and key = value pairs.</summary>
    public sealed class VectorRecord
    {
        public string Group;
        public string Source;
        public string File;
        public int Index;                       // position inside the group
        readonly Dictionary<string, string> _v = new Dictionary<string, string>();

        public void Set(string k, string v) { _v[k] = v; }
        public bool Has(string k) { return _v.ContainsKey(k); }
        public string Str(string k)
        {
            string s;
            if (!_v.TryGetValue(k, out s)) throw new KeyNotFoundException(File + " [" + Group + "] #" + Index + ": no field " + k);
            return s;
        }
        public byte[] Bytes(string k) { return Hex.Decode(Str(k)); }
        public int Int(string k) { return int.Parse(Str(k)); }
        public long Long(string k) { return long.Parse(Str(k)); }
        public string Where { get { return File + " [" + Group + "] #" + Index + (string.IsNullOrEmpty(Source) ? "" : " (" + Source + ")"); } }
    }

    /// <summary>
    /// Reader for the .nsv vector files in acceptance/vectors. Format: "[group]" starts a group,
    /// "# source: text" names the source of the records that follow, "key = value" lines form a record,
    /// a blank line ends a record. Other "#" lines are comments.
    /// </summary>
    public static class Nsv
    {
        public static List<VectorRecord> Load(string dir, string file, string group)
        {
            string path = Path.Combine(dir, file);
            // Every vector file is committed, the X9.24-3 file too (2026-11-11). The _cache folder holds downloaded documents only, so it is never read here.
            if (!File.Exists(path)) throw new NotRunException("VECTORS_MISSING", file + " is not in " + dir + ". Every vector file is committed; vectors/SOURCES.md names the tool that makes each one.");
            List<VectorRecord> all = new List<VectorRecord>();
            string curGroup = null, source = null;
            VectorRecord rec = null;
            int index = 0;
            foreach (string raw in File.ReadAllLines(path))
            {
                string ln = raw.TrimEnd();
                if (ln.Length == 0) { Flush(all, ref rec, group, curGroup); continue; }
                if (ln.StartsWith("[") && ln.EndsWith("]"))
                {
                    Flush(all, ref rec, group, curGroup);
                    curGroup = ln.Substring(1, ln.Length - 2);
                    index = 0;
                    continue;
                }
                if (ln.StartsWith("#"))
                {
                    if (ln.StartsWith("# source:")) source = ln.Substring(9).Trim();
                    continue;
                }
                int eq = ln.IndexOf('=');
                if (eq < 0) throw new FormatException(path + ": bad line: " + ln);
                if (rec == null) { rec = new VectorRecord(); rec.Group = curGroup; rec.Source = source; rec.File = file; rec.Index = index++; }
                rec.Set(ln.Substring(0, eq).Trim(), ln.Substring(eq + 1).Trim());
            }
            Flush(all, ref rec, group, curGroup);
            if (all.Count == 0) throw new NotRunException("VECTORS_EMPTY", file + " has no records in group " + group);
            return all;
        }

        static void Flush(List<VectorRecord> all, ref VectorRecord rec, string wanted, string cur)
        {
            if (rec != null && string.Equals(cur, wanted, StringComparison.Ordinal)) all.Add(rec);
            rec = null;
        }
    }
}
