using System;
using System.Collections.Generic;
using System.IO;
using NetSec.Bytes;

namespace NetSec.Tests
{
    /// <summary>
    /// Reads the published vectors in acceptance/vectors. The builder suite reads them and never writes there (D11).
    /// A record is a run of "name = value" lines, a blank line ends it, and "[group]" starts a group.
    /// </summary>
    static class VectorFile
    {
        public static List<Dictionary<string, string>> Read(string file, string group)
        {
            List<Dictionary<string, string>> records = new List<Dictionary<string, string>>();
            Dictionary<string, string> current = null;
            string section = null;
            foreach (string raw in File.ReadAllLines(Path.Combine(Root(), file)))
            {
                string line = raw.Trim();
                if (line.StartsWith("#")) continue;
                if (line.StartsWith("[")) { section = line.Trim('[', ']'); current = null; continue; }
                int eq = line.IndexOf('=');
                if (line.Length == 0 || eq < 0) { current = null; continue; }
                if (section != group) continue;
                if (current == null) { current = new Dictionary<string, string>(); records.Add(current); }
                current[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
            }
            if (records.Count == 0) throw new InvalidOperationException("no vectors in " + file + " group " + group);
            return records;
        }

        public static byte[] Bytes(this Dictionary<string, string> record, string name)
        {
            return Hex.Decode(record[name]);
        }

        static string Root()
        {
            for (string dir = AppContext.BaseDirectory; dir != null; dir = Path.GetDirectoryName(dir))
            {
                string candidate = Path.Combine(dir, "acceptance", "vectors");
                if (Directory.Exists(candidate)) return candidate;
            }
            throw new DirectoryNotFoundException("acceptance/vectors not found above " + AppContext.BaseDirectory);
        }
    }
}
