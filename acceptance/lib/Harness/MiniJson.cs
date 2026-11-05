using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A small JSON reader for trace lines and Host replies. Objects become Dictionary&lt;string, object&gt;, arrays List&lt;object&gt;,
    /// numbers double, plus string, bool and null. Written here so the suite parses what the product writes with code the product
    /// does not share. It compiles on net48 as well as net10.0.
    /// </summary>
    public static class MiniJson
    {
        public static object Parse(string text)
        {
            int i = 0;
            object v = Value(text, ref i);
            Skip(text, ref i);
            if (i != text.Length) throw new FormatException("trailing text at " + i);
            return v;
        }

        static void Skip(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

        static object Value(string s, ref int i)
        {
            Skip(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end");
            char c = s[i];
            if (c == '{') return Obj(s, ref i);
            if (c == '[') return Arr(s, ref i);
            if (c == '"') return Str(s, ref i);
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (s.Length - i >= 5 && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i;
            while (i < s.Length && (char.IsDigit(s[i]) || s[i] == '-' || s[i] == '+' || s[i] == '.' || s[i] == 'e' || s[i] == 'E')) i++;
            if (st == i) throw new FormatException("unexpected character '" + c + "' at " + i);
            return double.Parse(s.Substring(st, i - st), CultureInfo.InvariantCulture);
        }

        static Dictionary<string, object> Obj(string s, ref int i)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            i++;
            Skip(s, ref i);
            if (s[i] == '}') { i++; return d; }
            while (true)
            {
                Skip(s, ref i);
                string k = Str(s, ref i);
                Skip(s, ref i);
                if (s[i] != ':') throw new FormatException("expected ':' at " + i);
                i++;
                d[k] = Value(s, ref i);
                Skip(s, ref i);
                if (s[i] == ',') { i++; continue; }
                if (s[i] == '}') { i++; return d; }
                throw new FormatException("expected ',' or '}' at " + i);
            }
        }

        static List<object> Arr(string s, ref int i)
        {
            List<object> l = new List<object>();
            i++;
            Skip(s, ref i);
            if (s[i] == ']') { i++; return l; }
            while (true)
            {
                l.Add(Value(s, ref i));
                Skip(s, ref i);
                if (s[i] == ',') { i++; continue; }
                if (s[i] == ']') { i++; return l; }
                throw new FormatException("expected ',' or ']' at " + i);
            }
        }

        static string Str(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("expected string at " + i);
            i++;
            StringBuilder sb = new StringBuilder();
            while (s[i] != '"')
            {
                char c = s[i++];
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            i++;
            return sb.ToString();
        }

        // ---- typed access helpers ----
        public static Dictionary<string, object> AsObject(object o) { return o as Dictionary<string, object>; }
        public static List<object> AsArray(object o) { return o as List<object>; }

        public static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v != null ? v as string : null;
        }

        public static Dictionary<string, object> Obj(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v as Dictionary<string, object> : null;
        }

        public static List<object> Arr(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v as List<object> : null;
        }

        public static bool Bool(Dictionary<string, object> d, string key, bool whenMissing)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v is bool ? (bool)v : whenMissing;
        }

        public static double Num(Dictionary<string, object> d, string key, double whenMissing)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v is double ? (double)v : whenMissing;
        }

        /// <summary>The JSON text of a string, with quotes and escapes.</summary>
        public static string Quote(string s)
        {
            if (s == null) return "null";
            StringBuilder sb = new StringBuilder("\"");
            foreach (char ch in s)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20) sb.Append("\\u").Append(((int)ch).ToString("x4")); else sb.Append(ch);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }

        /// <summary>Writes a Dictionary, List, string, bool, number or null as JSON text.</summary>
        public static string Write(object o)
        {
            StringBuilder sb = new StringBuilder();
            WriteTo(sb, o);
            return sb.ToString();
        }

        static void WriteTo(StringBuilder sb, object o)
        {
            if (o == null) { sb.Append("null"); return; }
            string str = o as string;
            if (str != null) { sb.Append(Quote(str)); return; }
            if (o is bool) { sb.Append((bool)o ? "true" : "false"); return; }
            if (o is double) { sb.Append(((double)o).ToString("R", System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (o is int || o is long) { sb.Append(Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture)); return; }
            Dictionary<string, object> d = o as Dictionary<string, object>;
            if (d != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (KeyValuePair<string, object> kv in d)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append(Quote(kv.Key)).Append(':');
                    WriteTo(sb, kv.Value);
                }
                sb.Append('}');
                return;
            }
            System.Collections.IEnumerable list = o as System.Collections.IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object item in list)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteTo(sb, item);
                }
                sb.Append(']');
                return;
            }
            throw new FormatException("MiniJson.Write cannot write " + o.GetType().Name);
        }
    }
}
