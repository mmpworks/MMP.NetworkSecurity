using System;
using System.Text;

namespace Acceptance
{
    /// <summary>Hex helpers that compile on net10.0 and net48 (no Convert.ToHexString, no Span).</summary>
    public static class Hex
    {
        public static byte[] Decode(string s)
        {
            if (s == null) throw new ArgumentNullException("s");
            s = s.Replace(" ", "");
            if (s.Length % 2 != 0) throw new FormatException("odd hex length " + s.Length);
            byte[] r = new byte[s.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = (byte)((Nibble(s[2 * i]) << 4) | Nibble(s[2 * i + 1]));
            return r;
        }

        static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new FormatException("not a hex digit: " + c);
        }

        public static string Encode(byte[] b)
        {
            if (b == null) return "<null>";
            StringBuilder sb = new StringBuilder(b.Length * 2);
            for (int i = 0; i < b.Length; i++) sb.Append(b[i].ToString("x2"));
            return sb.ToString();
        }

        /// <summary>Short form for failure details: first 16 bytes and the length.</summary>
        public static string Short(byte[] b)
        {
            if (b == null) return "<null>";
            if (b.Length <= 16) return Encode(b);
            byte[] head = new byte[16];
            Array.Copy(b, head, 16);
            return Encode(head) + "..(" + b.Length + " bytes)";
        }

        public static bool Eq(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        public static byte[] Concat(params byte[][] parts)
        {
            int n = 0;
            for (int i = 0; i < parts.Length; i++) n += parts[i].Length;
            byte[] r = new byte[n];
            int o = 0;
            for (int i = 0; i < parts.Length; i++) { Array.Copy(parts[i], 0, r, o, parts[i].Length); o += parts[i].Length; }
            return r;
        }

        public static byte[] Slice(byte[] b, int off, int n)
        {
            byte[] r = new byte[n];
            Array.Copy(b, off, r, 0, n);
            return r;
        }
    }
}
