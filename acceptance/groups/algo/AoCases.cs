using System;
using System.Collections.Generic;
using System.Text;

namespace Acceptance
{
    /// <summary>What one side did in one case: the exception (type and NetSec code) or none, and every array the case looks at afterwards.</summary>
    public sealed class AoRec
    {
        public string Sig = "ok";
        public readonly List<byte[]> Arrays = new List<byte[]>();
        public readonly List<string> Texts = new List<string>();
        public void Add(byte[] b) { Arrays.Add(b == null ? null : (byte[])b.Clone()); }
        public void Add(string s) { Texts.Add(s == null ? "<null>" : s); }
        public void Add(bool b) { Texts.Add(b ? "true" : "false"); }

        /// <summary>Type name, plus the machine code when the exception carries a NetSecError. Messages are not compared.</summary>
        public static string SigOf(Exception e)
        {
            string code = "";
            System.Reflection.FieldInfo f = e.GetType().GetField("Error");
            if (f != null)
            {
                object err = f.GetValue(e);
                if (err != null)
                {
                    System.Reflection.FieldInfo cf = err.GetType().GetField("Code");
                    if (cf != null) code = ":" + cf.GetValue(err);
                }
            }
            return e.GetType().Name + code;
        }

        /// <summary>Null when the two records agree, else the first difference.</summary>
        public static string Diff(AoRec a, AoRec b)
        {
            if (a.Sig != b.Sig) return "outcome " + a.Sig + " vs " + b.Sig;
            if (a.Arrays.Count != b.Arrays.Count) return "array count " + a.Arrays.Count + " vs " + b.Arrays.Count;
            for (int i = 0; i < a.Arrays.Count; i++)
                if (!Hex.Eq(a.Arrays[i], b.Arrays[i])) return "array " + i + ": " + Hex.Short(a.Arrays[i]) + " vs " + Hex.Short(b.Arrays[i]);
            if (a.Texts.Count != b.Texts.Count) return "text count " + a.Texts.Count + " vs " + b.Texts.Count;
            for (int i = 0; i < a.Texts.Count; i++)
                if (a.Texts[i] != b.Texts[i]) return "text " + i + ": " + a.Texts[i] + " vs " + b.Texts[i];
            return null;
        }
    }

    public delegate void AoCase(AoSide s, AoRec r);

    /// <summary>A referee that cannot run this case. The case is counted as skipped for that referee, never as an outcome.</summary>
    public class AoSkipException : Exception { }

    /// <summary>A fault in the suite's own code. It ends the clause; it never counts as an outcome that both sides share.</summary>
    public sealed class AoHarnessException : Exception
    {
        public AoHarnessException(string message) : base(message) { }
    }

    /// <summary>
    /// Text of an object graph: public instance fields by name, arrays in order, enums by name. The frozen and the product walk types
    /// have the same field names, so equal text means equal walks.
    /// </summary>
    public static class AoDump
    {
        public static string Of(object o)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            Write(sb, o, 0);
            return sb.ToString();
        }

        static void Write(System.Text.StringBuilder sb, object o, int depth)
        {
            if (depth > 32) throw new AoHarnessException("AoDump: graph deeper than 32 at " + (o == null ? "null" : o.GetType().Name));
            if (o == null) { sb.Append("null"); return; }
            Type t = o.GetType();
            if (o is byte[]) { sb.Append(Hex.Encode((byte[])o)); return; }
            if (t.IsPrimitive || t.IsEnum || o is string) { sb.Append(o.ToString()); return; }
            if (o is Array)
            {
                sb.Append('[');
                foreach (object e in (Array)o) { Write(sb, e, depth + 1); sb.Append(','); }
                sb.Append(']');
                return;
            }
            System.Reflection.FieldInfo[] fs = t.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            Array.Sort(fs, delegate (System.Reflection.FieldInfo a, System.Reflection.FieldInfo b) { return string.CompareOrdinal(a.Name, b.Name); });
            sb.Append(t.Name).Append('{');
            foreach (System.Reflection.FieldInfo f in fs) { sb.Append(f.Name).Append('='); Write(sb, f.GetValue(o), depth + 1); sb.Append(';'); }
            sb.Append('}');
        }
    }

    /// <summary>
    /// The case grammar of AO-2 and AO-4. Draws are weighted to the edges an optimization gets wrong: lengths 0, 1, block size -1, 0, +1;
    /// aliased and shifted buffers; canary bytes on both sides of every output; counters near all-FF; invalid arguments.
    /// </summary>
    public static class AoDraw
    {
        static readonly int[] EdgeLengths = { 0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 71, 72, 73, 127, 128, 129, 135, 136, 137, 167, 168, 169, 255, 256, 257 };

        /// <summary>40 percent edge lengths, 50 percent 0 to 299, 10 percent 0 to max.</summary>
        public static int Len(Rng r, int max)
        {
            int p = r.Int(100);
            int n;
            if (p < 40) n = EdgeLengths[r.Int(EdgeLengths.Length)];
            else if (p < 90) n = r.Int(300);
            else n = r.Int(max + 1);
            return Math.Min(n, max);
        }

        /// <summary>A whole number of blocks, with the block count weighted to 0, 1 and 2.</summary>
        public static int Blocks(Rng r, int blockSize, int maxBlocks)
        {
            int p = r.Int(100);
            int b = p < 15 ? 0 : p < 40 ? 1 : p < 55 ? 2 : r.Int(maxBlocks + 1);
            return b * blockSize;
        }

        public static int KeyLen(Rng r) { int[] k = { 16, 24, 32 }; return k[r.Int(3)]; }

        public static readonly int[] BadAesKeyLengths = { 0, 1, 8, 15, 17, 23, 25, 31, 33, 64 };

        public static byte[] NearWrapCounter(Rng r)
        {
            byte[] c = r.Bytes(16);
            if (r.Int(4) == 0)
            {
                int k = 1 + r.Int(16);
                for (int i = 16 - k; i < 16; i++) c[i] = 0xFF;
                if (r.Int(2) == 0 && k < 16) c[15 - k] = (byte)r.Int(256);
            }
            return c;
        }

        public static byte[] FlipBit(Rng r, byte[] b)
        {
            byte[] c = (byte[])b.Clone();
            if (c.Length > 0) c[r.Int(c.Length)] ^= (byte)(1 << r.Int(8));
            return c;
        }

        public static string Digits(Rng r, int n)
        {
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) sb.Append((char)('0' + r.Int(10)));
            return sb.ToString();
        }

        public static string Ascii(Rng r, int n)
        {
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) sb.Append((char)(0x20 + r.Int(95)));
            return sb.ToString();
        }

        /// <summary>Split points for n bytes: 1 to 6 pieces, some empty, some on the block size given.</summary>
        public static int[] Pieces(Rng r, int n, int block)
        {
            int count = 1 + r.Int(6);
            List<int> cuts = new List<int>();
            for (int i = 1; i < count; i++)
            {
                int p = r.Int(3);
                int cut = p == 0 && block > 0 ? Math.Min(n, block * (1 + r.Int(3)) + r.Int(3) - 1) : r.Int(n + 1);
                cuts.Add(Math.Max(0, cut));
            }
            cuts.Sort();
            List<int> sizes = new List<int>();
            int prev = 0;
            foreach (int c in cuts) { sizes.Add(c - prev); prev = c; }
            sizes.Add(n - prev);
            return sizes.ToArray();
        }
    }

    /// <summary>One block-cipher call with a drawn aliasing: separate arrays, the same array at the same offset, or the same array shifted.</summary>
    public sealed class AoBlockCall
    {
        public bool Encrypt, Same, BadArgs;
        public int Io, Oo, Block;
        public byte[] In, Out;   // In alone when Same

        public static AoBlockCall Draw(Rng r, int block)
        {
            AoBlockCall c = new AoBlockCall();
            c.Block = block;
            c.Encrypt = r.Int(2) == 0;
            int mode = r.Int(3);
            if (r.Int(50) == 0) return DrawBad(r, c);
            if (mode == 0)
            {
                c.Io = r.Int(block + 1); c.Oo = r.Int(block + 1);
                c.In = r.Bytes(c.Io + block + r.Int(9));
                c.Out = r.Bytes(c.Oo + block + r.Int(9));
            }
            else
            {
                c.Same = true;
                c.Io = r.Int(block + 1);
                int shift = mode == 1 ? 0 : (1 + r.Int(block - 1)) * (r.Int(2) == 0 ? 1 : -1);
                c.Oo = Math.Max(0, c.Io + shift);
                c.In = r.Bytes(Math.Max(c.Io, c.Oo) + block + r.Int(9));
            }
            return c;
        }

        static AoBlockCall DrawBad(Rng r, AoBlockCall c)
        {
            c.BadArgs = true;
            c.In = r.Bytes(c.Block + r.Int(4));
            c.Out = r.Bytes(c.Block + r.Int(4));
            switch (r.Int(5))
            {
                case 0: c.Io = -1 - r.Int(3); break;
                case 1: c.Oo = -1 - r.Int(3); break;
                case 2: c.Io = c.In.Length - c.Block + 1 + r.Int(3); break;
                case 3: c.Oo = c.Out.Length - c.Block + 1 + r.Int(3); break;
                default: if (r.Int(2) == 0) c.In = null; else c.Out = null; break;
            }
            return c;
        }

        public delegate void BlockOp(byte[] i, int io, byte[] o, int oo);

        /// <summary>Runs the call on private copies and records every byte of every buffer afterwards, canaries included.</summary>
        public void Run(BlockOp enc, BlockOp dec, AoRec rec)
        {
            BlockOp op = Encrypt ? enc : dec;
            byte[] i = In == null ? null : (byte[])In.Clone();
            byte[] o = Same ? i : (Out == null ? null : (byte[])Out.Clone());
            string sig = "ok";
            try { op(i, Io, o, Oo); }
            catch (Exception e) { sig = AoRec.SigOf(e); }
            rec.Add(sig);
            rec.Add(i);
            if (!Same) rec.Add(o);
        }
    }
}
