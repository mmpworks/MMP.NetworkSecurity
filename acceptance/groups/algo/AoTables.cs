using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;

namespace Acceptance
{
    /// <summary>
    /// AO-3: table proof. The suite builds each table from the math (GF(2^8) inverse and affine map, xtime products, the GHASH reduction
    /// constant), in every word layout an implementation can choose. Every static array field of a product type in the scope must equal
    /// one of them. A second check reads the IL of each type initializer in the scope: it may only store constant arrays, so no code
    /// builds a table at start-up (PRD 7.1 rule 1).
    /// </summary>
    public static class AoTables
    {
        // ---- the math ----

        static int Xtime(int a) { return ((a << 1) ^ ((a & 0x80) != 0 ? 0x11b : 0)) & 0xff; }

        static int Mul(int a, int b)
        {
            int r = 0;
            for (; b != 0; b >>= 1, a = Xtime(a)) if ((b & 1) != 0) r ^= a;
            return r;
        }

        static int Inverse(int a)
        {
            if (a == 0) return 0;
            for (int x = 1; x < 256; x++) if (Mul(a, x) == 1) return x;
            throw new InvalidOperationException("no inverse");
        }

        static int Rotl8(int v, int n) { return ((v << n) | (v >> (8 - n))) & 0xff; }

        public static int[] Sbox()
        {
            int[] s = new int[256];
            for (int x = 0; x < 256; x++)
            {
                int b = Inverse(x);
                s[x] = b ^ Rotl8(b, 1) ^ Rotl8(b, 2) ^ Rotl8(b, 3) ^ Rotl8(b, 4) ^ 0x63;
            }
            return s;
        }

        public static int[] InverseSbox(int[] s) { int[] inv = new int[256]; for (int x = 0; x < 256; x++) inv[s[x]] = x; return inv; }

        static ulong[] Ul(int[] a) { ulong[] r = new ulong[a.Length]; for (int i = 0; i < a.Length; i++) r[i] = (ulong)a[i]; return r; }

        static ulong Pack(int b0, int b1, int b2, int b3, bool bigEndian)
        {
            return bigEndian ? ((ulong)b0 << 24) | ((ulong)b1 << 16) | ((ulong)b2 << 8) | (ulong)b3
                             : ((ulong)b3 << 24) | ((ulong)b2 << 16) | ((ulong)b1 << 8) | (ulong)b0;
        }

        /// <summary>Word tables: column bytes [m0 x, m1 x, m2 x, m3 x] of f(x), every rotation and both byte orders, alone and joined.</summary>
        static void AddWordTables(Dictionary<string, ulong[]> into, string name, int[] f, int[] m)
        {
            foreach (bool be in new[] { true, false })
            {
                List<ulong[]> rots = new List<ulong[]>();
                for (int rot = 0; rot < 4; rot++)
                {
                    ulong[] t = new ulong[256];
                    for (int x = 0; x < 256; x++)
                    {
                        int v = f == null ? x : f[x];
                        int[] col = { Mul(v, m[(0 - rot + 4) % 4]), Mul(v, m[(1 - rot + 4) % 4]), Mul(v, m[(2 - rot + 4) % 4]), Mul(v, m[(3 - rot + 4) % 4]) };
                        t[x] = Pack(col[0], col[1], col[2], col[3], be);
                    }
                    into[name + (be ? ".be" : ".le") + ".rot" + rot] = t;
                    rots.Add(t);
                }
                ulong[] joined = new ulong[1024];
                for (int rot = 0; rot < 4; rot++) Array.Copy(rots[rot], 0, joined, rot * 256, 256);
                into[name + (be ? ".be" : ".le") + ".joined"] = joined;
            }
        }

        public static Dictionary<string, ulong[]> AesMath()
        {
            Dictionary<string, ulong[]> m = new Dictionary<string, ulong[]>();
            int[] s = Sbox(), inv = InverseSbox(s);
            m["sbox"] = Ul(s);
            m["inverse-sbox"] = Ul(inv);
            foreach (int k in new[] { 2, 3, 9, 11, 13, 14 })
            {
                int[] t = new int[256];
                for (int x = 0; x < 256; x++) t[x] = Mul(x, k);
                m["times" + k] = Ul(t);
            }
            AddWordTables(m, "te", s, new[] { 2, 1, 1, 3 });
            AddWordTables(m, "td", inv, new[] { 14, 9, 13, 11 });
            AddWordTables(m, "inv-mix", null, new[] { 14, 9, 13, 11 });   // InvMixColumns of a key byte, for the equivalent inverse cipher
            AddWordTables(m, "sbox-word", s, new[] { 1, 1, 1, 1 });
            AddWordTables(m, "inverse-sbox-word", inv, new[] { 1, 1, 1, 1 });
            int[] rcon = new int[10];
            int rc = 1;
            for (int i = 0; i < 10; i++) { rcon[i] = rc; rc = Xtime(rc); }
            m["rcon"] = Ul(rcon);
            ulong[] rconHigh = new ulong[10];
            for (int i = 0; i < 10; i++) rconHigh[i] = (ulong)rcon[i] << 24;
            m["rcon-high-byte"] = rconHigh;
            int[] shift = new int[16], invShift = new int[16];
            for (int i = 0; i < 16; i++)
            {
                int c = i / 4, r = i % 4;
                shift[i] = r + 4 * ((c + r) % 4);
                invShift[i] = r + 4 * ((c - r + 4) % 4);
            }
            // FIPS 197 section 5.1.3 and 5.3.3: the first row of the MixColumns and InvMixColumns matrices.
            m["mix-row"] = Ul(new[] { 2, 3, 1, 1 });
            m["inverse-mix-row"] = Ul(new[] { 14, 11, 13, 9 });
            m["shift-rows-map"] = Ul(shift);
            m["inverse-shift-rows-map"] = Ul(invShift);
            return m;
        }

        /// <summary>The 4-bit GHASH reduction table: entry i is the xor, over the set bits of i, of 0xE1 shifted into place (SP 800-38D).</summary>
        public static Dictionary<string, ulong[]> GhashMath()
        {
            Dictionary<string, ulong[]> m = new Dictionary<string, ulong[]>();
            ulong[] r16 = new ulong[16], r64 = new ulong[16], r8 = new ulong[256];
            for (int i = 0; i < 16; i++)
            {
                ulong v = 0;
                for (int b = 0; b < 4; b++) if ((i & (1 << b)) != 0) v ^= 0xE100UL >> (3 - b);
                r16[i] = v; r64[i] = v << 48;
            }
            for (int i = 0; i < 256; i++)
            {
                ulong v = 0;
                for (int b = 0; b < 8; b++) if ((i & (1 << b)) != 0) v ^= 0xE1000UL >> (7 - b);
                r8[i] = v;
            }
            m["ghash-reduce-4bit-16"] = r16;
            m["ghash-reduce-4bit-64"] = r64;
            m["ghash-reduce-8bit"] = r8;
            return m;
        }

        // ---- reading the product ----

        static ulong[] Values(Array a)
        {
            ulong[] r = new ulong[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                object o = a.GetValue(i);
                r[i] = o is int ? (ulong)(uint)(int)o : o is short ? (ulong)(ushort)(short)o : o is long ? (ulong)(long)o : o is sbyte ? (ulong)(byte)(sbyte)o : Convert.ToUInt64(o);
            }
            return r;
        }

        static bool Same(ulong[] a, ulong[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        public delegate bool InScope(Type t);

        public static List<Type> TypesIn(Assembly asm, string ns, InScope scope)
        {
            List<Type> r = new List<Type>();
            foreach (Type t in asm.GetTypes())
                if (t.Namespace == ns && scope(t)) r.Add(t);
            return r;
        }

        static List<FieldInfo> TableFields(Type t)
        {
            List<FieldInfo> r = new List<FieldInfo>();
            foreach (FieldInfo f in t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                if (f.FieldType.IsArray && f.FieldType.GetElementType().IsPrimitive && f.FieldType.GetArrayRank() == 1) r.Add(f);
            return r;
        }

        /// <summary>Every static table in the scope equals a table from the math. Returns the matched names; throws with the unmatched ones.</summary>
        public static string EqualsMath(List<Type> types, Dictionary<string, ulong[]> math)
        {
            List<string> matched = new List<string>(), unmatched = new List<string>();
            foreach (Type t in types)
                foreach (FieldInfo f in TableFields(t))
                {
                    Array a = (Array)f.GetValue(null);
                    string label = t.Name + "." + f.Name;
                    if (a == null) { unmatched.Add(label + " (null)"); continue; }
                    ulong[] v = Values(a);
                    string hit = null;
                    foreach (KeyValuePair<string, ulong[]> kv in math) if (Same(v, kv.Value)) { hit = kv.Key; break; }
                    if (hit == null) unmatched.Add(label + " (" + a.Length + " " + f.FieldType.GetElementType().Name + ")");
                    else matched.Add(label + "=" + hit);
                }
            if (unmatched.Count > 0) throw new FailException("AO_TABLE_UNMATCHED", unmatched.Count + " tables equal no table from the math: " + string.Join(", ", unmatched.ToArray()) + ". Matched: " + string.Join(", ", matched.ToArray()));
            if (matched.Count == 0) throw new NotRunException("NO_TABLES", "no static table in the scope (" + types.Count + " types)");
            return matched.Count + " of " + matched.Count + " tables equal the math: " + string.Join(", ", matched.ToArray());
        }

        // ---- start-up code: the IL of each type initializer ----

        static readonly Dictionary<short, OpCode> Ops = LoadOps();

        static Dictionary<short, OpCode> LoadOps()
        {
            Dictionary<short, OpCode> d = new Dictionary<short, OpCode>();
            foreach (FieldInfo f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                OpCode op = (OpCode)f.GetValue(null);
                d[op.Value] = op;
            }
            return d;
        }

        static int OperandSize(OpCode op, byte[] il, int at)
        {
            switch (op.OperandType)
            {
                case OperandType.InlineNone: return 0;
                case OperandType.ShortInlineBrTarget: case OperandType.ShortInlineI: case OperandType.ShortInlineVar: return 1;
                case OperandType.InlineVar: return 2;
                case OperandType.InlineI8: case OperandType.InlineR: return 8;
                case OperandType.InlineSwitch: return 4 + 4 * BitConverter.ToInt32(il, at);
                default: return 4;
            }
        }

        /// <summary>
        /// Null when the initializer only stores constants: no branch, and no call other than RuntimeHelpers.InitializeArray.
        /// A loop needs a branch, and a builder method needs a call, so either one names the type.
        /// </summary>
        public static string StartupBuild(Type t)
        {
            ConstructorInfo cctor = t.TypeInitializer;
            if (cctor == null) return null;
            MethodBody body = cctor.GetMethodBody();
            if (body == null) return null;
            byte[] il = body.GetILAsByteArray();
            for (int i = 0; i < il.Length;)
            {
                short code = il[i] == 0xFE ? (short)(0xFE00 | il[i + 1]) : (short)il[i];
                i += il[i] == 0xFE ? 2 : 1;
                OpCode op;
                if (!Ops.TryGetValue(code, out op)) return t.Name + ": unknown IL op 0x" + code.ToString("x");
                if (op.FlowControl == FlowControl.Branch || op.FlowControl == FlowControl.Cond_Branch) return t.Name + ": the type initializer branches (" + op.Name + "), so it computes";
                if (op.FlowControl == FlowControl.Call)
                {
                    MethodBase m = t.Module.ResolveMethod(BitConverter.ToInt32(il, i));
                    if (!(m.DeclaringType != null && m.DeclaringType.FullName == "System.Runtime.CompilerServices.RuntimeHelpers" && m.Name == "InitializeArray"))
                        return t.Name + ": the type initializer calls " + (m.DeclaringType == null ? "" : m.DeclaringType.Name + ".") + m.Name;
                }
                i += OperandSize(op, il, i);
            }
            return null;
        }

        public static string NoStartupBuild(List<Type> types)
        {
            List<string> bad = new List<string>();
            foreach (Type t in types) { string why = StartupBuild(t); if (why != null) bad.Add(why); }
            if (bad.Count > 0) throw new FailException("AO_TABLE_BUILT_AT_STARTUP", string.Join("; ", bad.ToArray()));
            return types.Count + " types read; no type initializer computes a table";
        }

        // ---- scopes and clauses ----

        public static bool AesScope(Type t) { return t.Name.StartsWith("Aes") && !t.Name.Contains("Walk") && !t.Name.Contains("Trace"); }
        public static bool GhashScope(Type t) { return t.Name.StartsWith("Gf128") || t.Name.StartsWith("Gcm") || t.Name.StartsWith("Ghash"); }

    }
}
