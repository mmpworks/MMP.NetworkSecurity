using System.Collections.Generic;
using NetSec.Crypto;

namespace Acceptance
{
    /// <summary>The one place where the A19 engine clauses touch product code (docs/walkthrough-design.md section 3.3). It maps the product's types to the suite's own, and computes nothing.</summary>
    static class WalkSubject
    {
        static WalkRun Map(AesBlockWalk w)
        {
            WalkRun r = new WalkRun();
            r.Rounds = w.Rounds; r.Input = WalkCheck.Lower(w.Input); r.Output = WalkCheck.Lower(w.Output);
            foreach (AesStep s in w.Steps)
            {
                WalkStep x = new WalkStep();
                x.Kind = s.Kind.ToString(); x.Round = s.Round; x.State = WalkCheck.Lower(s.State); x.RoundKey = WalkCheck.Lower(s.RoundKey);
                x.Terms = s.Terms == null ? null : MapTerms(s.Terms);
                r.Steps.Add(x);
            }
            return r;
        }

        public static WalkRun Encrypt(byte[] key, byte[] block) { return Map(new AesKey(key).WalkEncrypt(block)); }
        public static WalkRun Decrypt(byte[] key, byte[] block) { return Map(new AesKey(key).WalkDecrypt(block)); }

        public static IList<KeyRow> KeyWords(byte[] key)
        {
            List<KeyRow> rows = new List<KeyRow>();
            foreach (AesKeyWord w in new AesKey(key).WalkKeyExpansion())
            {
                KeyRow r = new KeyRow();
                r.Index = w.Index; r.Previous = WalkCheck.Lower(w.Previous); r.Rotated = WalkCheck.Lower(w.Rotated); r.Substituted = WalkCheck.Lower(w.Substituted);
                r.Rcon = WalkCheck.Lower(w.Rcon); r.AfterRcon = WalkCheck.Lower(w.AfterRcon); r.KeyBack = WalkCheck.Lower(w.KeyBack); r.Word = WalkCheck.Lower(w.Word);
                rows.Add(r);
            }
            return rows;
        }

        static List<ColumnByte> MapTerms(AesColumnByte[] terms)
        {
            List<ColumnByte> all = new List<ColumnByte>();
            foreach (AesColumnByte b in terms)
            {
                ColumnByte x = new ColumnByte();
                x.Result = b.Result.ToString("x2");
                foreach (AesTerm t in b.Terms)
                {
                    TermPart p = new TermPart();
                    p.Factor = t.Factor; p.Input = t.Input.ToString("x2"); p.Reduced = t.Reduced; p.Result = t.Result.ToString("x2");
                    foreach (AesDoubling d in t.Doublings ?? new AesDoubling[0])
                    {
                        Doubling y = new Doubling();
                        y.From = d.From.ToString("x2"); y.Shifted = d.Shifted; y.Reduced = d.Reduced; y.To = d.To.ToString("x2");
                        p.Doublings.Add(y);
                    }
                    foreach (byte q in t.Picks ?? new byte[0]) p.Picks.Add(q.ToString("x2"));
                    foreach (byte q in t.Sums ?? new byte[0]) p.Sums.Add(q.ToString("x2"));
                    x.Parts.Add(p);
                }
                foreach (byte q in b.Running ?? new byte[0]) x.Running.Add(q.ToString("x2"));
                all.Add(x);
            }
            return all;
        }

        public static IList<ColumnByte> MixTerms(byte[] before, bool inverse) { return MapTerms(AesKey.MixTerms(before, inverse)); }
        public static int[] ShiftMap(bool inverse) { return AesKey.ShiftMap(inverse); }
        public static byte[] RoundConstants(int count) { return AesKey.RoundConstants(count); }

        public static byte[] Sbox() { return AesKey.SubstitutionTable(); }
        public static byte[] InverseSbox() { return AesKey.InverseSubstitutionTable(); }

        public static byte[] RealEncrypt(byte[] key, byte[] block) { byte[] o = new byte[16]; new AesKey(key).EncryptBlock(block, 0, o, 0); return o; }
        public static byte[] RealDecrypt(byte[] key, byte[] block) { byte[] o = new byte[16]; new AesKey(key).DecryptBlock(block, 0, o, 0); return o; }
    }
}
