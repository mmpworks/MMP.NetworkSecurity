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

        public static byte[] Sbox() { return AesKey.SubstitutionTable(); }
        public static byte[] InverseSbox() { return AesKey.InverseSubstitutionTable(); }

        public static byte[] RealEncrypt(byte[] key, byte[] block) { byte[] o = new byte[16]; new AesKey(key).EncryptBlock(block, 0, o, 0); return o; }
        public static byte[] RealDecrypt(byte[] key, byte[] block) { byte[] o = new byte[16]; new AesKey(key).DecryptBlock(block, 0, o, 0); return o; }
    }
}
