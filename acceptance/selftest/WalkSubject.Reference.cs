using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// The stand-in for WalkSubject.Product.cs: RefAes, with one named defect at a time. SELF.walk-clauses-pass-and-bite runs the real clause bodies on it.
    /// "canned" answers every key and block with the FIPS C.1 walk, the shape of a stored table.
    /// </summary>
    static class WalkSubject
    {
        public static string Defect = "";

        static readonly byte[] CannedKey = Hex.Decode("000102030405060708090a0b0c0d0e0f"), CannedBlock = Hex.Decode("00112233445566778899aabbccddeeff");

        static void Flip(WalkStep s) { s.State = (s.State[0] == '0' ? "1" : "0") + s.State.Substring(1); }

        public static WalkRun Encrypt(byte[] key, byte[] block)
        {
            if (Defect == "canned") return new RefAes(CannedKey).Encrypt(CannedBlock);
            WalkRun r = new RefAes(key).Encrypt(block);
            if (Defect == "state-flip") Flip(r.Steps[1]);
            if (Defect == "extra-mix") r.Steps.Insert(r.Steps.Count - 1, new WalkStep { Kind = "MixColumns", Round = r.Rounds, State = r.Steps[r.Steps.Count - 2].State });
            if (Defect == "row-first") foreach (WalkStep s in r.Steps) s.State = RowFirst(s.State);
            if (Defect == "output-other") r.Output = Hex.Encode(new byte[16]);
            if (Defect == "steps-carry-no-terms") foreach (WalkStep s in r.Steps) s.Terms = null;
            if (Defect == "step-term-flip") foreach (WalkStep s in r.Steps) if (s.Terms != null) s.Terms[3].Parts[1].Result = "00";
            if (Defect == "no-spread") { r.Steps[4].State = new RefAes(new byte[16]).Encrypt(new byte[16]).Steps[4].State; }
            return r;
        }

        static string RowFirst(string hex)
        {
            string o = "";
            for (int row = 0; row < 4; row++) for (int col = 0; col < 4; col++) o += hex.Substring(2 * (row + 4 * col), 2);
            return o;
        }

        public static WalkRun Decrypt(byte[] key, byte[] block)
        {
            if (Defect == "canned") return new RefAes(CannedKey).Decrypt(Hex.Decode("69c4e0d86a7b0430d8cdb78070b4c55a"));
            WalkRun r = new RefAes(key).Decrypt(block);
            if (Defect == "inverse-flip") Flip(r.Steps[1]);
            if (Defect == "inverse-terms-forward") foreach (WalkStep s in r.Steps) if (s.Terms != null) s.Terms[0].Parts[0].Factor = 2;
            if (Defect == "equivalent-order")
            {
                // FIPS 197 section 5.3.5 order: the two steps change places in each middle round.
                for (int i = 1; i + 1 < r.Steps.Count; i++)
                    if (r.Steps[i].Kind == "InvShiftRows") { WalkStep a = r.Steps[i]; r.Steps[i] = r.Steps[i + 1]; r.Steps[i + 1] = a; }
            }
            return r;
        }

        public static IList<KeyRow> KeyWords(byte[] key)
        {
            List<KeyRow> rows = new RefAes(key).KeyRows;
            if (Defect == "key-row-flip") rows[rows.Count - 1].Word = "00000000";
            if (Defect == "rcon-empty") rows[rows.Count / 2 / 4 * 4].Rcon = null;
            return rows;
        }

        public static IList<ColumnByte> MixTerms(byte[] before, bool inverse)
        {
            List<ColumnByte> t = RefField.MixTerms(before, inverse);
            if (Defect == "term-wrong-result") t[0].Parts[0].Result = "00";
            if (Defect == "term-not-reduced") t[0].Parts[0].Reduced = false;
            if (Defect == "term-no-doublings") foreach (TermPart p in t[0].Parts) p.Doublings.Clear();
            if (Defect == "term-plain-multiply") t[0].Result = "ff";
            return t;
        }

        static readonly int[] SharedMap = RefField.ShiftMap(false);

        public static int[] ShiftMap(bool inverse)
        {
            if (Defect == "map-shared" && !inverse) return SharedMap;
            int[] m = RefField.ShiftMap(inverse);
            if (Defect == "map-swapped") { int a = m[1]; m[1] = m[5]; m[5] = a; }
            if (Defect == "map-right-for-left") return RefField.ShiftMap(!inverse);
            return m;
        }

        public static byte[] RoundConstants(int count)
        {
            byte[] r = RefField.RoundConstants(count);
            if (Defect == "rcon-plain-double" && count > 8) r[8] = 0x00;
            return r;
        }

        public static byte[] Sbox()
        {
            byte[] t = (byte[])RefAes.Sbox.Clone();
            if (Defect == "sbox-flip") t[200] ^= 1;
            return Defect == "shared-table" ? Shared : t;
        }

        static readonly byte[] Shared = (byte[])RefAes.Sbox.Clone();

        public static byte[] InverseSbox()
        {
            byte[] t = (byte[])RefAes.InverseSbox.Clone();
            if (Defect == "inverse-sbox-flip") t[200] ^= 1;
            return t;
        }

        public static byte[] RealEncrypt(byte[] key, byte[] block)
        {
            byte[] o = Hex.Decode(new RefAes(key).Encrypt(block).Output);
            if (Defect == "real-path-differs") o[0] ^= 1;
            return o;
        }

        public static byte[] RealDecrypt(byte[] key, byte[] block) { return Hex.Decode(new RefAes(key).Decrypt(block).Output); }
    }
}
