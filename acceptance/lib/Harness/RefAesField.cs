using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>One factor x input term of a mixed byte (docs/walkthrough-design.md section 3.3). Hex is lower case.</summary>
    public sealed class TermPart
    {
        public int Factor; public string Input, Result; public bool Reduced;
        public List<string> Doublings = new List<string>();
    }

    /// <summary>The terms of one mixed byte. Result is the XOR of the parts.</summary>
    public sealed class ColumnByte
    {
        public string Result;
        public List<TermPart> Parts = new List<TermPart>();
    }

    /// <summary>The suite's own field terms, shift maps and round constants, from FIPS 197 sections 4.2, 5.1.2, 5.1.3, 5.2 and 5.3. It shares no code with NetSec.Core.</summary>
    public static class RefField
    {
        static readonly int[] Forward = new int[] { 2, 3, 1, 1 }, Inverse = new int[] { 14, 11, 13, 9 };

        static byte Twice(byte b, out bool reduced)
        {
            reduced = (b & 0x80) != 0;
            return (byte)((b << 1) ^ (reduced ? 0x1b : 0));
        }

        public static TermPart Part(int factor, byte input)
        {
            TermPart p = new TermPart();
            p.Factor = factor; p.Input = input.ToString("x2");
            int result = (factor & 1) != 0 ? input : 0;
            byte d = input;
            for (int bit = 1; (factor >> bit) != 0; bit++)
            {
                bool over;
                d = Twice(d, out over);
                p.Reduced = p.Reduced || over;
                p.Doublings.Add(d.ToString("x2"));
                if (((factor >> bit) & 1) != 0) result ^= d;
            }
            p.Result = ((byte)result).ToString("x2");
            return p;
        }

        /// <summary>One entry per state byte, in r + 4c order.</summary>
        public static List<ColumnByte> MixTerms(byte[] before, bool inverse)
        {
            int[] m = inverse ? Inverse : Forward;
            List<ColumnByte> all = new List<ColumnByte>();
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                {
                    ColumnByte b = new ColumnByte();
                    int x = 0;
                    for (int j = 0; j < 4; j++)
                    {
                        TermPart p = Part(m[(j - r + 4) % 4], before[4 * c + j]);
                        x ^= Hex.Decode(p.Result)[0];
                        b.Parts.Add(p);
                    }
                    b.Result = ((byte)x).ToString("x2");
                    all.Add(b);
                }
            return all;
        }

        /// <summary>state[i] after the step equals state[map[i]] before it.</summary>
        public static int[] ShiftMap(bool inverse)
        {
            int[] map = new int[16];
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    map[r + 4 * c] = r + 4 * ((c + (inverse ? 4 - r : r)) % 4);
            return map;
        }

        public static byte[] RoundConstants(int count)
        {
            byte[] rc = new byte[count];
            byte v = 1;
            for (int i = 0; i < count; i++) { rc[i] = v; bool over; v = Twice(v, out over); }
            return rc;
        }

        /// <summary>A FAIL at the first term that differs from the suite's own terms, or that does not XOR to the byte in the state after the step.</summary>
        public static int Compare(string where, List<ColumnByte> expected, IList<ColumnByte> actual, string stateAfter)
        {
            Check.True(actual != null && actual.Count == 16, where + ": " + (actual == null ? 0 : actual.Count) + " mixed bytes, expected 16");
            int cells = 0;
            for (int i = 0; i < 16; i++)
            {
                ColumnByte e = expected[i], a = actual[i];
                string at = where + ", byte " + i;
                Check.True(a.Parts != null && a.Parts.Count == 4, at + ": expected 4 terms");
                int x = 0;
                for (int j = 0; j < 4; j++)
                {
                    TermPart ep = e.Parts[j], ap = a.Parts[j];
                    string t = at + ", term " + j;
                    Check.True(ap.Factor == ep.Factor, t + ": factor " + ap.Factor + ", expected " + ep.Factor);
                    Check.True(Same(ap.Input, ep.Input), t + ": input " + ap.Input + ", expected " + ep.Input);
                    Check.True(ap.Reduced == ep.Reduced, t + ": reduced " + ap.Reduced + ", expected " + ep.Reduced);
                    Check.True(Same(string.Join(" ", ap.Doublings.ToArray()), string.Join(" ", ep.Doublings.ToArray())), t + ": doublings " + string.Join(" ", ap.Doublings.ToArray()) + ", expected " + string.Join(" ", ep.Doublings.ToArray()));
                    Check.True(Same(ap.Result, ep.Result), t + ": result " + ap.Result + ", expected " + ep.Result);
                    x ^= Hex.Decode(ap.Result)[0];
                    cells++;
                }
                Check.True(Same(a.Result, ((byte)x).ToString("x2")), at + ": result " + a.Result + " is not the XOR of its terms, " + ((byte)x).ToString("x2"));
                Check.True(Same(a.Result, stateAfter.Substring(2 * i, 2)), at + ": result " + a.Result + " is not the state byte after the step, " + stateAfter.Substring(2 * i, 2));
            }
            return cells;
        }

        static bool Same(string a, string b) { return string.Equals(a, b, System.StringComparison.OrdinalIgnoreCase); }
    }
}
