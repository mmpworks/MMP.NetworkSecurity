using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>One factor x input term of a mixed byte (docs/walkthrough-design.md section 3.3). Hex is lower case.</summary>
    public sealed class TermPart
    {
        public int Factor; public string Input, Result; public bool Reduced;
        public List<Doubling> Doublings = new List<Doubling>();
        public List<string> Picks = new List<string>(), Sums = new List<string>();
    }

    /// <summary>One field multiply by 2. Shifted is the 9-bit value before the reduction.</summary>
    public sealed class Doubling
    {
        public string From, To; public int Shifted; public bool Reduced;
    }

    /// <summary>The terms of one mixed byte. Result is the XOR of the parts.</summary>
    public sealed class ColumnByte
    {
        public string Result;
        public List<TermPart> Parts = new List<TermPart>();
        public List<string> Running = new List<string>();   // The XOR after each term. The last value is Result
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
            int result = 0;
            if ((factor & 1) != 0) { result = input; p.Picks.Add(input.ToString("x2")); p.Sums.Add(((byte)result).ToString("x2")); }
            byte d = input;
            for (int bit = 1; (factor >> bit) != 0; bit++)
            {
                Doubling step = new Doubling();
                step.From = d.ToString("x2"); step.Shifted = d << 1;
                bool over;
                d = Twice(d, out over);
                step.Reduced = over; step.To = d.ToString("x2");
                p.Reduced = p.Reduced || over;
                p.Doublings.Add(step);
                if (((factor >> bit) & 1) != 0)
                {
                    result ^= d;
                    p.Picks.Add(d.ToString("x2"));
                    p.Sums.Add(((byte)result).ToString("x2"));
                }
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
                        b.Running.Add(((byte)x).ToString("x2"));
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
                    Check.True(ap.Doublings.Count == ep.Doublings.Count, t + ": " + ap.Doublings.Count + " doublings, expected " + ep.Doublings.Count);
                    for (int k = 0; k < ep.Doublings.Count; k++)
                    {
                        Doubling ed = ep.Doublings[k], ad = ap.Doublings[k];
                        string at2 = t + ", doubling " + k;
                        Check.True(Same(ad.From, ed.From), at2 + ": from " + ad.From + ", expected " + ed.From);
                        Check.True(ad.Shifted == ed.Shifted, at2 + ": shifted " + ad.Shifted.ToString("x") + ", expected " + ed.Shifted.ToString("x"));
                        Check.True(ad.Reduced == ed.Reduced, at2 + ": reduced " + ad.Reduced + ", expected " + ed.Reduced);
                        Check.True(Same(ad.To, ed.To), at2 + ": to " + ad.To + ", expected " + ed.To);
                        // The design's rule, on the reply's own values: reduced means past 8 bits, and to is shifted, XOR 11b when reduced.
                        Check.True(ad.Reduced == (ad.Shifted > 0xff), at2 + ": reduced " + ad.Reduced + " with shifted " + ad.Shifted.ToString("x"));
                        Check.True(Hex.Decode(ad.To)[0] == (ad.Reduced ? ad.Shifted ^ 0x11b : ad.Shifted), at2 + ": to " + ad.To + " is not shifted " + ad.Shifted.ToString("x") + (ad.Reduced ? " XOR 11b" : ""));
                    }
                    Check.True(Same(string.Join(" ", ap.Picks.ToArray()), string.Join(" ", ep.Picks.ToArray())), t + ": picks " + string.Join(" ", ap.Picks.ToArray()) + ", expected " + string.Join(" ", ep.Picks.ToArray()));
                    Check.True(Same(string.Join(" ", ap.Sums.ToArray()), string.Join(" ", ep.Sums.ToArray())), t + ": sums " + string.Join(" ", ap.Sums.ToArray()) + ", expected " + string.Join(" ", ep.Sums.ToArray()));
                    Check.True(ap.Sums.Count > 0 && Same(ap.Sums[ap.Sums.Count - 1], ap.Result), t + ": the last sum is not the term's result " + ap.Result);
                    Check.True(Same(ap.Result, ep.Result), t + ": result " + ap.Result + ", expected " + ep.Result);
                    x ^= Hex.Decode(ap.Result)[0];
                    cells++;
                }
                Check.True(a.Running != null && a.Running.Count == 4, at + ": running should hold 4 values");
                Check.True(Same(string.Join(" ", a.Running.ToArray()), string.Join(" ", e.Running.ToArray())), at + ": running " + string.Join(" ", a.Running.ToArray()) + ", expected " + string.Join(" ", e.Running.ToArray()));
                Check.True(Same(a.Running[3], a.Result), at + ": the last running value is not the result " + a.Result);
                Check.True(Same(a.Result, ((byte)x).ToString("x2")), at + ": result " + a.Result + " is not the XOR of its terms, " + ((byte)x).ToString("x2"));
                Check.True(Same(a.Result, stateAfter.Substring(2 * i, 2)), at + ": result " + a.Result + " is not the state byte after the step, " + stateAfter.Substring(2 * i, 2));
            }
            return cells;
        }

        static bool Same(string a, string b) { return string.Equals(a, b, System.StringComparison.OrdinalIgnoreCase); }
    }
}
