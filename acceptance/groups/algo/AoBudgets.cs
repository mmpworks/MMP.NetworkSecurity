using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>The AO-5 budgets of acceptance/ao-budgets.tsv. A row with no line is held to 0 bytes (PRD 7.4 rule 3).</summary>
    public static class AoBudgets
    {
        public static double For(Ctx c, string rowId)
        {
            string path = Path.Combine(c.AcceptanceDir, "ao-budgets.tsv");
            if (!File.Exists(path)) throw new FailException("AO_BUDGETS_UNREADABLE", "acceptance/ao-budgets.tsv is missing");
            double found = 0;
            int lines = 0;
            foreach (string line in File.ReadAllLines(path))
            {
                if (line.StartsWith("#") || line.StartsWith("id\t") || line.Trim().Length == 0) continue;
                string[] f = line.Split('\t');
                if (f.Length != 5) throw new FailException("AO_BUDGETS_UNREADABLE", "acceptance/ao-budgets.tsv: a line needs 5 tab-separated fields: " + line);
                if (f[0] != rowId) continue;
                lines++;
                double b;
                if (!double.TryParse(f[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out b) || b < 0)
                    throw new FailException("AO_BUDGETS_UNREADABLE", "acceptance/ao-budgets.tsv: budget_bytes is not a number of 0 or more: " + line);
                if (b > 0 && f[4].Trim().Length == 0) throw new FailException("AO_BUDGET_NO_TRADEOFF", "acceptance/ao-budgets.tsv: " + rowId + " has a budget above 0 and no tradeoff PR");
                found = b;
            }
            if (lines > 1) throw new FailException("AO_BUDGET_TWICE", "acceptance/ao-budgets.tsv has " + lines + " lines for " + rowId);
            return found;
        }
    }
}
