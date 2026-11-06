using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Acceptance
{
    /// <summary>
    /// Proof that the A18 line clauses bite. Each entry of checks/engine_limits.json runs on a stand-in tour that holds its example line, which must PASS.
    /// Then one change each: a required word gone, the line split across two steps, no claim, a claim on the wrong source, a banned phrase. Each must FAIL.
    /// </summary>
    public static class SelfA18
    {
        const string Wrong = "Wikipedia, secondary source";

        static string Tour(string lesson, string[] stepTexts, string claimSource, string extraClaim)
        {
            StringBuilder sb = new StringBuilder("{\"lesson\":" + lesson + ",\"steps\":[");
            for (int i = 0; i < stepTexts.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("{\"id\":\"T-S").Append(i).Append("\",\"title\":\"A step\",\"text\":[").Append(MiniJson.Quote(stepTexts[i])).Append("],\"claims\":[");
                if (claimSource != null) sb.Append("{\"id\":\"T-C").Append(i).Append("\",\"text\":\"A claim.\",\"source\":").Append(MiniJson.Quote(claimSource)).Append('}');
                if (extraClaim != null) sb.Append(claimSource != null ? "," : "").Append("{\"id\":\"T-X\",\"text\":").Append(MiniJson.Quote(extraClaim)).Append(",\"source\":\"x\"}");
                sb.Append("]}");
            }
            return sb.Append("]}").ToString();
        }

        static string Status(Ctx c, string root, Dictionary<string, object> entry, string tour)
        {
            string id = MiniJson.Str(entry, "id");
            SelfA17Text.Put(root, "app/src/tours/lesson-" + ((int)MiniJson.Num(entry, "lesson", 0)).ToString("00") + ".json", tour);
            Dictionary<string, string> r = SelfA17Text.Docs(c, root, id);
            return r.ContainsKey(id) ? r[id] : "nothing";
        }

        static void MustFail(Ctx c, string root, Dictionary<string, object> entry, string tour, string change, ref int cases)
        {
            string got = Status(c, root, entry, tour);
            Check.True(got.StartsWith("FAIL:ASSERTION"), MiniJson.Str(entry, "id") + " should FAIL when " + change + ", gave " + got);
            cases++;
        }

        [Clause("SELF.a18-lines-bite")]
        public static string LinesBite(Ctx c)
        {
            string file = Path.Combine(c.AcceptanceDir, "checks", "engine_limits.json");
            Dictionary<string, object> limits = MiniJson.AsObject(MiniJson.Parse(File.ReadAllText(file, Encoding.UTF8)));
            string absent = MiniJson.Str(limits, "absent");
            int cases = 0, lines = 0;
            foreach (object o in MiniJson.Arr(limits, "lines"))
            {
                Dictionary<string, object> e = MiniJson.AsObject(o);
                string id = MiniJson.Str(e, "id"), example = MiniJson.Str(e, "example"), lesson = ((int)MiniJson.Num(e, "lesson", 0)).ToString();
                string source = MiniJson.Str(e, "source").Replace("\\", "");
                string root = Path.Combine(c.WorkDir, "a18", id);
                string good = Status(c, root, e, Tour(lesson, new[] { example }, source, null));
                Check.True(good.StartsWith("PASS"), id + " should PASS on its example line, gave " + good);
                cases++; lines++;

                foreach (object p in MiniJson.Arr(e, "require"))
                    MustFail(c, root, e, Tour(lesson, new[] { Regex.Replace(example, (string)p, "zz", RegexOptions.IgnoreCase) }, source, null), "the words of " + p + " are gone", ref cases);
                if (MiniJson.Bool(e, "needsAbsent", true))
                    MustFail(c, root, e, Tour(lesson, new[] { Regex.Replace(example, absent, "zz", RegexOptions.IgnoreCase) }, source, null), "nothing says the item is absent", ref cases);

                int mid = example.IndexOf(' ', example.Length / 2);
                MustFail(c, root, e, Tour(lesson, new[] { example.Substring(0, mid), example.Substring(mid) }, source, null), "the line is split across two steps", ref cases);
                MustFail(c, root, e, Tour(lesson, new[] { example }, null, null), "the step has no claim", ref cases);
                MustFail(c, root, e, Tour(lesson, new[] { example }, Wrong, null), "the claim cites the wrong source", ref cases);

                foreach (object p in MiniJson.Arr(e, "banAnywhere") ?? new List<object>())
                    MustFail(c, root, e, Tour(lesson, new[] { example }, source, "Keep this: " + p + "."), "a claim still says " + p, ref cases);
                if (MiniJson.Arr(e, "banInLine") != null)
                    MustFail(c, root, e, Tour(lesson, new[] { example + " The standard requires these." }, source, null), "the line ranks the standard's list", ref cases);
            }
            Check.True(lines == 8, "engine_limits.json should hold 8 lines, holds " + lines);
            return lines + " line clauses PASS on their example, and " + (cases - lines) + " one-change tours each FAIL";
        }
    }
}
