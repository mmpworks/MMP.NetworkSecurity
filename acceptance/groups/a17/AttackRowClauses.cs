using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// prd.md line 93: "Every lesson has attack buttons. Each attack names the check that caught it." The count comes from the live Host's
    /// GET /api/lessons, which lists AttackCatalog, so the suite never counts the registry by text search. Each available row is forked
    /// through session.attack, and the fork must end with the row's code and name the row's check. The button half is the e2e clause
    /// A17.ui.every-attack-row-has-a-button.
    /// </summary>
    public static class AttackRowClauses
    {
        [Clause("A17.attacks.every-row-forks-to-its-code")]
        public static string EveryRowForksToItsCode(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-attack-rows"))
            {
                Reply lessons = HostHttp.Get(h, "/api/lessons");
                Check.True(lessons.Ok && lessons.Array != null, "GET /api/lessons got " + lessons);
                int rows = 0, caught = 0, noCheck = 0;
                List<string> unavailable = new List<string>(), notBuilt = new List<string>(), misses = new List<string>();
                foreach (object lo in lessons.Array)
                {
                    Dictionary<string, object> lesson = MiniJson.AsObject(lo);
                    int n = (int)MiniJson.Num(lesson, "lesson", -1);
                    List<object> attacks = MiniJson.Arr(lesson, "attacks") ?? new List<object>();
                    if (attacks.Count == 0) continue;
                    SessionRun parent = null;
                    foreach (object ao in attacks)
                    {
                        Dictionary<string, object> row = MiniJson.AsObject(ao);
                        string id = MiniJson.Str(row, "attackId");
                        rows++;
                        if (row.ContainsKey("available") && !MiniJson.Bool(row, "available", true))
                        {
                            if (string.IsNullOrEmpty(MiniJson.Str(row, "whyNot"))) misses.Add(id + ": unavailable and names no whyNot");
                            else unavailable.Add(id + " (" + MiniJson.Str(row, "whyNot") + ")");
                            continue;
                        }
                        if (parent == null)
                        {
                            parent = HostSession.Run(h, n, "glass", null);
                            if (parent.ErrorCode == "LESSON_NOT_BUILT") { notBuilt.Add("lesson " + n); }
                            else Check.True(parent.Error == null && parent.Finished != null, "the parent run of lesson " + n + " did not finish");
                        }
                        if (parent.ErrorCode == "LESSON_NOT_BUILT") { notBuilt.Add(id); continue; }
                        SessionRun fork = HostSession.Fork(h, parent.SessionId, id);
                        if (fork.Error != null || fork.Finished == null) { misses.Add(id + ": the fork did not finish: " + (fork.ErrorCode ?? (fork.Frames.Count == 0 ? "no frames" : fork.Frames[fork.Frames.Count - 1]))); continue; }
                        string expectCode = MiniJson.Str(row, "expectCode"), expectCheck = MiniJson.Str(row, "expectCheck");
                        string code = MiniJson.Str(fork.Finished, "code"), check = MiniJson.Str(fork.Finished, "check"), outcome = MiniJson.Str(fork.Finished, "outcome");
                        if (string.IsNullOrEmpty(expectCode))
                        {
                            // A row that expects no check (the attack goes through, or nothing catches it) must not end caught.
                            if (outcome == "caught") misses.Add(id + ": expects no check, and the fork was caught by '" + check + "' [" + code + "]");
                            else noCheck++;
                            continue;
                        }
                        if (code != expectCode) { misses.Add(id + ": the fork ended with code " + (code ?? "none") + ", and the row names " + expectCode); continue; }
                        if (string.IsNullOrEmpty(check)) { misses.Add(id + ": the fork ended with " + code + " and names no check"); continue; }
                        if (!string.IsNullOrEmpty(expectCheck) && !string.Equals(check, expectCheck, StringComparison.OrdinalIgnoreCase)) { misses.Add(id + ": the fork names the check '" + check + "', and the row names '" + expectCheck + "'"); continue; }
                        caught++;
                    }
                }
                Check.True(rows > 0, "GET /api/lessons lists no attack row");
                if (misses.Count > 0) throw new FailException(misses.Count + " of " + rows + " attack rows miss: " + string.Join("; ", misses.ToArray()));
                return rows + " attack rows on the live Host: " + caught + " forks end with their code and name their check, " + noCheck + " expect no check and are not caught"
                    + (unavailable.Count > 0 ? ", " + unavailable.Count + " unavailable with a reason: " + string.Join(", ", unavailable.ToArray()) : "")
                    + (notBuilt.Count > 0 ? ", not built: " + string.Join(", ", notBuilt.ToArray()) : "");
            }
        }
    }
}
