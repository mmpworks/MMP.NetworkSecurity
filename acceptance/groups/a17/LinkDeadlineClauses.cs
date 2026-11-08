using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Acceptance
{
    /// <summary>
    /// The link's read deadline and idle limits (Richard's #309, the lead's ask). The read deadline, 30,000 ms, is armed only while a side holds
    /// unconsumed input at some layer (part of a frame, record, handshake message, or SSH line or packet). A side that holds no partial input
    /// waits an idle limit set by role only: 60,000 ms for the side that opened the connection, 90,000 ms for the side that accepted it. Twice
    /// and three times the read deadline, so the side holding a partial record always times out first, and in a mutual wait the opener does, by
    /// a 30 s gap. A role rule cannot tie. Every expiry writes a check.result on the engine's own stream, "read deadline" or "idle limit".
    /// The checkable case: the drop fork L5-flip-record-length grows a record length by 256 bytes that never come (Labs.cs), so the client,
    /// which holds the cut-short Finished record, must end on "read deadline", and the server on "peer stayed until the end", in 20 of 20 runs.
    /// </summary>
    public static class LinkDeadlineClauses
    {
        public const string DropFork = "L5-flip-record-length";
        public const int Runs = 20;

        static string Side(Dictionary<string, object> ev)
        {
            string actor = MiniJson.Str(ev, "actor");
            if (!string.IsNullOrEmpty(actor)) return actor.ToLowerInvariant();
            string stream = MiniJson.Str(ev, "streamId") ?? "";
            int i = stream.IndexOf('/');
            return (i < 0 ? stream : stream.Substring(i + 1)).ToLowerInvariant();
        }

        static string CheckName(Dictionary<string, object> ev)
        {
            Dictionary<string, object> check = MiniJson.Obj(ev, "check");
            return MiniJson.Str(check, "name") ?? MiniJson.Str(ev, "message") ?? "";
        }

        /// <summary>The check names one side writes in one fork, in order.</summary>
        static List<string> Checks(SessionRun run, string side)
        {
            List<string> names = new List<string>();
            foreach (Dictionary<string, object> ev in run.Events)
                if (MiniJson.Str(ev, "type") == "check.result" && Side(ev).Contains(side)) names.Add(CheckName(ev));
            return names;
        }

        [Clause("A17.link.partial-holder-ends-on-read-deadline")]
        public static string PartialHolderEndsOnReadDeadline(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-link-deadline"))
            {
                SessionRun parent = HostSession.Run(h, 5, "glass", null);
                if (parent.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "lesson 5 is not built");
                Check.True(parent.Error == null && parent.Finished != null, "the parent run of lesson 5 did not finish: " + (parent.ErrorCode ?? "no finish"));
                // 20 forks, 4 at a time: each one waits out the 30 s read deadline, so one after another would take 10 minutes.
                SessionRun[] forks = new SessionRun[Runs];
                Parallel.For(0, Runs, new ParallelOptions { MaxDegreeOfParallelism = 4 }, i => { forks[i] = HostSession.Fork(h, parent.SessionId, DropFork); });
                List<string> misses = new List<string>();
                int clientDeadline = 0, serverPeerStayed = 0;
                for (int i = 0; i < Runs; i++)
                {
                    SessionRun f = forks[i];
                    if (f == null || f.Error != null || f.Finished == null) { misses.Add("run " + (i + 1) + ": the fork did not finish (" + (f == null ? "no run" : f.ErrorCode ?? "no finish") + ")"); continue; }
                    List<string> client = Checks(f, "client"), server = Checks(f, "server");
                    if (client.Contains("read deadline")) clientDeadline++;
                    else misses.Add("run " + (i + 1) + ": the client, which holds the cut-short Finished record, wrote no \"read deadline\" check (its checks: " + string.Join(", ", client.ToArray()) + ")");
                    if (client.Contains("peer stayed until the end")) misses.Add("run " + (i + 1) + ": the client wrote \"peer stayed until the end\", and the client is the side that times out");
                    if (server.Contains("peer stayed until the end")) serverPeerStayed++;
                    else misses.Add("run " + (i + 1) + ": the server did not end on \"peer stayed until the end\" (its checks: " + string.Join(", ", server.ToArray()) + ")");
                    // One side ends the run (Jared, #310): the server writes no timer check of its own, which is the race #309 removes.
                    if (server.Contains("read deadline") || server.Contains("idle limit")) misses.Add("run " + (i + 1) + ": the server also wrote a timer check (" + string.Join(", ", server.ToArray()) + "), so both sides timed out");
                }
                if (misses.Count > 0) throw new FailException(misses.Count + " misses in " + Runs + " runs of " + DropFork + ": " + string.Join("; ", misses.ToArray()));
                return "in " + Runs + " of " + Runs + " forks of " + DropFork + " the client (holder of the partial record) ends on \"read deadline\" (" + clientDeadline + ") and the server on \"peer stayed until the end\" (" + serverPeerStayed + "), and the client never writes \"peer stayed\", and the server writes no timer check";
            }
        }
    }
}
