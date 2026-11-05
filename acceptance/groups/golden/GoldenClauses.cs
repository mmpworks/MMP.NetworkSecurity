using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;

namespace Acceptance
{
    /// <summary>
    /// A17.mock.golden-trace-equal (modes-design.md section 9.1, "Golden, by name"). With every key type built-in, each lab must give the traces it gave before the key work began.
    /// The recorder runs labs 0 to 10 in process, with FixedClock and the seed 20261105, and keeps every engine stream sorted by (StreamId, StreamSeq).
    /// Three things are left out, each by name:
    ///   1. every "&lt;streamId&gt;/wire" stream, since TCP chunking changes between runs;
    ///   2. lesson 11 as a whole, since its six event types (timing.lab.started, timing.samples, timing.managed, timing.verdict, timing.guess.finished, timing.failed)
    ///      hold Stopwatch samples and results that follow them, which leaves that lab nothing to compare. A12 still judges it;
    ///   3. the Host's "&lt;sessionId&gt;/keys" stream, which this in-process run never writes.
    /// One field is masked, in lab 9 only: atMicros, because lab 9 does not take its time from the clock it is given (see Mask).
    /// Files: acceptance/golden/&lt;build&gt;/lab-NN.ndjson. Record them with `pwsh acceptance/run.ps1 -Clauses A17.mock.golden-trace-equal -RecordGolden`, from a main
    /// that holds the step-gate fixes. The recorder runs each lab three times and refuses to write a lab whose three runs differ.
    /// </summary>
    public static class GoldenClauses
    {
        const int Seed = 20261105;
        static readonly int[] Labs = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        sealed class ByStream : IComparer<TraceEvent>
        {
            public int Compare(TraceEvent a, TraceEvent b)
            {
                int s = string.CompareOrdinal(a.StreamId, b.StreamId);
                return s != 0 ? s : a.StreamSeq.CompareTo(b.StreamSeq);
            }
        }

        static string[] Run(int lesson)
        {
            ILab lab = LabCatalog.Find(lesson);
            if (lab == null) throw new NotRunException("LESSON_NOT_BUILT", "the product has no lab for lesson " + lesson);
            ListSink sink = new ListSink();
            LabContext c = new LabContext();
            c.SessionId = "golden"; c.TraceId = "golden"; c.Seed = Seed;
            c.Gate = new FreeRunGate(); c.Sink = sink; c.Clock = new FixedClock(1); c.Random = new SeededRandom(Seed);
            LabResult result = Futs.Get(lab.Run(c), 180000, "lab " + lesson);
            List<TraceEvent> kept = new List<TraceEvent>();
            foreach (TraceEvent e in sink.Events) if (!e.StreamId.EndsWith("/wire")) kept.Add(e);
            kept.Sort(new ByStream());
            List<string> lines = new List<string>();
            foreach (TraceEvent e in kept) lines.Add(Mask(lesson, TraceJson.ToLine(e)));
            if (lines.Count == 0) throw new FailException("lab " + lesson + " wrote no engine events (completed " + result.Completed + ", " + result.FailedCode + ")");
            return lines.ToArray();
        }

        /// <summary>
        /// Lab 9 stamps some of its events with a real clock and not with the clock in LabContext (found by this recorder: the same seed gives a different atMicros on a rerun).
        /// Its atMicros is set to 0 before the lines are kept or compared. Every other lab keeps atMicros, which FixedClock holds steady.
        /// </summary>
        static string Mask(int lesson, string line)
        {
            return lesson == 9 ? System.Text.RegularExpressions.Regex.Replace(line, "\"atMicros\":\\d+", "\"atMicros\":0") : line;
        }

        static string FileOf(Ctx c, int lesson)
        {
            return Path.Combine(c.AcceptanceDir, "golden", c.Build, "lab-" + lesson.ToString("00") + ".ndjson");
        }

        [Clause("A17.mock.golden-trace-equal", PerBuild = true)]
        public static string GoldenTraceEqual(Ctx c)
        {
            bool record = c.Prop("golden.record", "") == "1";
            int compared = 0, events = 0;
            List<string> missing = new List<string>();
            foreach (int lesson in Labs)
            {
                string file = FileOf(c, lesson);
                if (!record && !File.Exists(file)) { missing.Add(lesson.ToString()); continue; }
                string[] now = Run(lesson);
                if (record)
                {
                    // A rerun must match, twice. A lab whose runs differ has no golden to keep.
                    for (int again = 0; again < 2; again++)
                    {
                        string[] other = Run(lesson);
                        int d = FirstDifference(now, other);
                        if (d >= 0) throw new FailException("lab " + lesson + " does not repeat: run " + (again + 2) + " differs from run 1 at line " + (d + 1) + ". Not recorded.\n  fields that differ: " + (d < now.Length && d < other.Length ? FieldDiff(now[d], other[d]) : "(a run has fewer lines: " + now.Length + " against " + other.Length + ")"));
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(file));
                    File.WriteAllText(file, string.Join("\n", now) + "\n", new UTF8Encoding(false));
                    compared++; events += now.Length;
                    continue;
                }
                string[] golden = File.ReadAllText(file, Encoding.UTF8).TrimEnd('\n').Split('\n');
                int diff = FirstDifference(golden, now);
                if (diff >= 0)
                    throw new FailException("lab " + lesson + " on built-in keys differs from its golden trace at line " + (diff + 1) + " of " + golden.Length + " (now " + now.Length + ").\n  golden: " + Cut(golden, diff) + "\n  now:    " + Cut(now, diff));
                compared++; events += now.Length;
            }
            if (record) return "recorded labs 0 to 10 for " + c.Build + " (" + events + " events), each run three times with the same lines";
            if (missing.Count == Labs.Length) throw new NotRunException("GOLDEN_NOT_RECORDED", "no golden trace is recorded for " + c.Build + " in acceptance/golden/" + c.Build + ". Record with: pwsh acceptance/run.ps1 -Clauses A17.mock.golden-trace-equal -RecordGolden");
            if (missing.Count > 0) throw new FailException("no golden trace for lab(s) " + string.Join(",", missing.ToArray()) + " although others are recorded");
            return compared + " labs (0 to 10, lesson 11 left out by name) give " + events + " engine events equal to the golden traces on " + c.Build + ", seed " + Seed;
        }

        static int FirstDifference(string[] a, string[] b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++) if (a[i] != b[i]) return i;
            return a.Length == b.Length ? -1 : n;
        }

        /// <summary>The JSON fields that differ between two event lines, so a person can see what moved (for instance a random cookie, a clock, or an id).</summary>
        static string FieldDiff(string a, string b)
        {
            try
            {
                Dictionary<string, object> x = MiniJson.AsObject(MiniJson.Parse(a)), y = MiniJson.AsObject(MiniJson.Parse(b));
                List<string> diffs = new List<string>();
                foreach (string k in x.Keys)
                {
                    string xv = MiniJson.Write(x[k]), yv = y.ContainsKey(k) ? MiniJson.Write(y[k]) : "(absent)";
                    if (xv != yv) diffs.Add(k + ": " + (xv.Length > 70 ? xv.Substring(0, 70) + ".." : xv) + " versus " + (yv.Length > 70 ? yv.Substring(0, 70) + ".." : yv));
                }
                return diffs.Count == 0 ? "(no field differs)" : string.Join("; ", diffs.ToArray());
            }
            catch (FormatException) { return "(not JSON)"; }
        }

        static string Cut(string[] lines, int i)
        {
            if (i >= lines.Length) return "(no line)";
            return lines[i].Length > 200 ? lines[i].Substring(0, 200) + "..." : lines[i];
        }
    }
}
