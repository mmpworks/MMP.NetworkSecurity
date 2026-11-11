using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace NetSec.Bench.Files;

/// <summary>
/// The --mode files entry point: load and check the file set, time every file and operation as an original/new pair, add the
/// small-message row, then the 25-thread shared-key runs last (they change the process thread pool), and write files-&lt;build&gt;.md
/// and the AO-9 part file.
/// </summary>
static class FilesMode
{
    const int PoolThreads = 25;   // the CF thread pool cap the PRD copies from MMP.GasPumpSimulator
    const string ThreadFile = "sample.csv";

    /// <summary>The report's Original line. Echo's frozen copy is the only original; the bench makes no copy of its own.</summary>
    const string OriginalNote = "Echo's frozen 5c5d4a4 copy (acceptance/groups/algo/Frozen, acceptance/tools/freeze_ref.py), linked and compiled with the product build settings";

    public static int Run(Dictionary<string, string> a, Run run, bool sameCode)
    {
        if (!a.ContainsKey("files")) { Console.Error.WriteLine("BENCH_USAGE: --mode files needs --files DIR"); return 2; }
        List<TestFile> files = FileSet.Load(a["files"]);
        Console.WriteLine("BENCH_FILES_OK " + files.Count + " files match files.tsv");

        ICodeUnderTest original = new FrozenCode(), current = new ProductCode();
        Action<FileRow> print = r => Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "{0,-16} {1,-20} original {2,8:F1} new {3,8:F1} MB/s ratio {4,6:F3} ({5:F3} to {6:F3}) new {7,12:F0} B/call",
            r.File, r.Operation, r.MegabytesPerSecond(r.Pair.Original), r.MegabytesPerSecond(r.Pair.New), r.Pair.MedianRatio,
            r.Pair.Ratios.Min(), r.Pair.Ratios.Max(), r.Pair.New.BytesPerCall) + string.Format(CultureInfo.InvariantCulture, " load {0:P1} core {1:P1}", r.Pair.OtherBusy, r.Pair.CoreBusy));

        if (!MachineLoad.Settle()) return MachineLoad.BusyExit;
        List<FileRow> fileRows = FileBench.Run(files, original, current, print);
        FileRow small = FileBench.SmallMessage(original, current, print);
        List<FileRow> rows = fileRows.Concat(new[] { small }).ToList();
        TestFile threadFile = files.First(f => f.Name == ThreadFile);
        Measure.Unpin();
        List<ThreadRow> threads = new[] { original, current, current, original }.Select(c => FileBench.Threads(threadFile, c, PoolThreads, 8)).ToList();
        foreach (ThreadRow t in threads) Console.WriteLine("BENCH_THREADS " + t.Code + " " + t.TotalMegabytesPerSecond.ToString("F1", CultureInfo.InvariantCulture) + " MB/s, mismatches " + t.Mismatches + "; " + t.PoolCap);

        AoParts.Write(a["out"], run.Build + "-files", AoFileRows.Rows(run.Build, fileRows, small, threads));
        File.WriteAllText(Path.Combine(a["out"], "files-" + run.Build + ".md"), FileReport.Markdown(run, OriginalNote, rows, threads));
        double[] ratios = rows.Select(r => r.Pair.MedianRatio).ToArray();
        Console.WriteLine("BENCH_NOISE " + NoiseBand.Describe(ratios));
        Console.WriteLine(run.CfLine);
        int bad = threads.Sum(t => t.Mismatches);
        Console.WriteLine("BENCH_FILES_DONE " + run.Build + " " + rows.Count + " rows, thread mismatches " + bad);
        int busy = MachineLoad.Exit(rows.Select(r => r.Pair.OtherBusy).ToArray());
        int band = Program.SameCodeExit(sameCode, ratios);
        return bad != 0 ? 4 : busy != 0 ? busy : band;
    }
}
