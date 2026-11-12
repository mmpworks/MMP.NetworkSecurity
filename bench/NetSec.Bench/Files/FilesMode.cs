using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace NetSec.Bench.Files;

/// <summary>
/// The --mode files entry point: load and check the file set, time every file and operation as an original/new pair, add the
/// small-message row, then the 25-thread shared-key runs last (they change the process thread pool), and write files-&lt;build&gt;.md
/// and the AO-9 part file. With --part TAG it is one part of the balanced crossover (<see cref="CrossoverPart"/>): it writes the paired
/// rows as cross-&lt;build&gt;-files-TAG.tsv, and part normal1 also runs the thread rows and writes them as a thread part; the combine
/// (<see cref="Crossover"/>) writes the AO-9 part from the code ratios.
/// </summary>
static class FilesMode
{
    const int PoolThreads = 25;   // the CF thread pool cap the PRD copies from MMP.GasPumpSimulator
    const string ThreadFile = "sample.csv";

    /// <summary>The id of the small-message row in a crossover part ("file|operation", like every file row).</summary>
    public const string SmallId = "64-byte message|key-setup+gcm-seal";

    /// <summary>The report's Original line. Echo's frozen copy is the only original; the bench makes no copy of its own.</summary>
    const string OriginalNote = "Echo's frozen 5c5d4a4 copy (acceptance/groups/algo/Frozen, acceptance/tools/freeze_ref.py), linked and compiled with the product build settings";

    public static string ThreadPartName(string filesBuild) => "cross-" + filesBuild + "-threads.tsv";

    public static int Run(Dictionary<string, string> a, Run run, bool sameCode)
    {
        if (!a.ContainsKey("files")) { Console.Error.WriteLine("BENCH_USAGE: --mode files needs --files DIR"); return 2; }
        a.TryGetValue("part", out string part);
        if (part != null && !CrossoverPart.IsTag(part)) { Console.Error.WriteLine("BENCH_USAGE: --part is one of " + string.Join(", ", CrossoverPart.Tags)); return 2; }
        bool swap = part != null && CrossoverPart.Swapped(part);
        int pairs = a.TryGetValue("pairs", out string pr) ? int.Parse(pr, CultureInfo.InvariantCulture) : FileBench.Pairs;
        List<TestFile> files = FileSet.Load(a["files"]);
        Console.WriteLine("BENCH_FILES_OK " + files.Count + " files match files.tsv");

        ICodeUnderTest frozen = new FrozenCode(), product = new ProductCode();
        ICodeUnderTest original = swap ? product : frozen, current = swap ? frozen : product;
        if (swap) Console.WriteLine("BENCH_SWAP original = product, new = frozen copy");
        if (part != null)
        {
            bool productFirst = CrossoverPart.JitFirst(part) == "product";
            FileBench.CompileFirst(files, productFirst ? product : frozen, productFirst ? frozen : product);
            Console.WriteLine("BENCH_JIT_FIRST " + CrossoverPart.JitFirst(part));
        }
        Action<FileRow> print = r => Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "{0,-16} {1,-20} original {2,8:F1} new {3,8:F1} MB/s ratio {4,6:F3} ({5:F3} to {6:F3}) new {7,12:F0} B/call",
            r.File, r.Operation, r.MegabytesPerSecond(r.Pair.Original), r.MegabytesPerSecond(r.Pair.New), r.Pair.MedianRatio,
            r.Pair.Ratios.Min(), r.Pair.Ratios.Max(), r.Pair.New.BytesPerCall) + string.Format(CultureInfo.InvariantCulture, " load {0:P1} core {1:P1} cpu {2}>{3}", r.Pair.OtherBusy, r.Pair.CoreBusy, r.Pair.CpuStart, r.Pair.CpuEnd));

        if (!MachineLoad.Settle()) return MachineLoad.BusyExit;
        string[] only = a.TryGetValue("ops", out string ops) ? ops.Split(',') : null;   // --ops a,b: a short check on those operations
        List<FileRow> fileRows = FileBench.Run(files, original, current, print, pairs, only);
        FileRow small = FileBench.SmallMessage(original, current, print, pairs);
        List<FileRow> rows = fileRows.Concat(new[] { small }).ToList();
        int busy = MachineLoad.Exit(rows.Select(r => r.Pair.OtherBusy).ToArray(), rows.Select(r => r.File + " " + r.Operation + ": " + r.Pair.TopOutside).ToArray());

        // The thread rows run once per crossover (in part normal1), last, as in a one-order run: they are not a paired measurement.
        List<ThreadRow> threads = new List<ThreadRow>();
        if (part == null || part == "normal1")
        {
            TestFile threadFile = files.First(f => f.Name == ThreadFile);
            Measure.Unpin();
            threads = new[] { frozen, product, product, frozen }.Select(c => FileBench.Threads(threadFile, c, PoolThreads, 8)).ToList();
            foreach (ThreadRow t in threads) Console.WriteLine("BENCH_THREADS " + t.Code + " " + t.TotalMegabytesPerSecond.ToString("F1", CultureInfo.InvariantCulture) + " MB/s, mismatches " + t.Mismatches + "; " + t.PoolCap);
        }
        int bad = threads.Sum(t => t.Mismatches);
        Console.WriteLine(run.CfLine);

        if (part != null)
        {
            string build = run.Build + "-files";
            CrossoverPart.Write(a["out"], build, part, Program.PartHeader(run, Report.Settings(FileBench.Round, pairs)),
                rows.Select(r => CrossoverPart.FromPair(r.File + "|" + r.Operation, "call", 1, r.BytesPerCall, r.Pair, swap, r.Pair.Original.BytesPerCall, r.Pair.New.BytesPerCall)).ToList());
            if (threads.Count > 0) File.WriteAllText(Path.Combine(a["out"], ThreadPartName(build)), WriteThreads(threads));
            Console.WriteLine("BENCH_PART_DONE " + build + " " + part + " " + rows.Count + " rows, thread mismatches " + bad);
            return bad != 0 ? 4 : busy;
        }

        AoParts.Write(a["out"], run.Build + "-files", AoFileRows.Rows(run.Build, fileRows, small, threads));
        File.WriteAllText(Path.Combine(a["out"], "files-" + run.Build + ".md"), FileReport.Markdown(run, OriginalNote, rows, threads));
        double[] ratios = rows.Select(r => r.Pair.MedianRatio).ToArray();
        Console.WriteLine("BENCH_NOISE " + NoiseBand.Describe(ratios));
        Console.WriteLine("BENCH_FILES_DONE " + run.Build + " " + rows.Count + " rows, thread mismatches " + bad);
        int band = Program.SameCodeExit(sameCode, ratios);
        return bad != 0 ? 4 : busy != 0 ? busy : band;
    }

    static string WriteThreads(IList<ThreadRow> threads)
    {
        System.Text.StringBuilder s = new System.Text.StringBuilder("code\tfile\tworkers\tcallsPerWorker\tmismatches\twallNs\ttotalMBps\tpeakWorkingSet\tpoolCap\n");
        foreach (ThreadRow t in threads)
            s.Append(string.Format(CultureInfo.InvariantCulture, "{0}\t{1}\t{2}\t{3}\t{4}\t{5:R}\t{6:R}\t{7}\t{8}\n",
                t.Code, t.File, t.Workers, t.CallsPerWorker, t.Mismatches, t.WallNs, t.TotalMegabytesPerSecond, t.PeakWorkingSet, t.PoolCap.Replace('\t', ' ')));
        return s.ToString();
    }

    public static List<ThreadRow> ReadThreads(string[] lines) => lines.Skip(1).Where(l => l.Length > 0).Select(l => l.Split('\t')).Select(f => new ThreadRow
    {
        Code = f[0], File = f[1], Workers = int.Parse(f[2], CultureInfo.InvariantCulture), CallsPerWorker = int.Parse(f[3], CultureInfo.InvariantCulture),
        Mismatches = int.Parse(f[4], CultureInfo.InvariantCulture), WallNs = double.Parse(f[5], CultureInfo.InvariantCulture),
        TotalMegabytesPerSecond = double.Parse(f[6], CultureInfo.InvariantCulture), PeakWorkingSet = long.Parse(f[7], CultureInfo.InvariantCulture), PoolCap = f[8],
    }).ToList();
}
