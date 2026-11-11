using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace NetSec.Bench.Files;

/// <summary>
/// The --mode files entry point: load and check the file set, time every file and operation on both copies of the code, add the
/// small-message rows, then the 25-thread shared-key run last (it changes the process thread pool), and write files-&lt;build&gt;.md.
/// </summary>
static class FilesMode
{
    const int PoolThreads = 25;   // the CF thread pool cap the PRD copies from MMP.GasPumpSimulator
    const string ThreadFile = "sample.csv";

    public static int Run(Dictionary<string, string> a, string build, string cfLine)
    {
        if (!a.ContainsKey("files")) { Console.Error.WriteLine("BENCH_USAGE: --mode files needs --files DIR"); return 2; }
        List<TestFile> files = FileSet.Load(a["files"]);
        Console.WriteLine("BENCH_FILES_OK " + files.Count + " files match files.tsv");

        List<ICodeUnderTest> codes = new List<ICodeUnderTest> { new FrozenCode(), new ProductCode() };
        Action<FileRow> print = r => Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "{0,-16} {1,-20} {2,-9} {3,9:F1} MB/s {4,12:F0} B/call gen {5}/{6}/{7}", r.File, r.Operation, r.Code, r.MegabytesPerSecond,
            r.BytesAllocatedPerCall, r.Gen0, r.Gen1, r.Gen2));

        List<FileRow> fileRows = FileBench.Run(files, codes, print);
        List<FileRow> small = FileBench.SmallMessage(codes, print);
        List<FileRow> rows = fileRows.Concat(small).ToList();
        TestFile threadFile = files.First(f => f.Name == ThreadFile);
        List<ThreadRow> threads = codes.Select(c => FileBench.Threads(threadFile, c, PoolThreads, 8)).ToList();
        foreach (ThreadRow t in threads) Console.WriteLine("BENCH_THREADS " + t.Code + " " + t.TotalMegabytesPerSecond.ToString("F1", CultureInfo.InvariantCulture) + " MB/s, mismatches " + t.Mismatches + "; " + t.PoolCap);

        AoParts.Write(a["out"], build + "-files", AoFileRows.Rows(build, fileRows, small, threads));
        File.WriteAllText(Path.Combine(a["out"], "files-" + build + ".md"), FileReport.Markdown(build, a["head"], OriginalNote, rows, threads, cfLine));
        Console.WriteLine(cfLine);
        int bad = threads.Sum(t => t.Mismatches);
        Console.WriteLine("BENCH_FILES_DONE " + build + " " + rows.Count + " rows, thread mismatches " + bad);
        return bad == 0 ? 0 : 4;
    }

    /// <summary>The report's Original line. Echo's frozen copy is the only original; the bench makes no copy of its own.</summary>
    const string OriginalNote = "Echo's frozen 5c5d4a4 copy (acceptance/groups/algo/Frozen, acceptance/tools/freeze_ref.py), linked and compiled with the product build settings";
}
