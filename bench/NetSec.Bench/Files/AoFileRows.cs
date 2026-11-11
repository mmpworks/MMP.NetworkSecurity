using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace NetSec.Bench.Files;

/// <summary>
/// The AO-9 rows of the bench report, as agreed with Echo: { id, outputsEqual, originalNsPerOp, newNsPerOp, files, op }.
/// For gcm, cbc, ctr, sha256 and hmac, each ns number is the sum over the file set of the median ns per call of each direction in the row.
/// small-message is one key setup plus one 64-byte seal. pool-25 is the mean wall time of the two thread runs of each copy.
/// outputsEqual: <see cref="FileBench"/> stops the run on any byte difference between the copies, so a file row that reaches here is true;
/// pool-25 is true only with no mismatch in any thread run.
/// </summary>
static class AoFileRows
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    static readonly (string Row, string[] Ops, string Op)[] Groups =
    {
        ("gcm", new[] { "gcm-seal", "gcm-open" }, "GCM seal plus open of each file, summed over the file set"),
        ("cbc", new[] { "cbc-encrypt", "cbc-decrypt" }, "CBC encrypt plus decrypt of each PKCS#7-padded file, summed over the file set"),
        ("ctr", new[] { "ctr-encrypt", "ctr-decrypt" }, "CTR encrypt plus decrypt of each file, summed over the file set"),
        ("sha256", new[] { "sha256" }, "SHA-256 of each file, summed over the file set"),
        ("hmac", new[] { "hmac-sha256" }, "HMAC-SHA256 of each file, summed over the file set"),
    };

    public static List<string> Rows(string build, IList<FileRow> fileRows, FileRow small, IList<ThreadRow> threads)
    {
        string suffix = build == "net10" ? "net10" : "cf";
        int files = fileRows.Select(r => r.File).Distinct().Count();
        List<string> rows = Groups.Select(g => Row("AO-9." + g.Row + "." + suffix, true,
            Sum(fileRows, g.Ops, r => r.Pair.Original), Sum(fileRows, g.Ops, r => r.Pair.New), files, g.Op)).ToList();
        rows.Add(Row("AO-9.small-message." + suffix, true, small.Pair.Original.MedianNs, small.Pair.New.MedianNs, 0,
            "one AES-128 key setup plus one GCM seal of 64 bytes"));
        ThreadRow last = threads.Last();
        rows.Add(Row("AO-9.pool-25." + suffix, threads.All(t => t.Mismatches == 0), MeanWall(threads, "original"), MeanWall(threads, "new"), 1,
            "mean wall time of 2 runs: " + last.Workers + " pool workers x " + last.CallsPerWorker + " GCM seals of " + last.File + " on one shared key"));
        return rows;
    }

    static double Sum(IList<FileRow> rows, string[] ops, System.Func<FileRow, Side> side) =>
        rows.Where(r => ops.Contains(r.Operation)).Sum(r => side(r).MedianNs);

    static double MeanWall(IList<ThreadRow> threads, string code) => threads.Where(t => t.Code == code).Average(t => t.WallNs);

    static string Row(string id, bool equal, double original, double current, int files, string op) => string.Format(Inv,
        "{{ \"id\": \"{0}\", \"outputsEqual\": {1}, \"originalNsPerOp\": {2:F2}, \"newNsPerOp\": {3:F2}, \"files\": {4}, \"op\": {5} }}",
        id, equal ? "true" : "false", original, current, files, Report.Quote(op));
}
