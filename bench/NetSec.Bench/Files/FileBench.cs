using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace NetSec.Bench.Files;

/// <summary>One measured row: one file, one operation, one copy of the code.</summary>
sealed class FileRow
{
    public string File, Operation, Code;
    public int BytesPerCall;
    public long CallsPerRun;
    public double[] NsPerCallRuns;
    public double BytesAllocatedPerCall;
    public int Gen0, Gen1, Gen2;
    public long PeakWorkingSet;

    public double MedianNs => NsPerCallRuns.OrderBy(v => v).ElementAt(NsPerCallRuns.Length / 2);
    public double MegabytesPerSecond => BytesPerCall / MedianNs * 1e9 / (1024 * 1024);
}

/// <summary>The shared-key thread run of AO-9 rule 8: total throughput and peak memory with 25 pool threads on one bound key.</summary>
sealed class ThreadRow
{
    public string Code, File;
    public int Workers, CallsPerWorker, Mismatches;
    public double TotalMegabytesPerSecond, WallNs;
    public long PeakWorkingSet;
    public string PoolCap;
}

/// <summary>
/// The AO-9 file benchmark. For each file and operation it first checks that every copy of the code gives the same bytes, then times each
/// copy in this process: a warm-up, then <see cref="Runs"/> runs of a fixed call count, each run lasting about <see cref="RunTarget"/>.
/// The garbage collection counts and allocated bytes cover the timed runs only; the peak working set is the process peak after the row.
/// </summary>
static class FileBench
{
    public const int Runs = 15;
    public static readonly TimeSpan RunTarget = TimeSpan.FromMilliseconds(60);
    static readonly TimeSpan WarmTarget = TimeSpan.FromMilliseconds(300);

    static readonly byte[] AesKey = Seq(16, 0x01), HmacKey = Seq(32, 0x21), Nonce = Seq(12, 0x41), Aad = Seq(13, 0x51), Iv = Seq(16, 0x61);
    public static object Sink;

    sealed class Op
    {
        public Op(string name, Func<TestFile, byte[]> input, Func<IBoundCode, byte[], byte[]> call) { Name = name; Input = input; Call = call; }
        public string Name { get; }
        public Func<TestFile, byte[]> Input { get; }
        public Func<IBoundCode, byte[], byte[]> Call { get; }
    }

    /// <summary>The operations of AO-9. Decrypt and open take the bytes that encrypt and seal made from the same file.</summary>
    static List<Op> Ops(IBoundCode reference) => new List<Op>
    {
        new Op("gcm-seal", f => f.Bytes, (c, x) => c.GcmSeal(Nonce, Aad, x)),
        new Op("gcm-open", f => reference.GcmSeal(Nonce, Aad, f.Bytes), (c, x) => c.GcmOpen(Nonce, Aad, x)),
        new Op("cbc-encrypt", f => f.Padded, (c, x) => c.CbcEncrypt(Iv, x)),
        new Op("cbc-decrypt", f => reference.CbcEncrypt(Iv, f.Padded), (c, x) => c.CbcDecrypt(Iv, x)),
        new Op("ctr-encrypt", f => f.Bytes, (c, x) => c.Ctr(Iv, x)),
        new Op("ctr-decrypt", f => reference.Ctr(Iv, f.Bytes), (c, x) => c.Ctr(Iv, x)),
        new Op("sha256", f => f.Bytes, (c, x) => c.Sha256(x)),
        new Op("hmac-sha256", f => f.Bytes, (c, x) => c.HmacSha256(x)),
    };

    public static List<FileRow> Run(IList<TestFile> files, IList<ICodeUnderTest> codes, Action<FileRow> progress)
    {
        List<IBoundCode> bound = codes.Select(c => c.Bind(AesKey, HmacKey)).ToList();
        List<FileRow> rows = new List<FileRow>();
        foreach (TestFile f in files)
            foreach (Op op in Ops(bound[0]))
            {
                byte[] input = op.Input(f);
                RequireSameBytes(f.Name, op.Name, codes, bound.Select(b => op.Call(b, input)).ToList());
                for (int i = 0; i < codes.Count; i++)
                {
                    IBoundCode b = bound[i];
                    FileRow row = Time(() => op.Call(b, input));
                    row.File = f.Name; row.Operation = op.Name; row.Code = codes[i].Name; row.BytesPerCall = input.Length;
                    rows.Add(row);
                    progress(row);
                }
            }
        return rows;
    }

    /// <summary>AO-9 rule 6: one key setup plus one 64-byte seal, as one call.</summary>
    public static List<FileRow> SmallMessage(IList<ICodeUnderTest> codes, Action<FileRow> progress)
    {
        byte[] plain = Seq(64, 0x71);
        RequireSameBytes("64-byte message", "key-setup+gcm-seal", codes, codes.Select(c => c.KeySetupAndSeal(AesKey, Nonce, Aad, plain)).ToList());
        List<FileRow> rows = new List<FileRow>();
        foreach (ICodeUnderTest c in codes)
        {
            FileRow row = Time(() => c.KeySetupAndSeal(AesKey, Nonce, Aad, plain));
            row.File = "64-byte message"; row.Operation = "key-setup+gcm-seal"; row.Code = c.Name; row.BytesPerCall = plain.Length;
            rows.Add(row);
            progress(row);
        }
        return rows;
    }

    /// <summary>AO-9 rule 8. Each of 25 pool work items seals the file on one shared bound key; every output must equal the one-thread output.</summary>
    public static ThreadRow Threads(TestFile f, ICodeUnderTest code, int workers, int callsPerWorker)
    {
        IBoundCode b = code.Bind(AesKey, HmacKey);
        byte[] expected = b.GcmSeal(Nonce, Aad, f.Bytes);
        string cap = CapPool(workers);
        int mismatches = 0;
        using (CountdownEvent done = new CountdownEvent(workers))
        {
            Stopwatch sw = Stopwatch.StartNew();
            for (int w = 0; w < workers; w++)
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        for (int i = 0; i < callsPerWorker; i++)
                            if (!b.GcmSeal(Nonce, Aad, f.Bytes).SequenceEqual(expected)) Interlocked.Increment(ref mismatches);
                    }
                    catch (Exception) { Interlocked.Increment(ref mismatches); }
                    finally { done.Signal(); }
                });
            done.Wait();
            sw.Stop();
            return new ThreadRow
            {
                Code = code.Name, File = f.Name, Workers = workers, CallsPerWorker = callsPerWorker, Mismatches = mismatches, PoolCap = cap,
                TotalMegabytesPerSecond = (double)f.Bytes.Length * workers * callsPerWorker / sw.Elapsed.TotalSeconds / (1024 * 1024),
                WallNs = sw.Elapsed.TotalMilliseconds * 1e6,
                PeakWorkingSet = PeakWorkingSet(),
            };
        }
    }

    /// <summary>Caps the pool at the CF limit and starts that many threads at once. Returns what the runtime accepted, for the report.</summary>
    static string CapPool(int n)
    {
        ThreadPool.SetMinThreads(n, n);
        bool maxSet = ThreadPool.SetMaxThreads(n, n);
        ThreadPool.GetMaxThreads(out int worker, out int io);
        return "SetMaxThreads(" + n + ", " + n + ") returned " + maxSet + "; max now " + worker + " worker, " + io + " io";
    }

    static void RequireSameBytes(string file, string op, IList<ICodeUnderTest> codes, IList<byte[]> outputs)
    {
        for (int i = 1; i < outputs.Count; i++)
            if (!outputs[i].SequenceEqual(outputs[0]))
                throw new InvalidOperationException("BENCH_OUTPUT_DIFFERS: " + file + " " + op + ": " + codes[i].Name + " differs from " + codes[0].Name);
    }

    static FileRow Time(Func<byte[]> call)
    {
        long calls = Warm(call);
        int g0 = GC.CollectionCount(0), g1 = GC.CollectionCount(1), g2 = GC.CollectionCount(2);
        long allocBefore = Allocated.Now();
        double[] runs = new double[Runs];
        for (int r = 0; r < Runs; r++)
        {
            Stopwatch sw = Stopwatch.StartNew();
            for (long i = 0; i < calls; i++) Sink = call();
            runs[r] = sw.Elapsed.TotalMilliseconds * 1e6 / calls;
        }
        long allocAfter = Allocated.Now();
        return new FileRow
        {
            CallsPerRun = calls, NsPerCallRuns = runs, BytesAllocatedPerCall = (double)(allocAfter - allocBefore) / (calls * Runs),
            Gen0 = GC.CollectionCount(0) - g0, Gen1 = GC.CollectionCount(1) - g1, Gen2 = GC.CollectionCount(2) - g2, PeakWorkingSet = PeakWorkingSet(),
        };
    }

    /// <summary>Calls until the warm-up time has passed, doubling the batch until one batch lasts a run target. Returns the calls for one run.</summary>
    static long Warm(Func<byte[]> call)
    {
        long batch = 1;
        Stopwatch total = Stopwatch.StartNew();
        while (true)
        {
            Stopwatch one = Stopwatch.StartNew();
            for (long i = 0; i < batch; i++) Sink = call();
            bool longEnough = one.Elapsed >= RunTarget;
            if (longEnough && total.Elapsed >= WarmTarget) return batch;
            if (!longEnough) batch *= 2;
        }
    }

    static long PeakWorkingSet()
    {
        using (Process p = Process.GetCurrentProcess()) return p.PeakWorkingSet64;
    }

    static byte[] Seq(int n, byte start)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)(start + i * 7);
        return b;
    }
}
