using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace NetSec.Bench.Files;

/// <summary>One measured row: one file and one operation, timed as a pair on the original and the new copy.</summary>
sealed class FileRow
{
    public string File, Operation;
    public int BytesPerCall;
    public Pair Pair;

    public double MegabytesPerSecond(Side s) => BytesPerCall / s.MedianNs * 1e9 / (1024 * 1024);
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
/// The AO-9 file benchmark. For each file and operation it first checks that the two copies give the same bytes, then times them as a
/// pair with <see cref="Measure"/> (alternating rounds of at least <see cref="Round"/>, a full GC before each round).
/// </summary>
static class FileBench
{
    // 250 ms per copy per round: at 30 MB/s that is about 2 calls on the 4 MiB file, so the call count never drops to a single call.
    public static readonly TimeSpan Round = TimeSpan.FromMilliseconds(250);

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

    public static List<FileRow> Run(IList<TestFile> files, ICodeUnderTest original, ICodeUnderTest current, Action<FileRow> progress)
    {
        IBoundCode o = original.Bind(AesKey, HmacKey), n = current.Bind(AesKey, HmacKey);
        List<FileRow> rows = new List<FileRow>();
        foreach (TestFile f in files)
            foreach (Op op in Ops(o))
            {
                byte[] input = op.Input(f);
                RequireSameBytes(f.Name, op.Name, op.Call(o, input), op.Call(n, input));
                FileRow row = new FileRow
                {
                    File = f.Name, Operation = op.Name, BytesPerCall = input.Length,
                    Pair = Measure.Run(() => Sink = op.Call(o, input), () => Sink = op.Call(n, input), Round),
                };
                rows.Add(row);
                progress(row);
            }
        return rows;
    }

    /// <summary>AO-9 rule 6: one key setup plus one 64-byte seal, as one call.</summary>
    public static FileRow SmallMessage(ICodeUnderTest original, ICodeUnderTest current, Action<FileRow> progress)
    {
        byte[] plain = Seq(64, 0x71);
        RequireSameBytes("64-byte message", "key-setup+gcm-seal", original.KeySetupAndSeal(AesKey, Nonce, Aad, plain), current.KeySetupAndSeal(AesKey, Nonce, Aad, plain));
        FileRow row = new FileRow
        {
            File = "64-byte message", Operation = "key-setup+gcm-seal", BytesPerCall = plain.Length,
            Pair = Measure.Run(() => Sink = original.KeySetupAndSeal(AesKey, Nonce, Aad, plain), () => Sink = current.KeySetupAndSeal(AesKey, Nonce, Aad, plain), Round),
        };
        progress(row);
        return row;
    }

    /// <summary>AO-9 rule 8. Each of 25 pool work items seals the file on one shared bound key; every output must equal the one-thread output.</summary>
    public static ThreadRow Threads(TestFile f, ICodeUnderTest code, int workers, int callsPerWorker)
    {
        IBoundCode b = code.Bind(AesKey, HmacKey);
        byte[] expected = b.GcmSeal(Nonce, Aad, f.Bytes);
        string cap = CapPool(workers);
        int mismatches = 0;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
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

    static void RequireSameBytes(string file, string op, byte[] original, byte[] current)
    {
        if (!current.SequenceEqual(original)) throw new InvalidOperationException("BENCH_OUTPUT_DIFFERS: " + file + " " + op + ": new differs from original");
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
