using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// AO-4: one set of key objects shared by every worker. Payloads run on ThreadPool.QueueUserWorkItem with the pool capped at 25
    /// (the CF pool size, as MMP.GasPumpSimulator src/GasPump.Dispenser/Program.cs caps it). Each run makes FRESH key objects, and the
    /// first 25 payloads wait at a gate until 25 workers hold one, so the first use of every key object happens on many threads at once.
    /// The fingerprint of each payload must equal the fingerprint from a single-thread run on another fresh set of key objects.
    /// </summary>
    public static class AoThreads
    {
        public const int PoolCap = 25;
        public const int DefaultPayloads = 100000, DefaultRuns = 10;

        sealed class Keys
        {
            public object Aes128, Aes192, Aes256, Tdes;
            public static Keys Make(AoSide s, byte[][] raw)
            {
                Keys k = new Keys();
                k.Aes128 = s.NewAes((byte[])raw[0].Clone()); k.Aes192 = s.NewAes((byte[])raw[1].Clone());
                k.Aes256 = s.NewAes((byte[])raw[2].Clone()); k.Tdes = s.NewTdes((byte[])raw[3].Clone());
                return k;
            }
            public object Aes(int i) { return i == 0 ? Aes128 : i == 1 ? Aes192 : Aes256; }
        }

        delegate void Payload(AoSide s, Keys k, AoRec rec);

        static readonly string[] HashAlgs = { "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512" };

        static Payload Draw(Rng r, byte[] hmacKey)
        {
            int op = r.Int(11), ki = r.Int(3);
            byte[] data = r.Bytes(AoDraw.Len(r, 1024));
            byte[] blocks = r.Bytes(AoDraw.Blocks(r, 16, 16));
            byte[] iv = r.Bytes(16), nonce = r.Bytes(r.Int(4) == 0 ? 16 : 12), aad = r.Bytes(AoDraw.Len(r, 64));
            byte[] ctr = AoDraw.NearWrapCounter(r);
            bool enc = r.Int(2) == 0;
            string alg = HashAlgs[r.Int(HashAlgs.Length)];
            int[] pieces = AoDraw.Pieces(r, data.Length, AoGrammar.BlockOf(alg));
            AoBlockCall aesCall = AoBlockCall.Draw(r, 16), tdesCall = AoBlockCall.Draw(r, 8);
            return delegate (AoSide s, Keys k, AoRec rec)
            {
                object a = k.Aes(ki);
                switch (op)
                {
                    case 0: aesCall.Run(delegate (byte[] i, int io, byte[] o, int oo) { s.AesEncrypt(a, i, io, o, oo); }, delegate (byte[] i, int io, byte[] o, int oo) { s.AesDecrypt(a, i, io, o, oo); }, rec); break;
                    case 1: rec.Add(s.Ecb(a, (byte[])blocks.Clone())); break;
                    case 2: rec.Add(s.Cbc(a, (byte[])iv.Clone(), (byte[])blocks.Clone(), enc)); break;
                    case 3: rec.Add(s.Ctr(a, (byte[])ctr.Clone(), (byte[])data.Clone())); break;
                    case 4:
                        {
                            byte[] sealedBytes = s.GcmSeal(a, (byte[])nonce.Clone(), (byte[])aad.Clone(), (byte[])data.Clone());
                            byte[] plain;
                            rec.Add(sealedBytes); rec.Add(s.GcmOpen(a, (byte[])nonce.Clone(), (byte[])aad.Clone(), sealedBytes, out plain)); rec.Add(plain);
                            break;
                        }
                    case 5: { byte[] tag = s.Cmac(a, (byte[])data.Clone()); rec.Add(tag); rec.Add(s.CmacVerify(a, (byte[])data.Clone(), tag)); break; }
                    case 6: tdesCall.Run(delegate (byte[] i, int io, byte[] o, int oo) { s.TdesEncrypt(k.Tdes, i, io, o, oo); }, delegate (byte[] i, int io, byte[] o, int oo) { s.TdesDecrypt(k.Tdes, i, io, o, oo); }, rec); break;
                    case 7:
                        {
                            IAoHash h = s.NewHash(alg);
                            int off = 0;
                            foreach (int n in pieces) { h.Update(data, off, n); off += n; }
                            rec.Add(h.Finish());
                            break;
                        }
                    case 8: rec.Add(s.Hmac(alg, (byte[])hmacKey.Clone(), (byte[])data.Clone())); break;
                    case 9: rec.Add(s.Shake(enc, (byte[])data.Clone(), new int[] { 17, 200 })); break;
                    default: rec.Add(s.HkdfExpand(alg, s.HkdfExtract(alg, null, (byte[])data.Clone()), (byte[])aad.Clone(), 1 + ki * 40)); break;
                }
            };
        }

        static string Fingerprint(AoRec r)
        {
            StringBuilder sb = new StringBuilder(r.Sig);
            foreach (byte[] b in r.Arrays) sb.Append('|').Append(Hex.Encode(b));
            foreach (string t in r.Texts) sb.Append('|').Append(t);
            using (SHA256 sha = SHA256.Create()) return Hex.Encode(sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString())));
        }

        static string RunOne(Payload p, AoSide s, Keys k)
        {
            AoRec rec = new AoRec();
            try { p(s, k, rec); }
            catch (Exception e) { rec.Sig = AoRec.SigOf(e); }
            return Fingerprint(rec);
        }

        /// <summary>Caps the pool at 25 and checks that the cap took. Returns the cap the pool reports.</summary>
        public static string CapPool()
        {
            int minW, minIo;
            ThreadPool.GetMinThreads(out minW, out minIo);
            bool lowered = ThreadPool.SetMinThreads(Math.Min(minW, PoolCap), Math.Min(minIo, PoolCap));
            bool capped = ThreadPool.SetMaxThreads(PoolCap, PoolCap);
            if (!capped) throw new FailException("AO_POOL_CAP_REFUSED", "ThreadPool.SetMaxThreads(25, 25) returned false (processors " + Environment.ProcessorCount + ")");
            ThreadPool.SetMinThreads(PoolCap, PoolCap);
            int w, io;
            ThreadPool.GetMaxThreads(out w, out io);
            if (w != PoolCap) throw new FailException("AO_POOL_CAP_REFUSED", "the pool reports " + w + " worker threads after the cap");
            return "pool max " + w + " workers, " + io + " io (processors " + Environment.ProcessorCount + (lowered ? "" : ", min unchanged") + ")";
        }

        /// <summary>Runs the payloads and returns the detail line, or throws with the first three mismatches.</summary>
        public static string Run(AoSide s, int payloads, int runs, ulong seed)
        {
            string pool = CapPool();
            int bad = 0, peak = 0;
            List<string> first = new List<string>();
            for (int run = 0; run < runs; run++)
            {
                Rng r = new Rng(seed + (ulong)run * 0x9E3779B97F4A7C15UL);
                byte[][] raw = { r.Bytes(16), r.Bytes(24), r.Bytes(32), r.Bytes(24) };
                byte[] hmacKey = r.Bytes(AoDraw.Len(r, 200));
                Payload[] work = new Payload[payloads];
                for (int i = 0; i < payloads; i++) work[i] = Draw(r, hmacKey);

                Keys single = Keys.Make(s, raw);
                string[] expected = new string[payloads];
                for (int i = 0; i < payloads; i++) expected[i] = RunOne(work[i], s, single);

                Keys shared = Keys.Make(s, raw);
                string[] got = new string[payloads];
                int left = payloads, active = 0, runPeak = 0, gateCount = 0;
                ManualResetEvent done = new ManualResetEvent(false), gate = new ManualResetEvent(false);
                for (int i = 0; i < payloads; i++)
                {
                    int at = i;
                    ThreadPool.QueueUserWorkItem(delegate (object unused)
                    {
                        int now = Interlocked.Increment(ref active);
                        int seen;
                        while ((seen = runPeak) < now && Interlocked.CompareExchange(ref runPeak, now, seen) != seen) { }
                        if (at < PoolCap)
                        {
                            if (Interlocked.Increment(ref gateCount) == PoolCap) gate.Set();
                            gate.WaitOne(5000);
                        }
                        got[at] = RunOne(work[at], s, shared);
                        Interlocked.Decrement(ref active);
                        if (Interlocked.Decrement(ref left) == 0) done.Set();
                    });
                }
                if (!done.WaitOne(TimeSpan.FromMinutes(20))) throw new FailException("AO_THREADS_STALLED", "run " + run + ": " + left + " payloads still open after 20 minutes");
                peak = Math.Max(peak, runPeak);
                for (int i = 0; i < payloads; i++)
                {
                    if (got[i] == expected[i]) continue;
                    bad++;
                    if (first.Count < 3) first.Add("run " + run + " payload " + i);
                }
            }
            string tail = "payloads " + payloads + " x runs " + runs + ", seed 0x" + seed.ToString("x16") + ", " + pool + ", peak concurrent workers " + peak + ", subject " + s.Name;
            if (bad > 0) throw new FailException("AO_THREAD_MISMATCH", bad + " payloads differ from the single-thread run (" + tail + "). First: " + string.Join(", ", first.ToArray()));
            if (peak < 2) throw new FailException("AO_NO_CONCURRENCY", "no two payloads ran at once, so the run proved nothing about threads (" + tail + ")");
            return (payloads * runs) + " of " + (payloads * runs) + " payloads equal the single-thread run (" + tail + ")";
        }

        public const ulong Seed = 0xA04A04A04A04A04UL;

        [Clause("AO-4.shared-key-objects-pool-25", PerBuild = true, TimeoutSec = 3600)]
        public static string SharedKeys(Ctx c)
        {
            int payloads = int.Parse(c.Prop("ao.payloads", DefaultPayloads.ToString()));
            int runs = int.Parse(c.Prop("ao.runs", DefaultRuns.ToString()));
            return Run(AoSubject.Make(c), payloads, runs, Seed);
        }
    }
}
