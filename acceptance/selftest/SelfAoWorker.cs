using System;
using System.Collections.Generic;
using System.Threading;

namespace Acceptance
{
    /// <summary>In the selftest build the worker rows look at the stand-ins below.</summary>
    public static class AoWorkerSource
    {
        public static AoWorkerEnv Get(Ctx c)
        {
            AoWorkerEnv e = new AoWorkerEnv();
            e.Asm = typeof(AoWorkerSource).Assembly;
            e.Ns = "Acceptance.WorkerStandIn";
            return e;
        }
    }

    public static class SelfAoWorker
    {
        delegate string Body(Ctx c);

        static string Run(Body b, Ctx c)
        {
            try { return "PASS " + b(c); }
            catch (NotRunException e) { return "NOT RUN " + e.Reason + " " + e.Message; }
            catch (FailException e) { return "FAIL " + e.Reason + " " + e.Message; }
        }

        static Ctx Small(Ctx c)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot; n.WorkDir = c.WorkDir; n.VectorsDir = c.VectorsDir;
            n.Props["ao.payloads"] = "3000"; n.Props["ao.runs"] = "2"; n.Props["ao.wait-sec"] = "60";
            return n;
        }

        /// <summary>
        /// The worker rows against a faithful stand-in (each PASSes) and against one planted fault each (each must FAIL with the named
        /// reason). The stand-in follows PRD 7.3 items 2, 4 to 11 on the frozen Gcm.
        /// </summary>
        [Clause("SELF.ao4-worker-rows-bite", TimeoutSec = 1800)]
        public static string WorkerRowsBite(Ctx c)
        {
            Ctx x = Small(c);
            List<string> lines = new List<string>();
            WorkerStandIn.Faults.Set("");
            foreach (KeyValuePair<string, Body> row in Rows())
            {
                string got = Run(row.Value, x);
                if (!got.StartsWith("PASS")) throw new FailException(row.Key + " did not PASS on the faithful stand-in: " + got);
            }
            string[][] planted = {
                new[] { "round-trip", "wrong-id", "FAIL AO_WORKER_MISMATCH" }, new[] { "round-trip", "decode-skips-tag", "FAIL AO_WORKER_MISMATCH" },
                new[] { "round-trip", "nonce-length-unchecked", "FAIL AO_WORKER_MISMATCH" },
                new[] { "known-answer", "aad-little-endian", "FAIL ASSERTION" },
                new[] { "dispose", "idle-never-set", "FAIL AO_IDLE_TIMEOUT" }, new[] { "dispose", "blocks-when-full", "FAIL AO_WORKER_BLOCKED" },
                new[] { "dispose", "accepts-after-dispose", "FAIL AO_WORKER_AFTER_DISPOSE" }, new[] { "dispose", "drops-queued-on-dispose", "FAIL AO_WORKER_LOST_PAYLOAD" },
                new[] { "shared-gcmkey", "gcm-shared-scratch", "FAIL AO_THREAD_MISMATCH" },
            };
            Dictionary<string, Body> rows = new Dictionary<string, Body>();
            foreach (KeyValuePair<string, Body> kv in Rows()) rows[kv.Key] = kv.Value;
            foreach (string[] p in planted)
            {
                WorkerStandIn.Faults.Set(p[1]);
                string got;
                try { got = Run(rows[p[0]], x); }
                finally { WorkerStandIn.Faults.Set(""); }
                if (!got.StartsWith(p[2])) throw new FailException(p[0] + " did not catch the planted fault " + p[1] + ": " + got.Substring(0, Math.Min(200, got.Length)));
                lines.Add(p[0] + "/" + p[1] + ": " + p[2]);
            }
            return "4 worker rows PASS on the faithful stand-in; " + planted.Length + " planted faults each FAIL as named: " + string.Join("; ", lines.ToArray());
        }

        static List<KeyValuePair<string, Body>> Rows()
        {
            List<KeyValuePair<string, Body>> r = new List<KeyValuePair<string, Body>>();
            r.Add(new KeyValuePair<string, Body>("known-answer", AoWorker.KnownAnswer));
            r.Add(new KeyValuePair<string, Body>("round-trip", AoWorker.RoundTrip));
            r.Add(new KeyValuePair<string, Body>("dispose", AoWorker.DisposeDrains));
            r.Add(new KeyValuePair<string, Body>("shared-gcmkey", AoWorker.SharedGcmKey));
            return r;
        }
    }
}

namespace Acceptance.WorkerStandIn
{
    public static class Faults
    {
        static string _f = "";
        public static void Set(string f) { _f = f; }
        public static bool Is(string f) { return _f == f; }
    }

    /// <summary>A GcmKey stand-in on the frozen Gcm. The planted fault keeps one scratch nonce per key, used with no lock.</summary>
    public sealed class GcmKey
    {
        readonly object _aes;
        readonly byte[] _scratch = new byte[12];
        readonly bool _racy;
        public GcmKey(byte[] key) { _aes = new FrozenSide().NewAes(key); _racy = Faults.Is("gcm-shared-scratch"); }
        public byte[] Seal(byte[] nonce, byte[] aad, byte[] plain)
        {
            if (!_racy || nonce == null || nonce.Length != 12) return new FrozenSide().GcmSeal(_aes, nonce, aad, plain);
            Buffer.BlockCopy(nonce, 0, _scratch, 0, 12);
            Thread.SpinWait(200);
            return new FrozenSide().GcmSeal(_aes, (byte[])_scratch.Clone(), aad, plain);
        }
        public bool TryOpen(byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { return new FrozenSide().GcmOpen(_aes, nonce, aad, sealedBytes, out plain); }
    }

    public sealed class PayloadResult
    {
        public int Id; public byte[] Bytes; public string Code;
        public static PayloadResult Of(int id, byte[] b, string code) { PayloadResult r = new PayloadResult(); r.Id = id; r.Bytes = b; r.Code = code; return r; }
    }

    /// <summary>PRD 7.3 items 4 to 11: counter, volatile disposed flag, decrement in finally, catch on the pool thread, Idle as a drain signal.</summary>
    public sealed class AesPayloadWorker : IDisposable
    {
        readonly GcmKey _key; readonly int _max; readonly Action<WaitCallback> _dispatch;
        int _pending; volatile bool _disposed;
        readonly ManualResetEvent _idle = new ManualResetEvent(true);
        readonly string _fault;
        public WaitHandle Idle { get { return _idle; } }

        public AesPayloadWorker(GcmKey key, int maxQueued) : this(key, maxQueued, delegate (WaitCallback cb) { ThreadPool.QueueUserWorkItem(cb); }) { }
        public AesPayloadWorker(GcmKey key, int maxQueued, Action<WaitCallback> dispatch)
        {
            _key = key; _max = maxQueued; _dispatch = dispatch;
            foreach (string f in new[] { "wrong-id", "decode-skips-tag", "nonce-length-unchecked", "aad-little-endian", "idle-never-set", "blocks-when-full", "accepts-after-dispose", "drops-queued-on-dispose" })
                if (Faults.Is(f)) _fault = f;
        }

        byte[] Aad(int id)
        {
            return _fault == "aad-little-endian" ? new byte[] { (byte)id, (byte)(id >> 8), (byte)(id >> 16), (byte)(id >> 24) }
                                                 : new byte[] { (byte)(id >> 24), (byte)(id >> 16), (byte)(id >> 8), (byte)id };
        }

        bool Enter()
        {
            if (_fault == "blocks-when-full") while (Thread.VolatileRead(ref _pending) >= _max) Thread.Sleep(5);
            if (Interlocked.Increment(ref _pending) > _max) { Leave(); return false; }
            _idle.Reset();
            if (_disposed && _fault != "accepts-after-dispose") { Leave(); return false; }
            return true;
        }

        void Leave() { if (Interlocked.Decrement(ref _pending) == 0 && !(_fault == "idle-never-set" && _disposed)) _idle.Set(); }

        bool Queue(Action<PayloadResult> done, Func<PayloadResult> work)
        {
            if (!Enter()) return false;
            try
            {
                _dispatch(delegate (object s)
                {
                    try
                    {
                        if (_disposed && _fault == "drops-queued-on-dispose") return;
                        PayloadResult r;
                        try { r = work(); } catch (Exception e) { r = PayloadResult.Of(-1, null, AoRec.SigOf(e)); }
                        try { done(r); } catch (Exception) { }
                    }
                    finally { Leave(); }
                });
                return true;
            }
            catch (Exception) { Leave(); return false; }
        }

        public bool TryEncode(int id, byte[] nonce, byte[] plain, Action<PayloadResult> done)
        {
            return Queue(done, delegate
            {
                if ((nonce == null || nonce.Length != 12) && _fault != "nonce-length-unchecked") return PayloadResult.Of(id, null, "PAYLOAD_NONCE_LENGTH");
                byte[] n = nonce.Length == 12 ? nonce : Hex.Concat(nonce, new byte[12 - Math.Min(12, nonce.Length)]);
                byte[] sealedBytes = _key.Seal(n, Aad(id), plain);
                return PayloadResult.Of(_fault == "wrong-id" && id % 997 == 5 ? id + 1 : id, Hex.Concat(n, sealedBytes), null);
            });
        }

        public bool TryDecode(int id, byte[] wire, Action<PayloadResult> done)
        {
            return Queue(done, delegate
            {
                if (wire == null || wire.Length < 28) return PayloadResult.Of(id, null, "PAYLOAD_WIRE_SHORT");
                byte[] plain;
                if (_key.TryOpen(Hex.Slice(wire, 0, 12), Aad(id), Hex.Slice(wire, 12, wire.Length - 12), out plain)) return PayloadResult.Of(id, plain, null);
                return _fault == "decode-skips-tag" ? PayloadResult.Of(id, new byte[wire.Length - 28], null) : PayloadResult.Of(id, null, "AES_GCM_TAG");
            });
        }

        public void Dispose() { _disposed = true; if (Thread.VolatileRead(ref _pending) == 0 && _fault != "idle-never-set") _idle.Set(); }
    }
}
