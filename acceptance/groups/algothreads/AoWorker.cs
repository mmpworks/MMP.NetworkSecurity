using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// AO-4 rows for the S1 and S2 types of docs/algorithm-optimization-prd.md section 7.3, read through reflection because they do not exist
    /// at S0. A missing type reads NOT RUN PRODUCT_MISSING; a type with another shape reads NOT RUN SIGNATURE_NOT_CONFIRMED and lists its
    /// public members, so the row list (acceptance/ao-rows.tsv) catches a shape change as a red.
    ///   GcmKey: ctor(AesKey) or ctor(byte[]); byte[] Seal(byte[] nonce, byte[] aad, byte[] plain); bool TryOpen(byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
    ///   AesPayloadWorker(GcmKey key, int maxQueued [, Action&lt;WaitCallback&gt; dispatch]) : IDisposable, with a WaitHandle Idle
    ///   bool TryEncode(int id, byte[] nonce, byte[] plain, Action&lt;PayloadResult&gt; done); bool TryDecode(int id, byte[] wire, Action&lt;PayloadResult&gt; done)
    ///   PayloadResult: the ID (int), the bytes (byte[]) or a machine error code (string)
    /// Wire: 12-byte nonce, ciphertext, 16-byte tag; AAD = the ID, 4 bytes big-endian (7.3 item 11).
    /// </summary>
    /// <summary>Where the worker rows look for their types: the product (AoWorker.Product.cs), or the stand-ins of the self-check.</summary>
    public sealed class AoWorkerEnv
    {
        public Assembly Asm;
        public string Ns;                       // null: any namespace
        public Type AesKeyType;                 // for a GcmKey ctor(AesKey)
        public Func<byte[], object> NewAesKey;
    }

    public static class AoWorker
    {
        static AoWorkerEnv Asm(Ctx c) { return AoWorkerSource.Get(c); }

        /// <summary>How long a run waits for its last result before it fails as stalled: 20 minutes, or the ao.wait-sec property.</summary>
        static TimeSpan Wait(Ctx c) { return TimeSpan.FromSeconds(int.Parse(c.Prop("ao.wait-sec", "1200"))); }

        static Type Find(AoWorkerEnv e, string name, string slice)
        {
            foreach (Type t in e.Asm.GetTypes()) if (t.Name == name && t.IsPublic && (e.Ns == null || t.Namespace == e.Ns)) return t;
            throw new NotRunException("PRODUCT_MISSING", "no public type " + name + " in NetSec.Core (slice " + slice + ")");
        }

        static NotRunException Shape(Type t, string want)
        {
            string members = string.Join("; ", Array.ConvertAll(t.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly), delegate (MemberInfo m) { return m.ToString(); }));
            return new NotRunException("SIGNATURE_NOT_CONFIRMED", t.Name + " exists but lacks " + want + " (PRD 7.3). Its public members: " + members);
        }

        // ---- GcmKey ----

        sealed class GKey
        {
            public object Obj; public MethodInfo SealM, OpenM;
            public byte[] Seal(byte[] n, byte[] a, byte[] p) { try { return (byte[])SealM.Invoke(Obj, new object[] { n, a, p }); } catch (TargetInvocationException e) { throw e.InnerException; } }
            public bool Open(byte[] n, byte[] a, byte[] s, out byte[] p)
            {
                object[] args = { n, a, s, null };
                bool ok;
                try { ok = (bool)OpenM.Invoke(Obj, args); } catch (TargetInvocationException e) { throw e.InnerException; }
                p = (byte[])args[3];
                return ok;
            }
        }

        static GKey NewGcmKey(AoWorkerEnv e, Type t, byte[] key)
        {
            ConstructorInfo byAes = e.AesKeyType == null ? null : t.GetConstructor(new[] { e.AesKeyType }), byBytes = t.GetConstructor(new[] { typeof(byte[]) });
            MethodInfo seal = t.GetMethod("Seal", new[] { typeof(byte[]), typeof(byte[]), typeof(byte[]) });
            MethodInfo open = t.GetMethod("TryOpen", new[] { typeof(byte[]), typeof(byte[]), typeof(byte[]), typeof(byte[]).MakeByRefType() });
            if ((byAes == null && byBytes == null) || seal == null || open == null || seal.ReturnType != typeof(byte[]) || open.ReturnType != typeof(bool))
                throw Shape(t, "ctor(AesKey) or ctor(byte[]), byte[] Seal(nonce, aad, plain), bool TryOpen(nonce, aad, sealedBytes, out plain)");
            GKey g = new GKey();
            g.Obj = byAes != null ? byAes.Invoke(new object[] { e.NewAesKey((byte[])key.Clone()) }) : byBytes.Invoke(new object[] { (byte[])key.Clone() });
            g.SealM = seal; g.OpenM = open;
            return g;
        }

        /// <summary>AO-4 on a shared GcmKey: 100,000 seal-and-open payloads x 10 runs, pool 25, against the frozen Gcm on the same inputs.</summary>
        [Clause("AO-4.shared-gcmkey-pool-25", PerBuild = true, TimeoutSec = 3600)]
        public static string SharedGcmKey(Ctx c)
        {
            AoWorkerEnv env = Asm(c);
            Type t = Find(env, "GcmKey", "S1");
            string pool = AoThreads.CapPool();
            int payloads = int.Parse(c.Prop("ao.payloads", AoThreads.DefaultPayloads.ToString()));
            int runs = int.Parse(c.Prop("ao.runs", AoThreads.DefaultRuns.ToString()));
            int bad = 0; string first = null;
            for (int run = 0; run < runs; run++)
            {
                Rng r = new Rng(AoThreads.Seed ^ 0x6C ^ (ulong)run);
                byte[] key = r.Bytes(AoDraw.KeyLen(r));
                GKey shared = NewGcmKey(env, t, key);
                object frozen = new FrozenSide().NewAes((byte[])key.Clone());
                byte[][] nonce = new byte[payloads][], aad = new byte[payloads][], plain = new byte[payloads][];
                for (int i = 0; i < payloads; i++) { nonce[i] = r.Bytes(12); aad[i] = r.Bytes(AoDraw.Len(r, 64)); plain[i] = r.Bytes(AoDraw.Len(r, 1024)); }
                string[] got = new string[payloads];
                int left = payloads;
                ManualResetEvent done = new ManualResetEvent(false), gate = new ManualResetEvent(false);
                int gateCount = 0;
                for (int i = 0; i < payloads; i++)
                {
                    int id = i;
                    ThreadPool.QueueUserWorkItem(delegate (object unused)
                    {
                        if (id < AoThreads.PoolCap) { if (Interlocked.Increment(ref gateCount) == AoThreads.PoolCap) gate.Set(); gate.WaitOne(5000); }
                        try
                        {
                            byte[] s = shared.Seal((byte[])nonce[id].Clone(), (byte[])aad[id].Clone(), (byte[])plain[id].Clone());
                            byte[] p; bool ok = shared.Open((byte[])nonce[id].Clone(), (byte[])aad[id].Clone(), s, out p);
                            got[id] = Hex.Encode(s) + "|" + ok + "|" + Hex.Encode(p);
                        }
                        catch (Exception e) { got[id] = "threw " + AoRec.SigOf(e); }
                        if (Interlocked.Decrement(ref left) == 0) done.Set();
                    });
                }
                if (!done.WaitOne(Wait(c))) throw new FailException("AO_THREADS_STALLED", "run " + run + ": " + left + " payloads open");
                FrozenSide fs = new FrozenSide();
                for (int i = 0; i < payloads; i++)
                {
                    byte[] s = fs.GcmSeal(frozen, nonce[i], aad[i], plain[i]);
                    string want = Hex.Encode(s) + "|True|" + Hex.Encode(plain[i]);
                    if (got[i] != want) { bad++; if (first == null) first = "run " + run + " id " + i + ": " + got[i].Substring(0, Math.Min(80, got[i].Length)); }
                }
            }
            string tail = "payloads " + payloads + " x runs " + runs + ", seed 0x" + (AoThreads.Seed ^ 0x6C).ToString("x16") + ", " + pool;
            if (bad > 0) throw new FailException("AO_THREAD_MISMATCH", bad + " payloads differ from the frozen Gcm (" + tail + "). First: " + first);
            return (payloads * runs) + " of " + (payloads * runs) + " shared-GcmKey payloads equal the frozen Gcm (" + tail + ")";
        }

        // ---- the payload worker ----

        /// <summary>Turns a product Action&lt;PayloadResult&gt; into a call that hands the result over as an object.</summary>
        public sealed class Sink
        {
            readonly Action<object> _target;
            public Sink(Action<object> target) { _target = target; }
            public void On<T>(T r) { _target(r); }
            public Delegate For(Type resultType)
            {
                MethodInfo m = typeof(Sink).GetMethod("On").MakeGenericMethod(resultType);
                return Delegate.CreateDelegate(typeof(Action<>).MakeGenericType(resultType), this, m);
            }
        }

        /// <summary>A PayloadResult read by member type: the int is the ID, the byte[] the bytes, the string the error code.</summary>
        /// <summary>
        /// A PayloadResult read inside its done call (PRD 7.4 rule 6: the bytes are valid only until done returns, and PayloadResult
        /// carries a length because a buffer from the worker's set is longer than the result). Bytes is a copy of the first Length bytes,
        /// taken here; Raw is the worker's own array, kept to check that the worker clears it when done returns. Members are read by type:
        /// an int named Id is the ID, an int named Length or Count is the length, the byte[] is the bytes, the string is the error code.
        /// </summary>
        public sealed class Res
        {
            public int Id; public byte[] Bytes, Raw; public string Code; public int Length = -1;
            public static Res Of(object o)
            {
                Res r = new Res();
                Type t = o.GetType();
                int otherInt = 0; bool sawId = false;
                foreach (MemberInfo m in t.GetMembers(BindingFlags.Public | BindingFlags.Instance))
                {
                    object v; Type vt;
                    if (m is FieldInfo) { v = ((FieldInfo)m).GetValue(o); vt = ((FieldInfo)m).FieldType; }
                    else if (m is PropertyInfo && ((PropertyInfo)m).GetIndexParameters().Length == 0) { v = ((PropertyInfo)m).GetValue(o, null); vt = ((PropertyInfo)m).PropertyType; }
                    else continue;
                    if (vt == typeof(int))
                    {
                        if (m.Name == "Length" || m.Name == "Count") r.Length = (int)v;
                        else if (m.Name == "Id" || m.Name == "ID") { r.Id = (int)v; sawId = true; }
                        else otherInt = (int)v;
                    }
                    else if (vt == typeof(byte[])) r.Raw = (byte[])v;
                    else if (vt == typeof(string)) r.Code = (string)v;
                }
                if (!sawId) r.Id = otherInt;
                if (r.Raw != null)
                {
                    int n = r.Length < 0 ? r.Raw.Length : Math.Min(r.Length, r.Raw.Length);
                    r.Bytes = new byte[n];
                    Buffer.BlockCopy(r.Raw, 0, r.Bytes, 0, n);
                }
                return r;
            }
        }

        sealed class Worker : IDisposable
        {
            public object Obj; public MethodInfo Enc, Dec; public Type ResultType; public WaitHandle Idle;
            object Call(MethodInfo m, object[] a) { try { return m.Invoke(Obj, a); } catch (TargetInvocationException e) { throw e.InnerException; } }
            public bool Encode(int id, byte[] nonce, byte[] plain, Action<object> done) { return (bool)Call(Enc, new object[] { id, nonce, plain, new Sink(done).For(ResultType) }); }
            public bool Decode(int id, byte[] wire, Action<object> done) { return (bool)Call(Dec, new object[] { id, wire, new Sink(done).For(ResultType) }); }
            public void Dispose() { ((IDisposable)Obj).Dispose(); }
        }

        static Worker NewWorker(AoWorkerEnv asm, byte[] key, int maxQueued, Action<WaitCallback> dispatch)
        {
            Type wt = Find(asm, "AesPayloadWorker", "S2");
            Type gt = Find(asm, "GcmKey", "S1");
            Type rt = Find(asm, "PayloadResult", "S2");
            Type act = typeof(Action<>).MakeGenericType(rt);
            MethodInfo enc = wt.GetMethod("TryEncode", new[] { typeof(int), typeof(byte[]), typeof(byte[]), act });
            MethodInfo dec = wt.GetMethod("TryDecode", new[] { typeof(int), typeof(byte[]), act });
            ConstructorInfo two = wt.GetConstructor(new[] { gt, typeof(int) }), three = wt.GetConstructor(new[] { gt, typeof(int), typeof(Action<WaitCallback>) });
            MemberInfo[] idle = wt.GetMember("Idle", BindingFlags.Public | BindingFlags.Instance);
            if (enc == null || dec == null || enc.ReturnType != typeof(bool) || dec.ReturnType != typeof(bool) || two == null || idle.Length != 1 || !typeof(IDisposable).IsAssignableFrom(wt) || (dispatch != null && three == null))
                throw Shape(wt, "ctor(GcmKey, int[, Action<WaitCallback>]), bool TryEncode(int, byte[], byte[], Action<PayloadResult>), bool TryDecode(int, byte[], Action<PayloadResult>), WaitHandle Idle, IDisposable");
            Worker w = new Worker();
            object g = NewGcmKey(asm, gt, key).Obj;
            w.Obj = dispatch == null ? two.Invoke(new object[] { g, maxQueued }) : three.Invoke(new object[] { g, maxQueued, dispatch });
            w.Enc = enc; w.Dec = dec; w.ResultType = rt;
            object iv = idle[0] is PropertyInfo ? ((PropertyInfo)idle[0]).GetValue(w.Obj, null) : ((FieldInfo)idle[0]).GetValue(w.Obj);
            w.Idle = iv as WaitHandle;
            if (w.Idle == null) throw Shape(wt, "Idle as a WaitHandle");
            return w;
        }

        static byte[] Be(int id) { return new byte[] { (byte)(id >> 24), (byte)(id >> 16), (byte)(id >> 8), (byte)id }; }

        /// <summary>The wire the frozen Gcm gives for one payload: nonce, then Seal(nonce, ID big-endian, plain).</summary>
        public static byte[] ExpectedWire(byte[] key, int id, byte[] nonce, byte[] plain)
        {
            FrozenSide f = new FrozenSide();
            return Hex.Concat(nonce, f.GcmSeal(f.NewAes((byte[])key.Clone()), nonce, Be(id), plain));
        }

        static void Submit(Func<bool> attempt)
        {
            for (int spins = 0; !attempt(); spins++)
            {
                if (spins > 2000000) throw new FailException("AO_WORKER_STUCK", "the worker refused a payload two million times");
                Thread.Sleep(0);
            }
        }

        // Fixed known answer, from python cryptography's AESGCM (acceptance/groups/algothreads/AoWorker.Product.cs header names the layout).
        const string KatKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", KatNonce = "cafebabefacedbaddecaf888";
        const int KatId = 0x01020304;
        const string KatPlain = "414f2d34206b6e6f776e2d616e73776572207061796c6f6164";
        const string KatWire = "cafebabefacedbaddecaf888cbec8d128a112174316570bc156efe5a7f00b030a67505152ae421307e6f018cc1d88b7b936c2d6831";

        [Clause("AO-4.payload-worker.known-answer", PerBuild = true)]
        public static string KnownAnswer(Ctx c)
        {
            AoWorkerEnv asm = Asm(c);
            byte[] key = Hex.Decode(KatKey), nonce = Hex.Decode(KatNonce), plain = Hex.Decode(KatPlain), want = Hex.Decode(KatWire);
            if (!Hex.Eq(ExpectedWire(key, KatId, nonce, plain), want)) throw new FailException("AO_KAT_REFERENCE", "the frozen Gcm disagrees with the python cryptography known answer");
            using (Worker w = NewWorker(asm, key, 4, null))
            {
                Res enc = null, dec = null;
                ManualResetEvent e1 = new ManualResetEvent(false), e2 = new ManualResetEvent(false);
                Submit(delegate { return w.Encode(KatId, (byte[])nonce.Clone(), (byte[])plain.Clone(), delegate (object o) { enc = Res.Of(o); e1.Set(); }); });
                if (!e1.WaitOne(30000)) throw new FailException("AO_WORKER_STALLED", "no encode result in 30 s");
                Submit(delegate { return w.Decode(KatId, want, delegate (object o) { dec = Res.Of(o); e2.Set(); }); });
                if (!e2.WaitOne(30000)) throw new FailException("AO_WORKER_STALLED", "no decode result in 30 s");
                Check.Bytes("encode wire", want, enc.Bytes);
                Check.Equal("encode id", KatId, enc.Id);
                Check.Bytes("decode plain", plain, dec.Bytes);
                Check.Equal("decode id", KatId, dec.Id);
                return "wire " + KatWire.Substring(0, 24) + ".. (" + want.Length + " bytes) equals python cryptography AESGCM and the frozen Gcm; it decodes back to the plain text";
            }
        }

        /// <summary>
        /// 100,000 payloads x 10 runs, pool 25: encode on worker A, decode on worker B (same key bytes), matched by ID. Every wire must equal
        /// the frozen Gcm wire. Planted in the stream: a flipped wire byte and a moved ID (each must give a code and no bytes), a nonce of 11
        /// bytes and a wire of 27 bytes (a code), a done callback that throws (the worker survives), and a callback that re-enters worker A.
        /// </summary>
        [Clause("AO-4.payload-worker.round-trip-pool-25", PerBuild = true, TimeoutSec = 3600)]
        public static string RoundTrip(Ctx c)
        {
            AoWorkerEnv asm = Asm(c);
            string pool = AoThreads.CapPool();
            int payloads = int.Parse(c.Prop("ao.payloads", AoThreads.DefaultPayloads.ToString()));
            int runs = int.Parse(c.Prop("ao.runs", AoThreads.DefaultRuns.ToString()));
            int bad = 0, faulted = 0, thrown = 0; string first = null;
            for (int run = 0; run < runs; run++)
            {
                Rng r = new Rng(AoThreads.Seed ^ 0x77 ^ (ulong)run);
                byte[] key = r.Bytes(AoDraw.KeyLen(r));
                byte[][] plain = new byte[payloads][], nonce = new byte[payloads][];
                // 0 normal, 1 flipped wire byte, 2 moved ID, 3 bad nonce, 4 short wire, 5 callback throws, 6 re-enters, 7 keeps the array
                // (PRD 7.4 rule 6: the copy taken inside done stays right while later payloads run, and the kept array is cleared).
                int[] kind = new int[payloads];
                for (int i = 0; i < payloads; i++)
                {
                    plain[i] = r.Bytes(AoDraw.Len(r, 1024));
                    nonce[i] = Hex.Concat(Be(run), Be(i), r.Bytes(4));
                    int p = r.Int(100);
                    kind[i] = p < 78 ? 0 : p < 82 ? 1 : p < 86 ? 2 : p < 88 ? 3 : p < 90 ? 4 : p < 94 ? 5 : p < 97 ? 6 : 7;
                }
                using (Worker a = NewWorker(asm, key, 64, null))
                using (Worker b = NewWorker(asm, key, 64, null))
                {
                    Res[] wire = new Res[payloads], back = new Res[payloads];
                    int left = payloads, dupes = 0;
                    ManualResetEvent ready = new ManualResetEvent(false);
                    for (int i = 0; i < payloads; i++)
                    {
                        int id = i;
                        byte[] n = kind[id] == 3 ? Hex.Slice(nonce[id], 0, 11) : (byte[])nonce[id].Clone();
                        Submit(delegate { return a.Encode(id, n, (byte[])plain[id].Clone(), delegate (object o)
                        {
                            try
                            {
                                Res x = Res.Of(o);
                                // A result whose ID is out of range or already taken is a mismatch, counted once; the slot of its own ID stays empty.
                                if (x.Id < 0 || x.Id >= payloads || Interlocked.CompareExchange(ref wire[x.Id], x, null) != null) Interlocked.Increment(ref dupes);
                            }
                            finally { if (Interlocked.Decrement(ref left) == 0) ready.Set(); }
                        }); });
                    }
                    if (!ready.WaitOne(Wait(c))) throw new FailException("AO_WORKER_STALLED", "run " + run + ": " + left + " encodes open");
                    left = payloads; ready.Reset();
                    for (int i = 0; i < payloads; i++)
                    {
                        int id = i;
                        byte[] w = wire[id] == null || wire[id].Bytes == null ? new byte[0] : (byte[])wire[id].Bytes.Clone();
                        if (kind[id] == 1 && w.Length > 0) w[r.Int(w.Length)] ^= 0x20;
                        if (kind[id] == 4) w = w.Length >= 27 ? Hex.Slice(w, 0, 27) : w;
                        int asId = kind[id] == 2 ? id + 1 : id;
                        Submit(delegate
                        {
                            return b.Decode(asId, w, delegate (object o)
                            {
                                Res x = Res.Of(o);
                                back[id] = x;
                                if (Interlocked.Decrement(ref left) == 0) ready.Set();
                                if (kind[id] == 6) a.Encode(id, Hex.Concat(Be(run | 0x40000000), Be(id), new byte[4]), (byte[])plain[id].Clone(), delegate (object o2) { });
                                if (kind[id] == 5) { Interlocked.Increment(ref thrown); throw new InvalidOperationException("planted: a done callback that throws"); }
                            });
                        });
                    }
                    if (!ready.WaitOne(Wait(c))) throw new FailException("AO_WORKER_STALLED", "run " + run + ": " + left + " decodes open");
                    if (!a.Idle.WaitOne(60000) || !b.Idle.WaitOne(60000)) throw new FailException("AO_IDLE_TIMEOUT", "run " + run + ": a worker did not reach Idle in 60 s");
                    if (dupes > 0) { bad += dupes; if (first == null) first = "run " + run + ": " + dupes + " encode IDs came back twice"; }
                    for (int i = 0; i < payloads; i++)
                    {
                        string why = Judge(kind[i], i, key, nonce[i], plain[i], wire[i], back[i]);
                        if (why == null && kind[i] == 7 && back[i] != null && back[i].Raw != null)
                        {
                            // The worker sets the used range to 0 before the buffer goes back to its set (PRD 7.4 rule 6, bullet 4).
                            int used = Math.Min(back[i].Bytes.Length, back[i].Raw.Length);
                            for (int j = 0; j < used && why == null; j++) if (back[i].Raw[j] != 0) why = "the kept result array still holds plaintext after done returned";
                        }
                        if (kind[i] >= 1 && kind[i] <= 4) faulted++;
                        if (why != null) { bad++; if (first == null) first = "run " + run + " id " + i + " kind " + kind[i] + ": " + why; }
                    }
                }
            }
            string tail = "payloads " + payloads + " x runs " + runs + ", faulted " + faulted + ", throwing callbacks " + thrown + ", " + pool;
            if (bad > 0) throw new FailException("AO_WORKER_MISMATCH", bad + " payloads wrong (" + tail + "). First: " + first);
            return (payloads * runs) + " of " + (payloads * runs) + " payloads right, matched by ID (" + tail + ")";
        }

        static string Judge(int kind, int id, byte[] key, byte[] nonce, byte[] plain, Res wire, Res back)
        {
            if (wire == null) return "no encode result";
            if (wire.Id != id) return "encode result ID " + wire.Id;
            if (kind == 3) return wire.Code != null && wire.Bytes == null ? null : "an 11-byte nonce gave no code (code " + wire.Code + ")";
            if (wire.Code != null) return "encode gave code " + wire.Code;
            if (!Hex.Eq(wire.Bytes, ExpectedWire(key, id, nonce, plain))) return "the wire differs from the frozen Gcm wire";
            if (back == null) return "no decode result";
            if (kind == 1 || kind == 2 || kind == 4) return back.Code != null && back.Bytes == null ? null : "a bad wire decoded (code " + back.Code + ", bytes " + Hex.Short(back.Bytes) + ")";
            if (back.Code != null) return "decode gave code " + back.Code;
            return Hex.Eq(back.Bytes, plain) ? null : "the plain text did not come back";
        }

        /// <summary>
        /// Never blocks, and Dispose drains: a dispatch that holds each work item until released fills the queue, the next call must return
        /// false at once; after Dispose new calls return false, every queued payload still gets its done call, and Idle sets within 30 s.
        /// A dispatch that throws makes the call return false. A timeout on Idle is a FAIL.
        /// </summary>
        [Clause("AO-4.payload-worker.dispose-drains-to-idle", PerBuild = true, TimeoutSec = 600)]
        public static string DisposeDrains(Ctx c)
        {
            AoWorkerEnv asm = Asm(c);
            const int Max = 8;
            ManualResetEvent release = new ManualResetEvent(false);
            Action<WaitCallback> held = delegate (WaitCallback cb) { ThreadPool.QueueUserWorkItem(delegate (object s) { release.WaitOne(); cb(s); }); };
            byte[] key = new Rng(0xD15905E).Bytes(16);
            int doneCount = 0;
            using (Worker w = NewWorker(asm, key, Max, held))
            {
                int accepted = 0;
                for (int i = 0; i < Max; i++)
                    if (w.Encode(i, Hex.Concat(Be(7), Be(i), Be(0)), new byte[33], delegate (object o) { Interlocked.Increment(ref doneCount); })) accepted++;
                if (accepted != Max) throw new FailException("AO_WORKER_REFUSED", accepted + " of " + Max + " payloads accepted below maxQueued");
                // The probe runs on its own thread with a 1 s limit, so a worker that blocks fails here and never hangs the clause.
                bool extra = false;
                Thread probe = new Thread(delegate () { extra = w.Encode(Max, Hex.Concat(Be(7), Be(Max), Be(0)), new byte[1], delegate (object o) { }); });
                probe.IsBackground = true;
                probe.Start();
                if (!probe.Join(1000)) { release.Set(); throw new FailException("AO_WORKER_BLOCKED", "a full worker did not refuse within 1 s"); }
                if (extra) throw new FailException("AO_WORKER_OVER_LIMIT", "a payload past maxQueued was accepted");
                w.Dispose();
                release.Set();
                if (!w.Idle.WaitOne(30000)) throw new FailException("AO_IDLE_TIMEOUT", "Idle did not set within 30 s after Dispose; done calls " + doneCount + " of " + Max);
                if (doneCount != Max) throw new FailException("AO_WORKER_LOST_PAYLOAD", "done calls " + doneCount + " of " + Max + " after Idle");
                // The queue is empty now, so only the disposed flag can refuse this call.
                if (w.Encode(99, Hex.Concat(Be(7), Be(99), Be(0)), new byte[1], delegate (object o) { })) throw new FailException("AO_WORKER_AFTER_DISPOSE", "TryEncode returned true after Dispose, on an empty queue");
                if (w.Decode(99, new byte[40], delegate (object o) { })) throw new FailException("AO_WORKER_AFTER_DISPOSE", "TryDecode returned true after Dispose, on an empty queue");
            }
            using (Worker t = NewWorker(asm, key, Max, delegate (WaitCallback cb) { throw new InvalidOperationException("planted: dispatch throws"); }))
            {
                if (t.Encode(1, Hex.Concat(Be(8), Be(1), Be(0)), new byte[1], delegate (object o) { })) throw new FailException("AO_WORKER_DISPATCH", "TryEncode returned true when the dispatch threw");
                if (!t.Idle.WaitOne(5000)) throw new FailException("AO_IDLE_TIMEOUT", "Idle did not set after a dispatch that threw (the counter did not come back to 0)");
            }
            return "full queue refused in under 1 s; after Dispose: refused, " + Max + " of " + Max + " done calls, Idle set; a throwing dispatch: refused, Idle set";
        }
    }
}
