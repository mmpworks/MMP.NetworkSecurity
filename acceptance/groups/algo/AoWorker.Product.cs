using System;
using System.Reflection;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// AO-4, slice S2: the payload worker. The signature is PRD section 7.3 item 2, a hypothesis until S0 confirms it:
    /// AesPayloadWorker(AesKey key, int maxQueued), bool TryEncode(byte[] plain, Action&lt;byte[]&gt; done), bool TryDecode(byte[] wire, Action&lt;byte[]&gt; done).
    /// The clause is NOT RUN, by name, until the type exists with that shape. Then every payload must decode back to itself, a wire made
    /// on one worker must decode on another, and one done callback in ten re-enters the worker with the next payload.
    /// </summary>
    public static class AoWorker
    {
        static Type Find(Assembly asm)
        {
            foreach (Type t in asm.GetTypes()) if (t.Name == "AesPayloadWorker") return t;
            return null;
        }

        sealed class W
        {
            readonly object _w; readonly MethodInfo _enc, _dec;
            public W(object w, MethodInfo enc, MethodInfo dec) { _w = w; _enc = enc; _dec = dec; }
            public bool Encode(byte[] p, Action<byte[]> done) { return (bool)_enc.Invoke(_w, new object[] { p, done }); }
            public bool Decode(byte[] p, Action<byte[]> done) { return (bool)_dec.Invoke(_w, new object[] { p, done }); }
        }

        static W Make(Type t, NetSec.Crypto.AesKey key, int maxQueued)
        {
            ConstructorInfo ctor = t.GetConstructor(new[] { typeof(NetSec.Crypto.AesKey), typeof(int) });
            MethodInfo enc = t.GetMethod("TryEncode", new[] { typeof(byte[]), typeof(Action<byte[]>) });
            MethodInfo dec = t.GetMethod("TryDecode", new[] { typeof(byte[]), typeof(Action<byte[]>) });
            if (ctor == null || enc == null || dec == null || enc.ReturnType != typeof(bool) || dec.ReturnType != typeof(bool))
            {
                string members = string.Join("; ", Array.ConvertAll(t.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly), delegate (MemberInfo m) { return m.ToString(); }));
                throw new NotRunException("SIGNATURE_NOT_CONFIRMED", "AesPayloadWorker exists but differs from PRD 7.3 item 2. Its public members: " + members);
            }
            return new W(ctor.Invoke(new object[] { key, maxQueued }), enc, dec);
        }

        static void Submit(Func<bool> attempt)
        {
            int spins = 0;
            while (!attempt())
            {
                if (++spins > 2000000) throw new FailException("AO_WORKER_STUCK", "the worker refused a payload two million times");
                Thread.Sleep(0);
            }
        }

        [Clause("AO-4.payload-worker-pool-25", PerBuild = true, TimeoutSec = 3600)]
        public static string PayloadWorker(Ctx c)
        {
            AoSubject.Make(c);
            Type t = Find(typeof(NetSec.Crypto.AesKey).Assembly);
            if (t == null) throw new NotRunException("PRODUCT_MISSING", "no type AesPayloadWorker in NetSec.Core (slice S2)");
            string pool = AoThreads.CapPool();
            int payloads = int.Parse(c.Prop("ao.payloads", AoThreads.DefaultPayloads.ToString()));
            int runs = int.Parse(c.Prop("ao.runs", AoThreads.DefaultRuns.ToString()));
            int bad = 0;
            string first = null;
            for (int run = 0; run < runs; run++)
            {
                Rng r = new Rng(AoThreads.Seed ^ (ulong)(run + 1));
                byte[] key = r.Bytes(AoDraw.KeyLen(r));
                byte[][] plain = new byte[payloads][];
                for (int i = 0; i < payloads; i++) plain[i] = r.Bytes(AoDraw.Len(r, 1024));
                W a = Make(t, new NetSec.Crypto.AesKey((byte[])key.Clone()), 64);
                W b = Make(t, new NetSec.Crypto.AesKey((byte[])key.Clone()), 64);
                byte[][] wire = new byte[payloads][], back = new byte[payloads][];
                int left = payloads;
                ManualResetEvent encoded = new ManualResetEvent(false), decoded = new ManualResetEvent(false);
                for (int i = 0; i < payloads; i++)
                {
                    int at = i;
                    Submit(delegate { return a.Encode((byte[])plain[at].Clone(), delegate (byte[] w) { wire[at] = w; if (Interlocked.Decrement(ref left) == 0) encoded.Set(); }); });
                }
                if (!encoded.WaitOne(TimeSpan.FromMinutes(20))) throw new FailException("AO_WORKER_STALLED", "run " + run + ": " + left + " encodes still open");
                left = payloads;
                for (int i = 0; i < payloads; i++)
                {
                    int at = i;
                    // Decode on the other worker; one callback in ten re-enters worker a with an extra encode it then checks.
                    Submit(delegate
                    {
                        return b.Decode(wire[at], delegate (byte[] p)
                        {
                            back[at] = p;
                            if (at % 10 == 0) Submit(delegate { return a.Encode((byte[])plain[at].Clone(), delegate (byte[] w2) { }); });
                            if (Interlocked.Decrement(ref left) == 0) decoded.Set();
                        });
                    });
                }
                if (!decoded.WaitOne(TimeSpan.FromMinutes(20))) throw new FailException("AO_WORKER_STALLED", "run " + run + ": " + left + " decodes still open");
                for (int i = 0; i < payloads; i++)
                    if (!Hex.Eq(plain[i], back[i])) { bad++; if (first == null) first = "run " + run + " payload " + i + ": " + Hex.Short(plain[i]) + " came back " + Hex.Short(back[i]); }
            }
            if (bad > 0) throw new FailException("AO_WORKER_MISMATCH", bad + " payloads did not come back (" + pool + "). First: " + first);
            return (payloads * runs) + " of " + (payloads * runs) + " payloads came back through two workers on one key (" + pool + ")";
        }
    }
}
