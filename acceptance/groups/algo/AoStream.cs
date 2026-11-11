using System;
using System.Collections.Generic;
using FE = Acceptance.Frozen.Errors;

namespace Acceptance
{
    /// <summary>The running state of one streamed CBC or CTR message (PRD 7.3 item 15: CbcChain, CtrCounter), closed over its key and direction.</summary>
    public interface IAoChain
    {
        void Init(byte[] b, int offset);
        void Clear();
        void Call(byte[] i, int io, int n, byte[] o, int oo);
    }

    /// <summary>The streamed forms and the caller-buffer Verify forms of PRD 7.3 item 15 on one side: the product, or the reference model below.</summary>
    public interface IAoStream
    {
        string Name { get; }
        bool Has(string op);
        object NewKey(byte[] key);
        /// <summary>kind: "cbc-encrypt", "cbc-decrypt" or "ctr". One new state object for each call of this method.</summary>
        IAoChain NewChain(object k, string kind);
        bool CmacVerify(object k, byte[] m, int mo, int n, byte[] t, int to);
        bool CmacKeyVerify(object k, byte[] m, int mo, int n, byte[] t, int to);
    }

    /// <summary>
    /// The reference for one streamed message. The 5c5d4a4 code has no streamed form, so the reference is the frozen one-call op plus the
    /// rules of PRD 7.3 item 15 and 7.1.9, written here:
    /// 1. State 0 is empty, 1 is ready, 2 is ended. Init copies 16 bytes and makes the object ready. Clear ends it.
    /// 2. A call on an object that is not ready throws and writes nothing. The exception type is not fixed by the PRD, so the rows compare
    ///    "refused" against "ok" for these calls, and no type.
    /// 3. CBC: the chain value after a call is the last ciphertext block of that call. A count that is not a multiple of 16 is refused as
    ///    the frozen one-call form refuses it.
    /// 4. CTR: the calls of one message give the bytes of one frozen call over the joined input. A call with a partial last block is
    ///    processed, and it ends the object.
    /// 5. The overlap rule of the caller-buffer forms holds (ARG_RANGES_OVERLAP before any write).
    /// </summary>
    public class FrozenChain : IAoChain
    {
        protected readonly FrozenSide Side = new FrozenSide();
        protected readonly object Key;
        protected readonly string Kind;
        protected byte[] V = new byte[16];
        /// <summary>CTR only: the input bytes of this message so far. It is a multiple of 16 while the object is ready.</summary>
        protected int Done;
        protected int State;

        public FrozenChain(object key, string kind) { Key = key; Kind = kind; }

        public virtual void Init(byte[] b, int offset)
        {
            V = new byte[16];
            Buffer.BlockCopy(b, offset, V, 0, 16);
            Done = 0;
            State = 1;
        }

        public virtual void Clear() { Array.Clear(V, 0, 16); Done = 0; State = 2; }

        public virtual void Call(byte[] i, int io, int n, byte[] o, int oo)
        {
            if (State != 1) throw new InvalidOperationException("the object is empty or ended");
            if (i != null && ReferenceEquals(i, o) && io != oo && io < oo + n && oo < io + n)
                throw new FE.NetSecException(FE.NetSecError.Of("ARG_RANGES_OVERLAP", "input and output overlap and do not start at the same index"));
            byte[] src = new byte[n];
            Buffer.BlockCopy(i, io, src, 0, n);
            if (Kind == "ctr")
            {
                byte[] joined = new byte[Done + n];
                Buffer.BlockCopy(src, 0, joined, Done, n);
                byte[] r = Side.Ctr(Key, (byte[])V.Clone(), joined);
                Buffer.BlockCopy(r, Done, o, oo, n);
                Done += n;
                if (n % 16 != 0) State = 2;
                return;
            }
            bool encrypt = Kind == "cbc-encrypt";
            byte[] c = Side.Cbc(Key, (byte[])V.Clone(), src, encrypt);
            Buffer.BlockCopy(c, 0, o, oo, n);
            if (n >= 16) { V = new byte[16]; Buffer.BlockCopy(encrypt ? c : src, n - 16, V, 0, 16); }
        }
    }

    public class FrozenStream : IAoStream
    {
        readonly FrozenSide _f = new FrozenSide();
        public virtual string Name { get { return "frozen-5c5d4a4 + PRD 7.3 item 15 rules"; } }
        public bool Has(string op) { return true; }
        public object NewKey(byte[] key) { return _f.NewAes(key); }
        public virtual IAoChain NewChain(object k, string kind) { return new FrozenChain(k, kind); }

        public virtual bool CmacVerify(object k, byte[] m, int mo, int n, byte[] t, int to)
        {
            return Hex.Eq(_f.Cmac(k, Hex.Slice(m, mo, n)), Hex.Slice(t, to, 16));
        }

        public virtual bool CmacKeyVerify(object k, byte[] m, int mo, int n, byte[] t, int to) { return CmacVerify(k, m, mo, n, t, to); }
    }

    /// <summary>
    /// AO-2 for the streamed CBC and CTR forms and for the caller-buffer Verify forms. A streamed case is one object and 1 or 2 messages.
    /// Each message is Init and 1 to 4 calls, each call with its own drawn aliasing of input and output. A share of cases adds a call before
    /// Init, a call after Clear, a CTR call with a partial block and a call after it, or a CBC count that is not a multiple of 16.
    /// </summary>
    public static class AoStreamDiff
    {
        public static readonly string[] Ops = { "aes-cbc-stream", "aes-ctr-stream", "aes-cmac-verify-into", "aes-cmackey-verify-into" };

        public delegate void StreamCase(IAoStream s, AoRec r);

        delegate void Body();

        static void Try(AoRec r, Body b)
        {
            try { b(); r.Add("ok"); }
            catch (AoHarnessException) { throw; }
            catch (Exception e) { r.Add(AoRec.SigOf(e)); }
        }

        /// <summary>For a call on an object that is not ready: any exception reads "refused" (model rule 2).</summary>
        static void TryRefused(AoRec r, Body b)
        {
            try { b(); r.Add("ok"); }
            catch (AoHarnessException) { throw; }
            catch (Exception) { r.Add("refused"); }
        }

        static byte[] C(byte[] b) { return b == null ? null : (byte[])b.Clone(); }

        const int EvInit = 0, EvCall = 1, EvRefusedCall = 2, EvClear = 3;

        sealed class Ev
        {
            public int Kind, Off, N;
            public byte[] Buf;
            public AoIntoDiff.Place P;
        }

        static Ev Call(Rng r, int n, bool allowOverlap, int kind)
        {
            Ev e = new Ev();
            e.Kind = kind; e.N = n; e.P = AoIntoDiff.Place.Draw(r, n, n, allowOverlap);
            return e;
        }

        static List<Ev> DrawEvents(Rng r, bool ctr)
        {
            List<Ev> evs = new List<Ev>();
            if (r.Int(8) == 0) evs.Add(Call(r, 16, false, EvRefusedCall));   // before the first Init
            int messages = 1 + r.Int(2);
            for (int m = 0; m < messages; m++)
            {
                Ev init = new Ev();
                init.Kind = EvInit; init.Off = r.Int(5);
                init.Buf = ctr ? Hex.Concat(r.Bytes(init.Off), AoDraw.NearWrapCounter(r), r.Bytes(r.Int(5))) : r.Bytes(init.Off + 16 + r.Int(8));
                evs.Add(init);
                int chunks = 1 + r.Int(4);
                for (int c = 0; c < chunks; c++)
                {
                    int n = 16 * (1 + r.Int(8));
                    bool partial = c == chunks - 1 && r.Int(4) == 0;
                    if (partial) n += 1 + r.Int(15);
                    if (partial && !ctr)
                    {
                        // CBC refuses this count as the frozen form does. The state after a refused call is not fixed, so the case ends.
                        evs.Add(Call(r, n, false, EvCall));
                        return evs;
                    }
                    Ev call = Call(r, n, true, EvCall);
                    evs.Add(call);
                    if (call.P.Mode == 3) return evs;   // a refused overlap ends the case, for the same reason
                    if (partial) evs.Add(Call(r, 16, false, EvRefusedCall));   // the partial block ended the CtrCounter
                }
                if (r.Int(4) == 0)
                {
                    Ev clear = new Ev(); clear.Kind = EvClear; evs.Add(clear);
                    evs.Add(Call(r, 16, false, EvRefusedCall));
                }
            }
            return evs;
        }

        public static StreamCase Draw(string op, Rng r)
        {
            byte[] key = r.Bytes(AoDraw.KeyLen(r));
            if (op == "aes-cbc-stream" || op == "aes-ctr-stream")
            {
                bool ctr = op == "aes-ctr-stream";
                string kind = ctr ? "ctr" : r.Int(2) == 0 ? "cbc-encrypt" : "cbc-decrypt";
                List<Ev> evs = DrawEvents(r, ctr);
                return delegate (IAoStream s, AoRec rec)
                {
                    object k = s.NewKey(C(key));
                    IAoChain ch = s.NewChain(k, kind);
                    foreach (Ev ev in evs)
                    {
                        Ev e = ev;
                        if (e.Kind == EvInit)
                        {
                            byte[] b = C(e.Buf);
                            Try(rec, delegate { ch.Init(b, e.Off); });
                            rec.Add(b);
                        }
                        else if (e.Kind == EvClear) Try(rec, delegate { ch.Clear(); });
                        else
                        {
                            byte[] inb = C(e.P.In), outb = e.P.Mode == 0 ? C(e.P.Out) : inb;
                            Body call = delegate { ch.Call(inb, e.P.Io, e.N, outb, e.P.Oo); };
                            if (e.Kind == EvRefusedCall) TryRefused(rec, call); else Try(rec, call);
                            rec.Add(inb); if (e.P.Mode == 0) rec.Add(outb);
                        }
                    }
                };
            }
            // Verify: the right tag from the frozen code at a drawn offset, then no change, one changed tag bit, or one changed message bit.
            {
                int n = AoDraw.Len(r, 2048), mo = r.Int(8), to = r.Int(8);
                byte[] m = r.Bytes(mo + n + r.Int(8)), t = r.Bytes(to + 16 + r.Int(8));
                FrozenSide f = new FrozenSide();
                Buffer.BlockCopy(f.Cmac(f.NewAes(C(key)), Hex.Slice(m, mo, n)), 0, t, to, 16);
                int tamper = r.Int(3), flip = r.Int(1 << 20);
                if (tamper == 1) t[to + (flip % 16)] ^= (byte)(1 << (flip % 8));
                if (tamper == 2 && n > 0) m[mo + (flip % n)] ^= (byte)(1 << (flip % 8));
                return delegate (IAoStream s, AoRec rec)
                {
                    object k = s.NewKey(C(key));
                    byte[] mb = C(m), tb = C(t);
                    bool ok = false;
                    Try(rec, delegate { ok = op == "aes-cmac-verify-into" ? s.CmacVerify(k, mb, mo, n, tb, to) : s.CmacKeyVerify(k, mb, mo, n, tb, to); });
                    rec.Add(ok); rec.Add(mb); rec.Add(tb);
                };
            }
        }

        static AoRec Exec(StreamCase k, IAoStream s)
        {
            AoRec r = new AoRec();
            try { k(s, r); }
            catch (AoHarnessException) { throw; }
            catch (Exception e) { r.Sig = AoRec.SigOf(e); }
            return r;
        }

        public static string Run(string op, IAoStream reference, IAoStream subject, int cases)
        {
            if (!subject.Has(op)) throw new NotRunException("PRODUCT_MISSING", op + ": the form does not exist yet (PRD 7.3 item 15, slice S1)");
            bool stream = op == "aes-cbc-stream" || op == "aes-ctr-stream";
            ulong seed = AoDiff.SeedOf(op);
            int bad = 0, refused = 0, yes = 0, no = 0;
            List<string> first = new List<string>();
            for (int i = 0; i < cases; i++)
            {
                Rng r = new Rng(seed + (ulong)i * 0x9E3779B97F4A7C15UL);
                StreamCase k = Draw(op, r);
                AoRec a = Exec(k, reference), b = Exec(k, subject);
                foreach (string t in a.Texts) if (t == "refused" || t.Contains("ARG_RANGES_OVERLAP")) { refused++; break; }
                if (a.Texts.Contains("true")) yes++;
                if (a.Texts.Contains("false")) no++;
                string d = AoRec.Diff(a, b);
                if (d == null) continue;
                bad++;
                if (first.Count < 3) first.Add("case " + i + " (seed 0x" + seed.ToString("x16") + "): " + d);
            }
            string tail = op + ": seed 0x" + seed.ToString("x16") + ", cases " + cases +
                          (stream ? ", cases with a refusal on the reference " + refused : ", reference true " + yes + ", reference false " + no) +
                          ", reference " + reference.Name + ", subject " + subject.Name;
            if (bad > 0) throw new FailException("AO_DIFFERS", bad + " of " + cases + " cases differ (" + tail + "). First: " + string.Join(" | ", first.ToArray()));
            if (stream && refused == 0) throw new FailException("AO_GRAMMAR_ONE_SIDED", "no case drew a refusal, so the state rule went untested (" + tail + ")");
            if (!stream && (yes == 0 || no == 0)) throw new FailException("AO_GRAMMAR_ONE_SIDED", "the cases gave one answer only (" + tail + ")");
            return cases + " of " + cases + " cases equal (" + tail + ")";
        }
    }
}
