using System;
using System.Collections.Generic;
using F = Acceptance.Frozen.Crypto;
using FE = Acceptance.Frozen.Errors;

namespace Acceptance
{
    /// <summary>The caller-buffer forms of PRD 7.3 item 15 on one side: the product, or the reference model below.</summary>
    public interface IAoInto
    {
        string Name { get; }
        bool Has(string op);
        object NewKey(byte[] key);
        void Ecb(object k, bool encrypt, byte[] i, int io, int n, byte[] o, int oo);
        void Cbc(object k, bool encrypt, byte[] iv, int ivo, byte[] i, int io, int n, byte[] o, int oo);
        void Ctr(object k, byte[] ctr, int co, byte[] i, int io, int n, byte[] o, int oo);
        void Cmac(object k, byte[] m, int mo, int n, byte[] t, int to);
        void CmacKey(object k, byte[] m, int mo, int n, byte[] t, int to);
        void GcmSeal(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo);
        bool GcmOpen(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo);
    }

    /// <summary>
    /// The reference for the caller-buffer forms. The 5c5d4a4 code has none (each mode returns a new array), so the reference is the frozen
    /// allocating op plus the rules of PRD 7.1.9, 7.3 item 15 and 7.4 rule 3, written here:
    /// 1. The same array at the same index, and ranges that do not overlap, are legal and give the separate-buffer result.
    /// 2. Any other overlap of input and output throws NetSecException ARG_RANGES_OVERLAP before any write. For CMAC the input is the
    ///    message range and the output is the 16-byte tag range.
    /// 3. GCM reads 12 nonce bytes at the offset; fewer than 12 throws NetSecException GCM_NONCE_LENGTH.
    /// 4. GCM open checks the tag first. On a failure it sets the whole output range to 0 and returns false.
    /// 5. No input, IV, counter, nonce or AAD byte changes.
    /// The model is the expectation the PRD writes down; AO-1 and AO-2 on the allocating forms tie it to 5c5d4a4.
    /// </summary>
    public class FrozenInto : IAoInto
    {
        readonly FrozenSide _f = new FrozenSide();
        public virtual string Name { get { return "frozen-5c5d4a4 + PRD 7.3/7.4 rules"; } }
        public bool Has(string op) { return true; }
        public object NewKey(byte[] key) { return _f.NewAes(key); }

        static Exception Code(string code, string message) { return new FE.NetSecException(FE.NetSecError.Of(code, message)); }

        protected virtual void Overlap(byte[] a, int ao, int an, byte[] b, int bo, int bn)
        {
            if (a == null || b == null || !ReferenceEquals(a, b) || ao == bo) return;
            if (ao < bo + bn && bo < ao + an) throw Code("ARG_RANGES_OVERLAP", "input and output overlap and do not start at the same index");
        }

        protected static byte[] Slice(byte[] b, int off, int n) { byte[] r = new byte[n]; Buffer.BlockCopy(b, off, r, 0, n); return r; }

        public virtual void Ecb(object k, bool encrypt, byte[] i, int io, int n, byte[] o, int oo)
        {
            Overlap(i, io, n, o, oo, n);
            byte[] r = encrypt ? _f.Ecb(k, Slice(i, io, n)) : EcbDecrypt(k, Slice(i, io, n));
            Buffer.BlockCopy(r, 0, o, oo, n);
        }

        byte[] EcbDecrypt(object k, byte[] d)
        {
            byte[] r = new byte[d.Length];
            for (int b = 0; b < d.Length; b += 16) _f.AesDecrypt(k, d, b, r, b);
            return r;
        }

        public virtual void Cbc(object k, bool encrypt, byte[] iv, int ivo, byte[] i, int io, int n, byte[] o, int oo)
        {
            Overlap(i, io, n, o, oo, n);
            byte[] r = _f.Cbc(k, Slice(iv, ivo, 16), Slice(i, io, n), encrypt);
            Buffer.BlockCopy(r, 0, o, oo, n);
        }

        public virtual void Ctr(object k, byte[] ctr, int co, byte[] i, int io, int n, byte[] o, int oo)
        {
            Overlap(i, io, n, o, oo, n);
            byte[] r = _f.Ctr(k, Slice(ctr, co, 16), Slice(i, io, n));
            Buffer.BlockCopy(r, 0, o, oo, n);
        }

        public virtual void Cmac(object k, byte[] m, int mo, int n, byte[] t, int to)
        {
            // PRD 7.1.9: the tag range may start at the index of the message range, or lie apart from it. Any other overlap is refused.
            Overlap(m, mo, n, t, to, 16);
            Buffer.BlockCopy(_f.Cmac(k, Slice(m, mo, n)), 0, t, to, 16);
        }

        public virtual void CmacKey(object k, byte[] m, int mo, int n, byte[] t, int to) { Cmac(k, m, mo, n, t, to); }

        protected virtual byte[] Nonce(byte[] nonce, int no)
        {
            if (nonce == null || no < 0 || nonce.Length - no < 12) throw Code("GCM_NONCE_LENGTH", "fewer than 12 nonce bytes at the offset");
            return Slice(nonce, no, 12);
        }

        public virtual void GcmSeal(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo)
        {
            byte[] nn = Nonce(nonce, no);
            Overlap(i, io, n, o, oo, n + 16);
            byte[] r = _f.GcmSeal(k, nn, Slice(aad, ao, an), Slice(i, io, n));
            Buffer.BlockCopy(r, 0, o, oo, n + 16);
        }

        public virtual bool GcmOpen(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo)
        {
            byte[] nn = Nonce(nonce, no);
            Overlap(i, io, n, o, oo, n - 16);
            byte[] plain;
            bool ok = _f.GcmOpen(k, nn, Slice(aad, ao, an), Slice(i, io, n), out plain);
            if (ok) Buffer.BlockCopy(plain, 0, o, oo, n - 16);
            else Array.Clear(o, oo, n - 16);
            return ok;
        }
    }

    /// <summary>
    /// AO-2 for the caller-buffer forms (PRD 3.1 rule 4 as changed by 7.1.9): each case draws one aliasing of input and output - separate
    /// arrays, the same array at the same index, the same array with ranges apart, or a partial overlap (which must be refused) - with guard
    /// bytes around every range. Both sides run the case on private copies, and every byte of every array is compared afterwards.
    /// </summary>
    public static class AoIntoDiff
    {
        public static readonly string[] Ops = { "aes-ecb-into", "aes-cbc-into", "aes-ctr-into", "aes-cmac-into", "aes-cmackey-into", "aes-gcm-into" };

        public delegate void IntoCase(IAoInto s, AoRec r);

        delegate void Body();

        static void Try(AoRec r, Body b)
        {
            try { b(); r.Add("ok"); }
            catch (AoHarnessException) { throw; }
            catch (Exception e) { r.Add(AoRec.SigOf(e)); }
        }

        static byte[] C(byte[] b) { return b == null ? null : (byte[])b.Clone(); }

        /// <summary>Places a range of n input bytes and an output range of m bytes by the drawn aliasing. Returns (in, io, out, oo).</summary>
        public sealed class Place
        {
            public byte[] In, Out; public int Io, Oo; public int Mode;   // 0 separate, 1 same index, 2 apart in one array, 3 partial overlap
            public static Place Draw(Rng r, int n, int m, bool allowOverlap)
            {
                Place p = new Place();
                p.Mode = allowOverlap ? r.Int(4) : 0;
                int slack = 1 + r.Int(8);
                if (p.Mode == 0)
                {
                    p.Io = r.Int(slack); p.Oo = r.Int(slack);
                    p.In = r.Bytes(p.Io + n + slack); p.Out = r.Bytes(p.Oo + m + slack);
                }
                else if (p.Mode == 1)
                {
                    p.Io = p.Oo = r.Int(slack);
                    p.In = p.Out = r.Bytes(p.Io + Math.Max(n, m) + slack);
                }
                else if (p.Mode == 2)
                {
                    bool outFirst = r.Int(2) == 0;
                    int a = r.Int(slack), gap = r.Int(4);
                    p.In = p.Out = r.Bytes(a + n + m + gap + slack);
                    if (outFirst) { p.Oo = a; p.Io = a + m + gap; } else { p.Io = a; p.Oo = a + n + gap; }
                }
                else
                {
                    // A start 1 to 15 bytes apart (or less than the shorter range), in either direction: a partial overlap.
                    int span = Math.Max(1, Math.Min(Math.Min(n, m) - 1, 15));
                    int shift = 1 + r.Int(span);
                    int a = r.Int(slack) + shift;
                    if (r.Int(2) == 0) { p.Io = a; p.Oo = a + shift; } else { p.Io = a + shift; p.Oo = a; }
                    p.In = p.Out = r.Bytes(Math.Max(p.Io + n, p.Oo + m) + slack);
                    if (Math.Min(n, m) <= 1) { p.Mode = 0; p.Out = r.Bytes(p.Oo + m + slack); }
                }
                return p;
            }
        }

        public static IntoCase Draw(string op, Rng r)
        {
            int keyLen = AoDraw.KeyLen(r);
            byte[] key = r.Bytes(keyLen);
            switch (op)
            {
                case "aes-ecb-into":
                case "aes-cbc-into":
                case "aes-ctr-into":
                    {
                        int n = op == "aes-ctr-into" ? AoDraw.Len(r, 2048) : AoDraw.Blocks(r, 16, 64);
                        if (op != "aes-ctr-into" && n == 0) n = 16;
                        if (op == "aes-ctr-into" && n == 0) n = 1;
                        Place p = Place.Draw(r, n, n, true);
                        bool enc = r.Int(2) == 0;
                        byte[] iv = r.Bytes(16 + r.Int(8)); int ivo = r.Int(iv.Length - 15);
                        int co = r.Int(5);
                        byte[] ctrBuf = Hex.Concat(r.Bytes(co), AoDraw.NearWrapCounter(r), r.Bytes(r.Int(5)));
                        return delegate (IAoInto s, AoRec rec)
                        {
                            object k = s.NewKey(C(key));
                            byte[] inb = C(p.In), outb = p.Mode == 0 ? C(p.Out) : inb, ivb = C(iv), cb = C(ctrBuf);
                            Try(rec, delegate
                            {
                                if (op == "aes-ecb-into") s.Ecb(k, enc, inb, p.Io, n, outb, p.Oo);
                                else if (op == "aes-cbc-into") s.Cbc(k, enc, ivb, ivo, inb, p.Io, n, outb, p.Oo);
                                else s.Ctr(k, cb, co, inb, p.Io, n, outb, p.Oo);
                            });
                            rec.Add(inb); if (p.Mode == 0) rec.Add(outb); rec.Add(ivb); rec.Add(cb);
                        };
                    }
                case "aes-cmac-into":
                case "aes-cmackey-into":
                    {
                        // The message range and the 16-byte tag range by a drawn aliasing: separate arrays, the same index, apart in one
                        // array, or a partial overlap (which must be refused).
                        int n = AoDraw.Len(r, 2048);
                        Place p = Place.Draw(r, n, 16, true);
                        return delegate (IAoInto s, AoRec rec)
                        {
                            object k = s.NewKey(C(key));
                            byte[] mb = C(p.In), tb = p.Mode == 0 ? C(p.Out) : mb;
                            Try(rec, delegate { if (op == "aes-cmac-into") s.Cmac(k, mb, p.Io, n, tb, p.Oo); else s.CmacKey(k, mb, p.Io, n, tb, p.Oo); });
                            rec.Add(mb); if (p.Mode == 0) rec.Add(tb);
                        };
                    }
                default:
                    {
                        // Seal into a drawn placement, then open that wire into another drawn placement, with a share of changed tags,
                        // changed AAD, and nonce ranges shorter than 12 bytes.
                        int n = AoDraw.Len(r, 2048);
                        Place ps = Place.Draw(r, n, n + 16, true), po = Place.Draw(r, n + 16, n, true);
                        int no = r.Int(6);
                        byte[] nonce = r.Bytes(no + 12 + r.Int(6));
                        int shortNonce = r.Int(40) == 0 ? 1 + r.Int(11) : 0;   // 1 to 11 bytes left after the offset
                        if (shortNonce > 0) nonce = r.Bytes(no + shortNonce);
                        int ao = r.Int(5), an = AoDraw.Len(r, 64);
                        byte[] aad = r.Bytes(ao + an + r.Int(5));
                        int tamper = r.Int(4), flip = r.Int(1 << 20);   // 0 none; 1 a wire byte; 2 an AAD byte; 3 none
                        return delegate (IAoInto s, AoRec rec)
                        {
                            object k = s.NewKey(C(key));
                            byte[] nb = C(nonce), ab = C(aad), sin = C(ps.In), sout = ps.Mode == 0 ? C(ps.Out) : sin;
                            Try(rec, delegate { s.GcmSeal(k, nb, no, ab, ao, an, sin, ps.Io, n, sout, ps.Oo); });
                            rec.Add(sin); if (ps.Mode == 0) rec.Add(sout); rec.Add(nb); rec.Add(ab);
                            // The wire as the seal wrote it (or the drawn bytes, when the seal threw), copied into the open's input range.
                            byte[] wire = Hex.Slice(sout, ps.Oo, Math.Min(n + 16, sout.Length - ps.Oo));
                            byte[] oin = C(po.In), oout = po.Mode == 0 ? C(po.Out) : oin;
                            Buffer.BlockCopy(wire, 0, oin, po.Io, Math.Min(wire.Length, n + 16));
                            byte[] oab = C(ab);
                            if (tamper == 1) oin[po.Io + (flip % (n + 16))] ^= (byte)(1 << (flip % 8));
                            if (tamper == 2 && an > 0) oab[ao + (flip % an)] ^= (byte)(1 << (flip % 8));
                            bool ok = false;
                            Try(rec, delegate { ok = s.GcmOpen(k, nb, no, oab, ao, an, oin, po.Io, n + 16, oout, po.Oo); });
                            rec.Add(ok); rec.Add(oin); if (po.Mode == 0) rec.Add(oout); rec.Add(nb); rec.Add(oab);
                        };
                    }
            }
        }

        static AoRec Exec(IntoCase k, IAoInto s)
        {
            AoRec r = new AoRec();
            try { k(s, r); }
            catch (AoHarnessException) { throw; }
            catch (Exception e) { r.Sig = AoRec.SigOf(e); }
            return r;
        }

        public static string Run(string op, IAoInto reference, IAoInto subject, int cases)
        {
            if (!subject.Has(op)) throw new NotRunException("PRODUCT_MISSING", op + ": the caller-buffer form does not exist yet (PRD 7.3 item 15, slice S1)");
            ulong seed = AoDiff.SeedOf(op);
            int bad = 0, refused = 0;
            List<string> first = new List<string>();
            for (int i = 0; i < cases; i++)
            {
                Rng r = new Rng(seed + (ulong)i * 0x9E3779B97F4A7C15UL);
                IntoCase k = Draw(op, r);
                AoRec a = Exec(k, reference), b = Exec(k, subject);
                foreach (string t in a.Texts) if (t.Contains("ARG_RANGES_OVERLAP") || t.Contains("GCM_NONCE_LENGTH")) { refused++; break; }
                string d = AoRec.Diff(a, b);
                if (d == null) continue;
                bad++;
                if (first.Count < 3) first.Add("case " + i + " (seed 0x" + seed.ToString("x16") + "): " + d);
            }
            string tail = op + ": seed 0x" + seed.ToString("x16") + ", cases " + cases + ", cases with a refusal on the reference " + refused +
                          ", reference " + reference.Name + ", subject " + subject.Name;
            if (bad > 0) throw new FailException("AO_DIFFERS", bad + " of " + cases + " cases differ (" + tail + "). First: " + string.Join(" | ", first.ToArray()));
            if (refused == 0) throw new FailException("AO_GRAMMAR_ONE_SIDED", "no case drew a refusal, so the overlap rule went untested (" + tail + ")");
            return cases + " of " + cases + " cases equal (" + tail + ")";
        }
    }
}
