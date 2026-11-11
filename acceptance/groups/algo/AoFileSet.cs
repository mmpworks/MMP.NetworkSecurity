using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// AO-9 output equality, computed by the suite (Jared on #405, B1): the frozen 5c5d4a4 code and the product each process each file of
    /// the AO-9 set, and the suite compares the bytes. The set is acceptance/ao9-files.tsv (name, size, SHA-256); the files live in
    /// bench/files. A missing file reads NOT RUN AO9_FILES_ABSENT; a changed size or SHA-256 reads FAIL AO9_FILE_CHANGED.
    /// </summary>
    public static class AoFileSet
    {
        public sealed class Entry { public string Name; public long Size; public string Sha; public byte[] Bytes; }

        public static List<Entry> Load(string acceptanceDir, string repoRoot)
        {
            List<Entry> list = new List<Entry>();
            foreach (string line in File.ReadAllLines(Path.Combine(acceptanceDir, "ao9-files.tsv")))
            {
                if (line.StartsWith("#") || line.StartsWith("name\t") || line.Trim().Length == 0) continue;
                string[] f = line.Split('\t');
                Entry e = new Entry(); e.Name = f[0]; e.Size = long.Parse(f[1]); e.Sha = f[2];
                list.Add(e);
            }
            string dir = Path.Combine(repoRoot, "bench", "files");
            List<string> absent = new List<string>(), changed = new List<string>();
            foreach (Entry e in list)
            {
                string p = Path.Combine(dir, e.Name);
                if (!File.Exists(p)) { absent.Add(e.Name); continue; }
                e.Bytes = File.ReadAllBytes(p);
                string sha;
                using (SHA256 h = SHA256.Create()) sha = Hex.Encode(h.ComputeHash(e.Bytes));
                if (e.Bytes.Length != e.Size || sha != e.Sha) changed.Add(e.Name + " (" + e.Bytes.Length + " bytes, sha256 " + sha.Substring(0, 12) + "..)");
            }
            if (absent.Count > 0) throw new NotRunException("AO9_FILES_ABSENT", absent.Count + " of " + list.Count + " AO-9 files are not in " + dir + ": " + string.Join(", ", absent.ToArray()));
            if (changed.Count > 0) throw new FailException("AO9_FILE_CHANGED", "these files differ from acceptance/ao9-files.tsv: " + string.Join(", ", changed.ToArray()));
            return list;
        }

        static byte[] KeyFor(int i) { return new Rng(0xA09000UL + (ulong)i).Bytes(16 + 8 * (i % 3)); }
        static byte[] NonceFor(int i) { return new Rng(0xA09100UL + (ulong)i).Bytes(12); }
        static byte[] Pad16(byte[] b) { byte[] p = new byte[(b.Length + 15) / 16 * 16]; Buffer.BlockCopy(b, 0, p, 0, b.Length); return p; }

        /// <summary>One file through one op on both sides. Null when every output agrees, else the first difference.</summary>
        static string OneFile(string op, AoSide r, AoSide s, byte[] data, int i)
        {
            byte[] key = KeyFor(i), nonce = NonceFor(i), aad = new byte[0], iv = NonceFor(i + 50);
            iv = Hex.Concat(iv, new byte[4]);
            switch (op)
            {
                case "gcm":
                    {
                        object kr = r.NewAes((byte[])key.Clone()), ks = s.NewAes((byte[])key.Clone());
                        byte[] sr = r.GcmSeal(kr, nonce, aad, data), ss = s.GcmSeal(ks, nonce, aad, data);
                        if (!Hex.Eq(sr, ss)) return "seal differs";
                        byte[] p1, p2;
                        if (!s.GcmOpen(ks, nonce, aad, sr, out p1) || !Hex.Eq(p1, data)) return "the product does not open the original's seal";
                        if (!r.GcmOpen(kr, nonce, aad, ss, out p2) || !Hex.Eq(p2, data)) return "the original does not open the product's seal";
                        return null;
                    }
                case "cbc":
                    {
                        byte[] d = Pad16(data);
                        object kr = r.NewAes((byte[])key.Clone()), ks = s.NewAes((byte[])key.Clone());
                        byte[] er = r.Cbc(kr, iv, d, true), es = s.Cbc(ks, iv, d, true);
                        if (!Hex.Eq(er, es)) return "encrypt differs";
                        if (!Hex.Eq(r.Cbc(kr, iv, er, false), s.Cbc(ks, iv, er, false))) return "decrypt differs";
                        return Hex.Eq(s.Cbc(ks, iv, es, false), d) ? null : "the product's decrypt does not give the file back";
                    }
                case "ctr":
                    {
                        object kr = r.NewAes((byte[])key.Clone()), ks = s.NewAes((byte[])key.Clone());
                        byte[] cr = r.Ctr(kr, iv, data), cs = s.Ctr(ks, iv, data);
                        if (!Hex.Eq(cr, cs)) return "encrypt differs";
                        return Hex.Eq(s.Ctr(ks, iv, cs), data) ? null : "the product's decrypt does not give the file back";
                    }
                case "sha256":
                    {
                        IAoHash hr = r.NewHash("sha256"), hs = s.NewHash("sha256");
                        hr.Update(data, 0, data.Length); hs.Update(data, 0, data.Length);
                        return Hex.Eq(hr.Finish(), hs.Finish()) ? null : "digest differs";
                    }
                case "hmac":
                    return Hex.Eq(r.Hmac("sha256", key, data), s.Hmac("sha256", key, data)) ? null : "tag differs";
                default:
                    throw new ArgumentException("no AO-9 op " + op);
            }
        }

        public static string Compare(string op, AoSide reference, AoSide subject, List<Entry> files)
        {
            int ok = 0;
            List<string> bad = new List<string>();
            for (int i = 0; i < files.Count; i++)
            {
                string why = OneFile(op, reference, subject, files[i].Bytes, i);
                if (why == null) ok++; else bad.Add(files[i].Name + ": " + why);
            }
            if (bad.Count > 0) throw new FailException("AO9_OUTPUT_DIFFERS", op + ": " + string.Join("; ", bad.ToArray()));
            return ok + " of " + files.Count + " files give byte-equal " + op + " output on " + reference.Name + " and " + subject.Name;
        }

        /// <summary>One key setup and one 64-byte GCM seal, 1,000 times with new keys and messages, on both sides.</summary>
        public static string SmallMessage(AoSide reference, AoSide subject)
        {
            const int N = 1000;
            for (int i = 0; i < N; i++)
            {
                Rng g = new Rng(0xA09200UL + (ulong)i);
                byte[] key = g.Bytes(AoDraw.KeyLen(g)), nonce = g.Bytes(12), msg = g.Bytes(64);
                byte[] a = reference.GcmSeal(reference.NewAes((byte[])key.Clone()), nonce, new byte[0], msg);
                byte[] b = subject.GcmSeal(subject.NewAes((byte[])key.Clone()), nonce, new byte[0], msg);
                if (!Hex.Eq(a, b)) throw new FailException("AO9_OUTPUT_DIFFERS", "small-message " + i + ": seal differs");
            }
            return N + " of " + N + " small messages (key setup + 64-byte GCM seal) byte-equal on " + reference.Name + " and " + subject.Name;
        }

        /// <summary>25 workers x 8 seals of sample.csv on one shared subject key, each equal to the reference's one-thread seal. Pool cap 25.</summary>
        public static string Pool25(AoSide reference, AoSide subject, List<Entry> files)
        {
            byte[] csv = null;
            foreach (Entry e in files) if (e.Name == "sample.csv") csv = e.Bytes;
            if (csv == null) throw new FailException("AO9_FILE_CHANGED", "sample.csv is not in acceptance/ao9-files.tsv");
            const int Workers = 25, Seals = 8;
            byte[] key = KeyFor(1);
            object shared = subject.NewAes((byte[])key.Clone()), refKey = reference.NewAes((byte[])key.Clone());
            byte[][] got = new byte[Workers * Seals][];
            int left = Workers;
            ManualResetEvent done = new ManualResetEvent(false);
            for (int w = 0; w < Workers; w++)
            {
                int worker = w;
                ThreadPool.QueueUserWorkItem(delegate (object unused)
                {
                    try { for (int j = 0; j < Seals; j++) got[worker * Seals + j] = subject.GcmSeal(shared, Nonce(worker, j), new byte[0], csv); }
                    catch (Exception) { }
                    finally { if (Interlocked.Decrement(ref left) == 0) done.Set(); }
                });
            }
            if (!done.WaitOne(TimeSpan.FromMinutes(5))) throw new FailException("AO_THREADS_STALLED", left + " workers still open after 5 minutes");
            int bad = 0;
            for (int w = 0; w < Workers; w++)
                for (int j = 0; j < Seals; j++)
                    if (!Hex.Eq(got[w * Seals + j], reference.GcmSeal(refKey, Nonce(w, j), new byte[0], csv))) bad++;
            if (bad > 0) throw new FailException("AO9_OUTPUT_DIFFERS", "pool-25: " + bad + " of " + (Workers * Seals) + " seals differ from the one-thread original");
            return (Workers * Seals) + " of " + (Workers * Seals) + " shared-key seals of sample.csv on 25 workers equal the one-thread " + reference.Name + " output";
        }

        static byte[] Nonce(int worker, int j) { return new byte[] { 0xA0, 0x09, 0, 0, 0, 0, 0, (byte)worker, 0, 0, 0, (byte)j }; }
    }
}
