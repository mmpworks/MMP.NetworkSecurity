using System;
using System.Collections.Generic;
using System.Threading;

namespace Acceptance
{
    /// <summary>In the selftest build the AO subject is the frozen reference. SelfAo hands the planted faults to AoDiff.Run directly.</summary>
    public static class AoSubject
    {
        public static AoSide Make(Ctx c) { return new FrozenSide(); }
    }

    public static class AoSeams
    {
        public static System.Reflection.ConstructorInfo PortableSeam() { return null; }
        public static bool HasType(string name) { return false; }
    }

    /// <summary>
    /// The frozen reference with one planted fault: the kind of mistake an optimization makes. Each fault must turn its AO check red.
    /// </summary>
    public sealed class PlantedSide : FrozenSide
    {
        public readonly string Fault;
        public PlantedSide(string fault) { Fault = fault; }
        public override string Name { get { return "planted:" + Fault; } }

        /// <summary>A key object with the per-key state that the thread faults misuse.</summary>
        sealed class PKey
        {
            public object Inner;
            public int KeyLength;
            public byte[] Scratch = new byte[16];
            public int TableState;    // 0 none, 1 building, 2 built: the lazy-table fault
        }

        static object In(object k) { return ((PKey)k).Inner; }

        public override object NewAes(byte[] key)
        {
            PKey p = new PKey();
            p.Inner = base.NewAes(key);
            p.KeyLength = key.Length;
            return p;
        }

        public override void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo)
        {
            PKey p = (PKey)k;
            switch (Fault)
            {
                case "overlap-reads-after-write":
                    // Writes the output one word at a time and reads the input again after each word, as a word-state loop could.
                    Arg(i, io, o, oo);
                    for (int w = 0; w < 4; w++)
                    {
                        byte[] snap = new byte[16];
                        Buffer.BlockCopy(i, io, snap, 0, 16);
                        byte[] enc = new byte[16];
                        base.AesEncrypt(p.Inner, snap, 0, enc, 0);
                        Buffer.BlockCopy(enc, w * 4, o, oo + w * 4, 4);
                    }
                    return;
                case "writes-past-the-block":
                    base.AesEncrypt(p.Inner, i, io, o, oo);
                    if (o.Length > oo + 16) o[oo + 16] ^= 1;
                    return;
                case "skips-arg-check":
                    if (io < 0 || oo < 0) throw new IndexOutOfRangeException("planted");
                    base.AesEncrypt(p.Inner, i, io, o, oo);
                    return;
                case "shared-scratch":
                    // One scratch buffer per key object, used with no lock: a race when two threads share the key.
                    Buffer.BlockCopy(i, io, p.Scratch, 0, 16);
                    Thread.SpinWait(50);
                    base.AesEncrypt(p.Inner, p.Scratch, 0, o, oo);
                    return;
                case "lazy-table-race":
                    // A per-key table built on first use, published before it is complete.
                    if (p.TableState == 0) { p.TableState = 1; Thread.Sleep(2); p.TableState = 2; }
                    base.AesEncrypt(p.Inner, i, io, o, oo);
                    if (p.TableState == 1) o[oo] ^= 0x80;
                    return;
                default:
                    base.AesEncrypt(p.Inner, i, io, o, oo);
                    return;
            }
        }

        static void Arg(byte[] i, int io, byte[] o, int oo)
        {
            if (i == null || o == null) throw new ArgumentNullException("b");
            if (io < 0 || io > i.Length - 16 || oo < 0 || oo > o.Length - 16) throw new ArgumentOutOfRangeException("off");
        }

        public override void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo)
        {
            PKey p = (PKey)k;
            base.AesDecrypt(p.Inner, i, io, o, oo);
            if (Fault == "decrypt-wrong-for-192" && p.KeyLength == 24) o[oo + 5] ^= 4;
        }

        public override byte[] Ecb(object k, byte[] data)
        {
            if (Fault == "ecb-empty-gives-null" && data != null && data.Length == 0) return null;
            return base.Ecb(In(k), data);
        }

        public override byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt)
        {
            if (Fault == "cbc-zero-iv" && encrypt && iv != null) iv = new byte[iv.Length];
            byte[] r = base.Cbc(In(k), iv, data, encrypt);
            if (Fault == "cbc-decrypt-overwrites-input" && !encrypt && data != null) Buffer.BlockCopy(r, 0, data, 0, Math.Min(r.Length, data.Length));
            return r;
        }

        public override byte[] Ctr(object k, byte[] counter, byte[] data)
        {
            if (Fault == "ctr-advances-caller-counter")
            {
                byte[] r = base.Ctr(In(k), counter, data);
                counter[15]++;
                return r;
            }
            if (Fault == "ctr-carries-32-bits-only" && counter != null && counter.Length == 16 && data != null)
            {
                byte[] c = (byte[])counter.Clone(), o = new byte[data.Length], ks = new byte[16];
                for (int off = 0; off < data.Length; off += 16)
                {
                    base.AesEncrypt(In(k), c, 0, ks, 0);
                    for (int j = 0; j < 16 && off + j < data.Length; j++) o[off + j] = (byte)(data[off + j] ^ ks[j]);
                    for (int j = 15; j >= 12; j--) if (++c[j] != 0) break;
                }
                return o;
            }
            return base.Ctr(In(k), counter, data);
        }

        public override byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain)
        {
            if (Fault == "gcm-seal-shared-scratch" && nonce != null && nonce.Length == 12)
            {
                // The nonce goes through one buffer per key object, with no lock: a race when two threads seal on one key.
                PKey p = (PKey)k;
                Buffer.BlockCopy(nonce, 0, p.Scratch, 0, 12);
                Thread.SpinWait(500);
                byte[] n = new byte[12];
                Buffer.BlockCopy(p.Scratch, 0, n, 0, 12);
                return base.GcmSeal(p.Inner, n, aad, plain);
            }
            byte[] r = base.GcmSeal(In(k), nonce, aad, plain);
            if (Fault == "gcm-length-17" && plain != null && plain.Length == 17) r[3] ^= 1;
            return r;
        }

        public override bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { return base.GcmOpen(In(k), nonce, aad, sealedBytes, out plain); }
        public override byte[] Cmac(object k, byte[] message) { return base.Cmac(In(k), message); }

        public override bool CmacVerify(object k, byte[] message, byte[] tag)
        {
            if (Fault != "cmac-accepts-tag-prefix") return base.CmacVerify(In(k), message, tag);
            byte[] t = base.Cmac(In(k), message);
            if (tag == null || tag.Length == 0 || tag.Length > t.Length) return false;
            for (int j = 0; j < tag.Length; j++) if (tag[j] != t[j]) return false;
            return true;
        }

        sealed class SplitHash : IAoHash
        {
            readonly string _alg; readonly bool _shareOnClone; readonly List<byte> _all = new List<byte>(); bool _boundary;
            IAoHash _shared;
            public SplitHash(string alg, bool shareOnClone) { _alg = alg; _shareOnClone = shareOnClone; }
            public void Update(byte[] b, int off, int n)
            {
                if (_shared != null) { _shared.Update(b, off, n); return; }
                if (n > 0 && _all.Count > 0 && _all.Count % 64 == 0) _boundary = true;
                for (int j = 0; j < n; j++) _all.Add(b[off + j]);
            }
            public byte[] Finish()
            {
                if (_shared != null) return _shared.Finish();
                byte[] d = _all.ToArray();
                if (!_shareOnClone && _boundary && d.Length > 0) { byte[] e = new byte[d.Length - 1]; Array.Copy(d, 1, e, 0, e.Length); d = e; }
                IAoHash h = new FrozenSide().NewHash(_alg);
                h.Update(d, 0, d.Length);
                return h.Finish();
            }
            public IAoHash Clone()
            {
                if (_shareOnClone) return this;
                SplitHash c = new SplitHash(_alg, false);
                c._all.AddRange(_all); c._boundary = _boundary;
                return c;
            }
        }

        public override IAoHash NewHash(string alg)
        {
            if (Fault == "hash-drops-byte-at-block-split") return new SplitHash(alg, false);
            if (Fault == "hash-clone-shares-state") return new CloneSharer(base.NewHash(alg));
            if (Fault == "hash-drops-last-byte") return new DropLast(base.NewHash(alg));
            return base.NewHash(alg);
        }

        /// <summary>Holds back the last byte of each Update: a tail-handling fault that hits a whole-file hash.</summary>
        sealed class DropLast : IAoHash
        {
            readonly IAoHash _h;
            public DropLast(IAoHash h) { _h = h; }
            public void Update(byte[] b, int off, int n) { _h.Update(b, off, n > 0 ? n - 1 : 0); }
            public byte[] Finish() { return _h.Finish(); }
            public IAoHash Clone() { return new DropLast(_h.Clone()); }
        }

        sealed class CloneSharer : IAoHash
        {
            readonly IAoHash _h;
            public CloneSharer(IAoHash h) { _h = h; }
            public void Update(byte[] b, int off, int n) { _h.Update(b, off, n); }
            public byte[] Finish() { return _h.Finish(); }
            public IAoHash Clone() { return this; }
        }

        public override byte[] Shake(bool is128, byte[] data, int[] squeezeSizes)
        {
            if (Fault != "shake-squeeze-restarts") return base.Shake(is128, data, squeezeSizes);
            List<byte> all = new List<byte>();
            foreach (int n in squeezeSizes) all.AddRange(base.Shake(is128, data, new int[] { n }));
            return all.ToArray();
        }

        public override byte[] Hmac(string alg, byte[] key, byte[] data)
        {
            int block = AoGrammar.BlockOf(alg);
            if (Fault == "hmac-long-key-cut" && key != null && key.Length > block) { byte[] k = new byte[block]; Array.Copy(key, k, block); key = k; }
            if (Fault == "hmac-drops-last-byte" && data != null && data.Length > 0) { byte[] d = new byte[data.Length - 1]; Array.Copy(data, d, d.Length); data = d; }
            return base.Hmac(alg, key, data);
        }

        public override byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n)
        {
            int max = 255 * AoGrammar.DigestOf(alg);
            if (Fault == "hkdf-no-max-check" && n > max) return base.HkdfExpand(alg, prk, info, max);
            return base.HkdfExpand(alg, prk, info, n);
        }

        public override byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count)
        {
            if (Fault == "prf-count-zero-null" && count == 0) return null;
            return base.PrfDerive(secret, label, seed, count);
        }

        string _lastPan;
        public override byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8) { _lastPan = pan; return base.PinEncrypt4(pinKey, pin, pan, random8); }
        public override bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin)
        {
            if (Fault == "pin-ignores-pan" && _lastPan != null) pan = _lastPan;
            return base.PinTryDecrypt4(pinKey, block, pan, out pin);
        }

        public override object WalkEncrypt(object k, byte[] block)
        {
            PKey p = (PKey)k;
            if (Fault == "walk-wrong-for-192" && p.KeyLength == 24 && block != null && block.Length == 16) { block = (byte[])block.Clone(); block[0] ^= 1; }
            return base.WalkEncrypt(p.Inner, block);
        }
        public override object WalkDecrypt(object k, byte[] block) { return base.WalkDecrypt(In(k), block); }
        public override object WalkKeyExpansion(object k) { return base.WalkKeyExpansion(In(k)); }
    }

    public static class SelfAo
    {
        static readonly string[][] Ao2Faults = {
            new[] { "aes-block", "overlap-reads-after-write" }, new[] { "aes-block", "writes-past-the-block" }, new[] { "aes-block", "skips-arg-check" },
            new[] { "aes-block", "decrypt-wrong-for-192" }, new[] { "aes-ecb", "ecb-empty-gives-null" }, new[] { "aes-cbc", "cbc-decrypt-overwrites-input" },
            new[] { "aes-ctr", "ctr-advances-caller-counter" }, new[] { "aes-ctr", "ctr-carries-32-bits-only" }, new[] { "aes-gcm", "gcm-length-17" },
            new[] { "aes-cmac", "cmac-accepts-tag-prefix" }, new[] { "sha256", "hash-drops-byte-at-block-split" }, new[] { "sha1", "hash-clone-shares-state" },
            new[] { "shake128", "shake-squeeze-restarts" }, new[] { "hmac", "hmac-long-key-cut" }, new[] { "hkdf", "hkdf-no-max-check" },
            new[] { "tls11-prf", "prf-count-zero-null" }, new[] { "pinblock-format4", "pin-ignores-pan" },
            new[] { "aes-walk", "walk-wrong-for-192" },
        };

        [Clause("SELF.ao2-second-referee-agrees-and-bites", TimeoutSec = 1800)]
        public static string Ao2SecondReferee(Ctx c)
        {
            List<string> ran = new List<string>();
            foreach (string alg in AoGrammar.Algorithms)
            {
                if (!BclSide.Supports(alg)) continue;
                string r = AoDiff.Run(alg, new FrozenSide(), new FrozenSide(), new BclSide(), SelfCases);
                if (!r.StartsWith(SelfCases + " of ") || r.Contains(" ran 0 cases")) throw new FailException(alg + ": the BCL referee did not agree or did not run: " + r);
                ran.Add(alg);
            }
            string planted;
            try { planted = "PASS " + AoDiff.Run("sha256", new FrozenSide(), new FrozenSide(), new PlantedSide("hash-drops-byte-at-block-split"), SelfCases); }
            catch (FailException e) { planted = "FAIL " + e.Reason + " " + e.Message; }
            if (!planted.StartsWith("FAIL AO_DIFFERS") || !planted.Contains("the second referee")) throw new FailException("a wrong second referee went unseen: " + planted);
            return "BCL agrees with the frozen reference on the clean cases of " + ran.Count + " algorithms (" + string.Join(", ", ran.ToArray()) + "); a wrong second referee FAILs AO_DIFFERS";
        }

        [Clause("SELF.ao5-meter-bites")]
        public static string Ao5MeterBites(Ctx c)
        {
            object sink = null;
            string none = AoAllocMeter.Judge("no allocation", AoAllocMeter.PerUnit(delegate { sink = null; }, -1, 1), "call");
            string arrayOnly = AoAllocMeter.Judge("returns a new byte[32] only", AoAllocMeter.PerUnit(delegate { sink = new byte[32]; }, 32, 1), "call");
            List<string> planted = new List<string>();
            foreach (KeyValuePair<string, Action> p in new[] {
                new KeyValuePair<string, Action>("one byte[1] per call", delegate { sink = new byte[1]; }),
                new KeyValuePair<string, Action>("a byte[32] plus one object per call", delegate { sink = new byte[32]; sink = new object(); }),
                new KeyValuePair<string, Action>("one byte[16] per 64 calls", MakeRare(64)),
                // Rarer than once in 400 calls: the lowest round can read 0 B, so only the highest round sees it (Jared on #405, N2).
                new KeyValuePair<string, Action>("one byte[16] per 1000 calls", MakeRare(1000)) })
            {
                int outLen = p.Key.StartsWith("a byte[32]") ? 32 : -1;
                string got;
                try { got = "PASS " + AoAllocMeter.Judge(p.Key, AoAllocMeter.PerUnit(p.Value, outLen, 1), "call"); }
                catch (FailException e) { got = "FAIL " + e.Reason; }
                if (got != "FAIL AO5_ALLOCATES") throw new FailException("the meter passed a planted allocation (" + p.Key + "): " + got);
                planted.Add(p.Key + ": FAIL");
            }
            GC.KeepAlive(sink);
            // The budget (Jared's condition 2): 10 B against a budget of 16 is PASS; against a budget of 8 it is FAIL AO5_ALLOCATES.
            AoAllocMeter.PerUnitResult ten = new AoAllocMeter.PerUnitResult { Low = 10, High = 10 };
            string within = AoAllocMeter.Judge("ten bytes", ten, "call", 16);
            string over;
            try { over = "PASS " + AoAllocMeter.Judge("ten bytes", ten, "call", 8); } catch (FailException e) { over = "FAIL " + e.Reason; }
            if (!within.Contains("within the budget") || over != "FAIL AO5_ALLOCATES") throw new FailException("the budget judge gave '" + within + "' and '" + over + "'");
            return "control: " + none + "; " + arrayOnly + "; planted: " + string.Join("; ", planted.ToArray()) + "; budget: 10 B within 16 -> PASS, 10 B over 8 -> FAIL";
        }

        static Action MakeRare(int every)
        {
            int n = 0;
            object keep = null;
            return delegate { if (++n % every == 0) keep = new byte[16]; GC.KeepAlive(keep); };
        }

        [Clause("SELF.ao9-files-bite", TimeoutSec = 900)]
        public static string Ao9FilesBite(Ctx c)
        {
            string root = System.IO.Path.Combine(c.WorkDir, "ao9-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            string acc = System.IO.Path.Combine(root, "acceptance"), files = System.IO.Path.Combine(root, "bench", "files");
            System.IO.Directory.CreateDirectory(acc); System.IO.Directory.CreateDirectory(files);
            List<string> lines = new List<string> { "name\tbytes\tsha256" };
            foreach (KeyValuePair<string, int> f in new[] { new KeyValuePair<string, int>("sample.csv", 5000), new KeyValuePair<string, int>("seventeen.bin", 17), new KeyValuePair<string, int>("empty.bin", 0) })
            {
                byte[] b = new Rng(0xA09F00UL + (ulong)f.Value).Bytes(f.Value);
                System.IO.File.WriteAllBytes(System.IO.Path.Combine(files, f.Key), b);
                using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create()) lines.Add(f.Key + "\t" + f.Value + "\t" + Hex.Encode(h.ComputeHash(b)));
            }
            System.IO.File.WriteAllLines(System.IO.Path.Combine(acc, "ao9-files.tsv"), lines.ToArray());
            List<AoFileSet.Entry> set = AoFileSet.Load(acc, root);
            List<string> control = new List<string>();
            foreach (string op in new[] { "gcm", "cbc", "ctr", "sha256", "hmac" }) control.Add(AoFileSet.Compare(op, new FrozenSide(), new FrozenSide(), set).Split(' ')[0]);
            AoFileSet.SmallMessage(new FrozenSide(), new FrozenSide());
            AoThreads.CapPool();
            AoFileSet.Pool25(new FrozenSide(), new PlantedSide("none"), set);
            string[][] planted = { new[] { "gcm", "gcm-length-17" }, new[] { "cbc", "cbc-zero-iv" }, new[] { "ctr", "ctr-advances-caller-counter" },
                                   new[] { "sha256", "hash-drops-last-byte" }, new[] { "hmac", "hmac-drops-last-byte" } };
            List<string> seen = new List<string>();
            foreach (string[] p in planted)
            {
                string got;
                try { got = "PASS " + AoFileSet.Compare(p[0], new FrozenSide(), new PlantedSide(p[1]), set); }
                catch (FailException e) { got = "FAIL " + e.Reason; }
                seen.Add(p[0] + "/" + p[1] + ": " + got);
                if (got != "FAIL AO9_OUTPUT_DIFFERS")
                    throw new FailException("AO-9 " + p[0] + " passed the planted fault " + p[1] + ": " + got);
            }
            string pool;
            try { pool = "PASS " + AoFileSet.Pool25(new FrozenSide(), new PlantedSide("gcm-seal-shared-scratch"), set); }
            catch (FailException e) { pool = "FAIL " + e.Reason; }
            if (pool != "FAIL AO9_OUTPUT_DIFFERS") throw new FailException("pool-25 passed a shared nonce buffer: " + pool);
            System.IO.File.WriteAllBytes(System.IO.Path.Combine(files, "seventeen.bin"), new byte[17]);
            string changed;
            try { AoFileSet.Load(acc, root); changed = "PASS"; } catch (FailException e) { changed = "FAIL " + e.Reason; }
            if (changed != "FAIL AO9_FILE_CHANGED") throw new FailException("a changed AO-9 file passed: " + changed);
            System.IO.File.Delete(System.IO.Path.Combine(files, "empty.bin"));
            string absent;
            try { AoFileSet.Load(acc, root); absent = "PASS"; } catch (NotRunException e) { absent = "NOT RUN " + e.Reason; } catch (FailException e) { absent = "FAIL " + e.Reason; }
            if (absent != "NOT RUN AO9_FILES_ABSENT") throw new FailException("a missing AO-9 file read " + absent);
            return "control: 5 ops, small-message and pool-25 equal on frozen and frozen; planted: " + string.Join("; ", seen.ToArray()) +
                   "; pool-25 with a shared nonce buffer: FAIL; changed file: FAIL AO9_FILE_CHANGED; missing file: NOT RUN AO9_FILES_ABSENT";
        }

        [Clause("SELF.ao7-walk-helper-rule-bites")]
        public static string Ao7WalkRuleBites(Ctx c)
        {
            string dir = System.IO.Path.Combine(c.WorkDir, "ao7-walk-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            System.IO.Directory.CreateDirectory(dir);
            string other = System.IO.Path.Combine(dir, "AesKey.cs"), good = System.IO.Path.Combine(dir, "GoodWalk.cs"), bad = System.IO.Path.Combine(dir, "BadWalk.cs");
            System.IO.File.WriteAllText(other, "class AesKey {\n  static byte Xtime(byte a) { return a; }\n  public void EncryptBlock(byte[] i, int io, byte[] o, int oo)\n  {\n  }\n}\n");
            System.IO.File.WriteAllText(good, "class AesKey {\n  static byte WalkXtime(byte a) { return a; }\n  void W() { WalkXtime(1); EncryptBlock(null, 0, null, 0); // Xtime(2) in a comment\n  }\n}\n");
            System.IO.File.WriteAllText(bad, "class AesKey {\n  void W() { byte b = Xtime(1); EncryptBlock(null, 0, null, 0); }\n}\n");
            string control = AoFiles.WalkCallsOnlyBlockEntries(good, new[] { other });
            string planted;
            try { planted = "PASS " + AoFiles.WalkCallsOnlyBlockEntries(bad, new[] { other }); }
            catch (FailException e) { planted = "FAIL " + e.Reason + " " + e.Message; }
            if (!planted.StartsWith("FAIL AO_WALK_CALLS_AESKEY_HELPER")) throw new FailException("a walk that calls Xtime passed: " + planted);
            string frozenDir = System.IO.Path.Combine(c.AcceptanceDir, "groups", "algo", "Frozen");
            string frozen;
            try { frozen = "PASS " + AoFiles.WalkCallsOnlyBlockEntries(System.IO.Path.Combine(frozenDir, "AesKey.Walk.cs"), new[] { System.IO.Path.Combine(frozenDir, "AesKey.cs") }); }
            catch (FailException e) { frozen = "FAIL " + e.Reason + " " + e.Message; }
            if (!frozen.StartsWith("FAIL AO_WALK_CALLS_AESKEY_HELPER")) throw new FailException("the 5c5d4a4 walk, which calls helpers in AesKey.cs, passed: " + frozen);
            return "control: " + control + "; planted Xtime call: FAIL; the 5c5d4a4 walk: " + frozen;
        }

        [Clause("SELF.ao7-files-check-bites")]
        public static string Ao7FilesBite(Ctx c)
        {
            string dir = System.IO.Path.Combine(c.WorkDir, "ao7-repo-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(dir, "acceptance", "golden"));
            string f = System.IO.Path.Combine(dir, "acceptance", "golden", "t.ndjson");
            System.IO.File.WriteAllText(f, "{\"a\":1}\n");
            string o;
            foreach (string args in new[] { "init -q", "-c user.email=self@test -c user.name=self add -A", "-c user.email=self@test -c user.name=self commit -q -m base" })
                if (Proc.Run("git", "-C \"" + dir + "\" " + args, dir, 60000, out o) != 0) throw new FailException("git " + args + ": " + o);
            Proc.Run("git", "-C \"" + dir + "\" rev-parse HEAD", dir, 60000, out o);
            string head = o.Trim();
            string control = AoFiles.Unchanged(dir, head, new[] { "acceptance/golden" });
            System.IO.File.WriteAllText(f, "{\"a\":2}\n");
            string changed;
            try { changed = "PASS " + AoFiles.Unchanged(dir, head, new[] { "acceptance/golden" }); }
            catch (FailException e) { changed = "FAIL " + e.Reason; }
            if (changed != "FAIL AO_FILES_CHANGED") throw new FailException("a changed golden file passed: " + changed);
            System.IO.File.WriteAllText(f, "{\"a\":1}\n");
            System.IO.File.WriteAllText(System.IO.Path.Combine(dir, "acceptance", "golden", "new.ndjson"), "x\n");
            string added;
            try { added = "PASS " + AoFiles.Unchanged(dir, head, new[] { "acceptance/golden" }); }
            catch (FailException e) { added = "FAIL " + e.Reason; }
            if (added != "FAIL AO_FILES_CHANGED") throw new FailException("an added golden file passed: " + added);
            return "control: " + control + "; one changed byte: FAIL; one added file: FAIL";
        }

        const int SelfCases = 20000;

        [Clause("SELF.ao2-control-passes", TimeoutSec = 1800)]
        public static string Ao2Control(Ctx c)
        {
            List<string> algs = new List<string>(AoGrammar.Algorithms);
            algs.Add("aes-walk");
            foreach (string alg in algs)
            {
                string r = AoDiff.Run(alg, new FrozenSide(), new FrozenSide(), SelfCases);
                if (!r.StartsWith(SelfCases + " of ")) throw new FailException(alg + " control gave " + r);
            }
            return algs.Count + " grammars (20 algorithms and the AES walk): frozen against frozen, " + SelfCases + " cases each, 0 differences";
        }

        [Clause("SELF.ao2-planted-faults-fail", TimeoutSec = 1800)]
        public static string Ao2Bites(Ctx c)
        {
            List<string> lines = new List<string>();
            foreach (string[] f in Ao2Faults)
            {
                string got;
                try { got = "PASS " + AoDiff.Run(f[0], new FrozenSide(), new PlantedSide(f[1]), SelfCases); }
                catch (FailException e) { got = "FAIL " + e.Reason + " " + e.Message; }
                if (!got.StartsWith("FAIL AO_DIFFERS")) throw new FailException("AO-2 " + f[0] + " did not catch the planted fault " + f[1] + ": " + got);
                lines.Add(f[0] + "/" + f[1] + ": " + got.Substring(16, Math.Min(60, got.Length - 16)));
            }
            return Ao2Faults.Length + " planted faults each FAIL AO_DIFFERS: " + string.Join("; ", lines.ToArray());
        }

        [Clause("SELF.ao3-math-and-startup-bite")]
        public static string Ao3Bites(Ctx c)
        {
            System.Reflection.Assembly me = typeof(SelfAo).Assembly;
            // Control: the frozen 5c5d4a4 tables equal the suite's math, so the math is right.
            string control = AoTables.EqualsMath(AoTables.TypesIn(me, "Acceptance.Frozen.Crypto", AoTables.AesScope), AoTables.AesMath());
            // Fact 1 of the PRD: the frozen AesKey builds its tables in a static constructor. The start-up check must see it.
            string frozenStartup;
            try { frozenStartup = "PASS " + AoTables.NoStartupBuild(AoTables.TypesIn(me, "Acceptance.Frozen.Crypto", AoTables.AesScope)); }
            catch (FailException e) { frozenStartup = "FAIL " + e.Reason + " " + e.Message; }
            if (!frozenStartup.StartsWith("FAIL AO_TABLE_BUILT_AT_STARTUP")) throw new FailException("the start-up check passed the frozen AesKey, which builds its tables: " + frozenStartup);
            string wrong;
            try { wrong = "PASS " + AoTables.EqualsMath(AoTables.TypesIn(me, "Acceptance.AoPlanted", delegate (Type t) { return t.Name == "AesWrongTable"; }), AoTables.AesMath()); }
            catch (FailException e) { wrong = "FAIL " + e.Reason; }
            if (wrong != "FAIL AO_TABLE_UNMATCHED") throw new FailException("a table with one wrong byte passed: " + wrong);
            string constOnly = AoTables.NoStartupBuild(AoTables.TypesIn(me, "Acceptance.AoPlanted", delegate (Type t) { return t.Name == "AesConstOnly"; }));
            string loop;
            try { loop = "PASS " + AoTables.NoStartupBuild(AoTables.TypesIn(me, "Acceptance.AoPlanted", delegate (Type t) { return t.Name == "AesLoopInit"; })); }
            catch (FailException e) { loop = "FAIL " + e.Reason; }
            if (loop != "FAIL AO_TABLE_BUILT_AT_STARTUP") throw new FailException("a type initializer with a loop passed the start-up check: " + loop);
            string ghash = AoTables.EqualsMath(AoTables.TypesIn(me, "Acceptance.AoPlanted", delegate (Type t) { return t.Name == "GhashKnownTable"; }), AoTables.GhashMath());
            return "frozen AES tables: " + control.Substring(0, Math.Min(80, control.Length)) + "; frozen start-up: FAIL as fact 1 says; one wrong S-box byte: FAIL; constant-only initializer: " +
                   constOnly + "; loop initializer: FAIL; published GHASH last4 table: " + ghash;
        }

        [Clause("SELF.ao4-control-and-planted-faults", TimeoutSec = 1800)]
        public static string Ao4Bites(Ctx c)
        {
            string control = AoThreads.Run(new FrozenSide(), 20000, 2, AoThreads.Seed);
            List<string> lines = new List<string>();
            foreach (string fault in new[] { "shared-scratch", "lazy-table-race" })
            {
                string got;
                try { got = "PASS " + AoThreads.Run(new PlantedSide(fault), 20000, 2, AoThreads.Seed); }
                catch (FailException e) { got = "FAIL " + e.Reason + " " + e.Message; }
                if (!got.StartsWith("FAIL AO_THREAD_MISMATCH")) throw new FailException("AO-4 did not catch the planted fault " + fault + ": " + got);
                lines.Add(fault + ": " + got.Substring(0, Math.Min(90, got.Length)));
            }
            return "control PASS (" + control.Substring(0, Math.Min(120, control.Length)) + "); " + string.Join("; ", lines.ToArray());
        }
    }
}

namespace Acceptance.AoPlanted
{
    /// <summary>An S-box with one byte changed: AO-3 must find no match.</summary>
    static class AesWrongTable
    {
        static readonly int[] Sbox = Make();
        static int[] Make() { int[] s = Acceptance.AoTables.Sbox(); s[77] ^= 1; return s; }
    }

    /// <summary>Constants only: the start-up check must pass this initializer.</summary>
    static class AesConstOnly
    {
        static readonly byte[] Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
        static readonly int[] ShiftRowsMap = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
    }

    /// <summary>A loop in the initializer: the start-up check must name it.</summary>
    static class AesLoopInit
    {
        static readonly byte[] Rcon = new byte[10];
        static AesLoopInit() { int rc = 1; for (int i = 0; i < 10; i++) { Rcon[i] = (byte)rc; rc = ((rc << 1) ^ ((rc & 0x80) != 0 ? 0x11b : 0)) & 0xff; } }
    }

    /// <summary>The 4-bit GHASH reduction table as published in the GCM paper (McGrew and Viega, 2005), typed from the paper.</summary>
    static class GhashKnownTable
    {
        static readonly ushort[] Last4 = { 0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0 };
    }
}

namespace Acceptance
{
    /// <summary>The caller-buffer reference model with one planted fault: each must turn its AO-2 "-into" row red.</summary>
    public sealed class PlantedInto : FrozenInto
    {
        readonly string _fault;
        public PlantedInto(string fault) { _fault = fault; }
        public override string Name { get { return "planted:" + _fault; } }

        protected override void Overlap(byte[] a, int ao, int an, byte[] b, int bo, int bn)
        {
            if (_fault == "accepts-partial-overlap") return;
            base.Overlap(a, ao, an, b, bo, bn);
        }

        protected override byte[] Nonce(byte[] nonce, int no)
        {
            if (_fault == "gcm-short-nonce-padded" && nonce != null && no >= 0 && nonce.Length - no < 12)
            {
                byte[] n = new byte[12];
                Buffer.BlockCopy(nonce, no, n, 0, Math.Max(0, nonce.Length - no));
                return n;
            }
            return base.Nonce(nonce, no);
        }

        public override void GcmSeal(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo)
        {
            // PRD 7.3 item 15: the nonce length is checked before the overlap. This fault checks the overlap first.
            if (_fault == "gcm-overlap-checked-before-nonce") base.Overlap(i, io, n, o, oo, n + 16);
            base.GcmSeal(k, nonce, no, aad, ao, an, i, io, n, o, oo);
        }

        public override void Cbc(object k, bool encrypt, byte[] iv, int ivo, byte[] i, int io, int n, byte[] o, int oo)
        {
            if (_fault != "cbc-decrypt-in-place-loses-chain" || encrypt || !ReferenceEquals(i, o) || io != oo) { base.Cbc(k, encrypt, iv, ivo, i, io, n, o, oo); return; }
            // In place, block by block, taking the chain from the array after the block before it was overwritten.
            FrozenSide f = new FrozenSide();
            byte[] prev = Slice(iv, ivo, 16), plain = new byte[16];
            for (int b = 0; b < n; b += 16)
            {
                f.AesDecrypt(k, i, io + b, plain, 0);
                for (int j = 0; j < 16; j++) o[oo + b + j] = (byte)(plain[j] ^ prev[j]);
                prev = Slice(o, oo + b, 16);
            }
        }

        public override void Ctr(object k, byte[] ctr, int co, byte[] i, int io, int n, byte[] o, int oo)
        {
            base.Ctr(k, ctr, co, i, io, n, o, oo);
            if (_fault == "ctr-moves-caller-counter") ctr[co + 15]++;
        }

        public override bool GcmOpen(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo)
        {
            if (_fault != "gcm-open-bad-tag-keeps-output") return base.GcmOpen(k, nonce, no, aad, ao, an, i, io, n, o, oo);
            byte[] keep = Slice(o, oo, n - 16);
            bool ok = base.GcmOpen(k, nonce, no, aad, ao, an, i, io, n, o, oo);
            if (!ok) Buffer.BlockCopy(keep, 0, o, oo, n - 16);
            return ok;
        }

        public override void CmacKey(object k, byte[] m, int mo, int n, byte[] t, int to)
        {
            base.CmacKey(k, m, mo, n, t, to);
            if (_fault == "cmackey-tag-short" ) t[to + 15] = 0;
        }
    }

    public static class SelfAoInto
    {
        const int Cases = 20000;

        [Clause("SELF.ao2-into-control-and-planted-faults", TimeoutSec = 1800)]
        public static string IntoBites(Ctx c)
        {
            foreach (string op in AoIntoDiff.Ops)
            {
                string r = AoIntoDiff.Run(op, new FrozenInto(), new FrozenInto(), Cases);
                if (!r.StartsWith(Cases + " of ")) throw new FailException(op + " control gave " + r);
            }
            string[][] planted = {
                new[] { "aes-ecb-into", "accepts-partial-overlap" }, new[] { "aes-cbc-into", "cbc-decrypt-in-place-loses-chain" },
                new[] { "aes-ctr-into", "ctr-moves-caller-counter" }, new[] { "aes-gcm-into", "gcm-open-bad-tag-keeps-output" },
                new[] { "aes-gcm-into", "gcm-short-nonce-padded" }, new[] { "aes-cmackey-into", "cmackey-tag-short" },
                new[] { "aes-gcm-into", "gcm-overlap-checked-before-nonce" },
                // A product that skips the overlap check of the CMAC tag range (PRD 7.1.9).
                new[] { "aes-cmac-into", "accepts-partial-overlap" }, new[] { "aes-cmackey-into", "accepts-partial-overlap" },
            };
            List<string> seen = new List<string>();
            foreach (string[] p in planted)
            {
                string got;
                try { got = "PASS " + AoIntoDiff.Run(p[0], new FrozenInto(), new PlantedInto(p[1]), Cases); }
                catch (FailException e) { got = "FAIL " + e.Reason; }
                if (got != "FAIL AO_DIFFERS") throw new FailException(p[0] + " did not catch " + p[1] + ": " + got);
                seen.Add(p[0] + "/" + p[1] + ": FAIL");
            }
            return AoIntoDiff.Ops.Length + " caller-buffer ops: the model against itself, " + Cases + " cases each, 0 differences; planted: " + string.Join("; ", seen.ToArray());
        }
    }

    /// <summary>The streamed reference model with one planted fault in the state object: each must turn its AO-2 "-stream" row red.</summary>
    public sealed class PlantedChain : FrozenChain
    {
        readonly string _fault;
        byte[] _first = new byte[16];
        public PlantedChain(object key, string kind, string fault) : base(key, kind) { _fault = fault; }

        bool _used;

        public override void Init(byte[] b, int offset)
        {
            // The second message on one object keeps the chain value and the counter position of the first.
            if (_fault == "second-init-keeps-state" && _used) { State = 1; return; }
            // PRD 7.3 item 15: a refused Init leaves the object as it was. This fault empties the object first.
            if (_fault == "refused-init-empties-object" && (b == null || offset < 0 || b.Length - offset < 16)) { Array.Clear(V, 0, 16); Done = 0; State = 0; }
            if (_fault == "short-init-padded" && b != null && offset >= 0 && offset <= b.Length && b.Length - offset < 16)
            {
                V = new byte[16];
                Buffer.BlockCopy(b, offset, V, 0, b.Length - offset);
                Done = 0; State = 1;
                return;
            }
            base.Init(b, offset);
            _used = true;
            _first = (byte[])V.Clone();
        }

        public override void Clear()
        {
            if (_fault == "clear-keeps-ready") return;
            base.Clear();
        }

        public override void Call(byte[] i, int io, int n, byte[] o, int oo)
        {
            if (_fault == "call-before-init-accepted" && State == 0) { V = new byte[16]; State = 1; }
            bool inPlace = ReferenceEquals(i, o) && io == oo;
            // PRD 7.3 item 15: the arguments are checked before the state. This fault checks the state first.
            if (_fault == "state-checked-before-arguments" && State != 1) throw new InvalidOperationException("planted");
            if (_fault == "state-refusal-is-a-subtype" || _fault == "range-fault-is-argument-exception")
            {
                // The PRD names each exception "as that type and no subtype". These faults throw a subtype, or the base type.
                try { base.Call(i, io, n, o, oo); }
                catch (ArgumentOutOfRangeException) { if (_fault == "range-fault-is-argument-exception") throw new ArgumentException("planted"); throw; }
                catch (InvalidOperationException e)
                {
                    if (_fault == "state-refusal-is-a-subtype" && e.GetType() == typeof(InvalidOperationException)) throw new ObjectDisposedException("planted");
                    throw;
                }
                return;
            }
            if (_fault == "refused-call-ends-object")
            {
                // A refused call must change nothing. This fault ends the object after any refusal.
                try { base.Call(i, io, n, o, oo); }
                catch (AoHarnessException) { throw; }
                catch (Exception) { State = 2; throw; }
                return;
            }
            base.Call(i, io, n, o, oo);
            if (_fault == "chain-not-carried") V = (byte[])_first.Clone();
            // Decrypt in place, taking the next chain value from the array after the plaintext went over the ciphertext.
            if (_fault == "decrypt-in-place-loses-chain" && Kind == "cbc-decrypt" && inPlace && n >= 16) { V = new byte[16]; Buffer.BlockCopy(o, oo + n - 16, V, 0, 16); }
            if (_fault == "counter-not-carried") Done = 0;
            if (_fault == "partial-does-not-end" && State == 2) State = 1;
        }
    }

    public sealed class PlantedStream : FrozenStream
    {
        readonly string _fault;
        public PlantedStream(string fault) { _fault = fault; }
        public override string Name { get { return "planted:" + _fault; } }
        public override IAoChain NewChain(object k, string kind) { return new PlantedChain(k, kind, _fault); }

        public override void NullStateCall(object k, string kind, byte[] i, int io, int n, byte[] o, int oo)
        {
            if (_fault == "null-state-not-named") throw new NullReferenceException();
            base.NullStateCall(k, kind, i, io, n, o, oo);
        }

        public override bool CmacVerify(object k, byte[] m, int mo, int n, byte[] t, int to)
        {
            if (_fault != "verify-skips-last-tag-byte") return base.CmacVerify(k, m, mo, n, t, to);
            byte[] copy = (byte[])t.Clone();
            copy[to + 15] = new FrozenSide().Cmac(k, Hex.Slice(m, mo, n))[15];
            return base.CmacVerify(k, m, mo, n, copy, to);
        }

        public override bool CmacKeyVerify(object k, byte[] m, int mo, int n, byte[] t, int to)
        {
            if (_fault == "verify-reads-tag-at-0") return base.CmacVerify(k, m, mo, n, t, 0);
            return base.CmacKeyVerify(k, m, mo, n, t, to);
        }
    }

    public static class SelfAoStream
    {
        const int Cases = 20000;

        [Clause("SELF.ao2-stream-control-and-planted-faults", TimeoutSec = 1800)]
        public static string StreamBites(Ctx c)
        {
            foreach (string op in AoStreamDiff.Ops)
            {
                string r = AoStreamDiff.Run(op, new FrozenStream(), new FrozenStream(), Cases);
                if (!r.StartsWith(Cases + " of ")) throw new FailException(op + " control gave " + r);
            }
            string[][] planted = {
                new[] { "aes-cbc-stream", "chain-not-carried" }, new[] { "aes-cbc-stream", "decrypt-in-place-loses-chain" },
                new[] { "aes-cbc-stream", "call-before-init-accepted" }, new[] { "aes-cbc-stream", "clear-keeps-ready" },
                new[] { "aes-ctr-stream", "counter-not-carried" }, new[] { "aes-ctr-stream", "partial-does-not-end" },
                new[] { "aes-ctr-stream", "call-before-init-accepted" }, new[] { "aes-ctr-stream", "clear-keeps-ready" },
                new[] { "aes-cbc-stream", "second-init-keeps-state" }, new[] { "aes-ctr-stream", "second-init-keeps-state" },
                new[] { "aes-cbc-stream", "state-checked-before-arguments" }, new[] { "aes-ctr-stream", "state-checked-before-arguments" },
                new[] { "aes-cbc-stream", "refused-call-ends-object" }, new[] { "aes-ctr-stream", "refused-call-ends-object" },
                new[] { "aes-cbc-stream", "short-init-padded" }, new[] { "aes-ctr-stream", "null-state-not-named" },
                new[] { "aes-cbc-stream", "refused-init-empties-object" }, new[] { "aes-ctr-stream", "refused-init-empties-object" },
                new[] { "aes-cbc-stream", "state-refusal-is-a-subtype" }, new[] { "aes-ctr-stream", "state-refusal-is-a-subtype" },
                new[] { "aes-cbc-stream", "range-fault-is-argument-exception" }, new[] { "aes-ctr-stream", "range-fault-is-argument-exception" },
                new[] { "aes-cmac-verify-into", "verify-skips-last-tag-byte" }, new[] { "aes-cmackey-verify-into", "verify-reads-tag-at-0" },
            };
            List<string> seen = new List<string>();
            foreach (string[] p in planted)
            {
                string got;
                try { got = "PASS " + AoStreamDiff.Run(p[0], new FrozenStream(), new PlantedStream(p[1]), Cases); }
                catch (FailException e) { got = "FAIL " + e.Reason; }
                if (got != "FAIL AO_DIFFERS") throw new FailException(p[0] + " did not catch " + p[1] + ": " + got);
                seen.Add(p[0] + "/" + p[1] + ": FAIL");
            }
            return AoStreamDiff.Ops.Length + " ops: the model against itself, " + Cases + " cases each, 0 differences; planted: " + string.Join("; ", seen.ToArray());
        }
    }
}
