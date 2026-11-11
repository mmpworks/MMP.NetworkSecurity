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
            return base.NewHash(alg);
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
