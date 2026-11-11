using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// AO-2: the differential run. Each case is drawn once from its own seed, then runs on the frozen 5c5d4a4 reference and on the subject.
    /// The two records must agree in full: outcome, outputs, inputs afterwards and canary bytes. Case i uses seed + i * golden, so one
    /// failing case can be run again alone.
    /// </summary>
    public static class AoDiff
    {
        public const int DefaultCases = 1000000;
        const ulong Step = 0x9E3779B97F4A7C15UL;

        /// <summary>A fixed seed for each algorithm: FNV-1a of the name. The report prints it.</summary>
        public static ulong SeedOf(string alg)
        {
            ulong h = 14695981039346656037UL;
            foreach (char ch in "AO-2." + alg) { h ^= ch; h *= 1099511628211UL; }
            return h;
        }

        public static int CasesOf(Ctx c) { return int.Parse(c.Prop("ao.cases", DefaultCases.ToString())); }

        static AoRec Exec(AoCase k, AoSide s)
        {
            AoRec r = new AoRec();
            try { k(s, r); }
            catch (AoHarnessException) { throw; }
            catch (Exception e) { r.Sig = AoRec.SigOf(e); }
            return r;
        }

        static bool Threw(AoRec r)
        {
            if (r.Sig != "ok") return true;
            foreach (string t in r.Texts) if (t.EndsWith("Exception") || t.Contains("Exception:")) return true;
            return false;
        }

        /// <summary>Runs the cases and returns the PASS detail, or throws FailException with the first three differences.</summary>
        public static string Run(string alg, AoSide reference, AoSide subject, int cases)
        {
            ulong seed = SeedOf(alg);
            int bad = 0, refThrew = 0;
            List<string> first = new List<string>();
            for (int i = 0; i < cases; i++)
            {
                Rng r = new Rng(seed + (ulong)i * Step);
                AoCase k = AoGrammar.Draw(alg, r);
                AoRec a = Exec(k, reference), b = Exec(k, subject);
                if (Threw(a)) refThrew++;
                string d = AoRec.Diff(a, b);
                if (d == null) continue;
                bad++;
                if (first.Count < 3) first.Add("case " + i + ": " + d);
            }
            string tail = alg + ": seed 0x" + seed.ToString("x16") + ", cases " + cases + ", cases where the reference threw " + refThrew +
                          ", reference " + reference.Name + ", subject " + subject.Name;
            if (bad > 0) throw new FailException("AO_DIFFERS", bad + " of " + cases + " cases differ (" + tail + "). First: " + string.Join(" | ", first.ToArray()));
            if (refThrew == 0 || refThrew == cases) throw new FailException("AO_GRAMMAR_ONE_SIDED", "every case or no case threw on the reference, so the error paths went untested (" + tail + ")");
            return cases + " of " + cases + " cases equal (" + tail + ")";
        }

        static string Clause(Ctx c, string alg) { return Run(alg, new FrozenSide(), AoSubject.Make(c), CasesOf(c)); }

        [Clause("AO-2.aes-block", PerBuild = true, TimeoutSec = 3600)] public static string AesBlock(Ctx c) { return Clause(c, "aes-block"); }
        [Clause("AO-2.aes-ecb", PerBuild = true, TimeoutSec = 3600)] public static string AesEcb(Ctx c) { return Clause(c, "aes-ecb"); }
        [Clause("AO-2.aes-cbc", PerBuild = true, TimeoutSec = 3600)] public static string AesCbc(Ctx c) { return Clause(c, "aes-cbc"); }
        [Clause("AO-2.aes-ctr", PerBuild = true, TimeoutSec = 3600)] public static string AesCtr(Ctx c) { return Clause(c, "aes-ctr"); }
        [Clause("AO-2.aes-gcm", PerBuild = true, TimeoutSec = 3600)] public static string AesGcm(Ctx c) { return Clause(c, "aes-gcm"); }
        [Clause("AO-2.aes-cmac", PerBuild = true, TimeoutSec = 3600)] public static string AesCmac(Ctx c) { return Clause(c, "aes-cmac"); }
        [Clause("AO-2.tdes-block", PerBuild = true, TimeoutSec = 3600)] public static string TdesBlock(Ctx c) { return Clause(c, "tdes-block"); }
        [Clause("AO-2.md5", PerBuild = true, TimeoutSec = 3600)] public static string Md5(Ctx c) { return Clause(c, "md5"); }
        [Clause("AO-2.sha1", PerBuild = true, TimeoutSec = 3600)] public static string Sha1(Ctx c) { return Clause(c, "sha1"); }
        [Clause("AO-2.sha256", PerBuild = true, TimeoutSec = 3600)] public static string Sha256(Ctx c) { return Clause(c, "sha256"); }
        [Clause("AO-2.sha384", PerBuild = true, TimeoutSec = 3600)] public static string Sha384(Ctx c) { return Clause(c, "sha384"); }
        [Clause("AO-2.sha512", PerBuild = true, TimeoutSec = 3600)] public static string Sha512(Ctx c) { return Clause(c, "sha512"); }
        [Clause("AO-2.sha3-256", PerBuild = true, TimeoutSec = 3600)] public static string Sha3_256(Ctx c) { return Clause(c, "sha3-256"); }
        [Clause("AO-2.sha3-512", PerBuild = true, TimeoutSec = 3600)] public static string Sha3_512(Ctx c) { return Clause(c, "sha3-512"); }
        [Clause("AO-2.shake128", PerBuild = true, TimeoutSec = 3600)] public static string Shake128(Ctx c) { return Clause(c, "shake128"); }
        [Clause("AO-2.shake256", PerBuild = true, TimeoutSec = 3600)] public static string Shake256(Ctx c) { return Clause(c, "shake256"); }
        [Clause("AO-2.hmac", PerBuild = true, TimeoutSec = 3600)] public static string Hmac(Ctx c) { return Clause(c, "hmac"); }
        [Clause("AO-2.hkdf", PerBuild = true, TimeoutSec = 3600)] public static string Hkdf(Ctx c) { return Clause(c, "hkdf"); }
        [Clause("AO-2.tls11-prf", PerBuild = true, TimeoutSec = 3600)] public static string Tls11Prf(Ctx c) { return Clause(c, "tls11-prf"); }
        [Clause("AO-2.pinblock-format4", PerBuild = true, TimeoutSec = 3600)] public static string PinBlock(Ctx c) { return Clause(c, "pinblock-format4"); }

        /// <summary>AO-7: the lesson walk, step for step, against the frozen walk. 100,000 cases: a walk case costs about 40 block calls.</summary>
        [Clause("AO-7.aes-walk-equals-frozen", PerBuild = true, TimeoutSec = 3600)]
        public static string AesWalk(Ctx c) { return Run("aes-walk", new FrozenSide(), AoSubject.Make(c), int.Parse(c.Prop("ao.walk-cases", "100000"))); }
    }
}
