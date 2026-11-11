namespace Acceptance
{
    /// <summary>AO-9 output equality on the file set (PRD 3.3), computed by the suite. pool-25 runs in the algothreads group, under the pool cap.</summary>
    public static class AoFiles9
    {
        static string Op(Ctx c, string op)
        {
            AoSide s = AoSubject.Make(c);
            return AoFileSet.Compare(op, new FrozenSide(), s, AoFileSet.Load(c.AcceptanceDir, c.RepoRoot));
        }

        [Clause("AO-9.gcm", PerBuild = true)] public static string Gcm(Ctx c) { return Op(c, "gcm"); }
        [Clause("AO-9.cbc", PerBuild = true)] public static string Cbc(Ctx c) { return Op(c, "cbc"); }
        [Clause("AO-9.ctr", PerBuild = true)] public static string Ctr(Ctx c) { return Op(c, "ctr"); }
        [Clause("AO-9.sha256", PerBuild = true)] public static string Sha256(Ctx c) { return Op(c, "sha256"); }
        [Clause("AO-9.hmac", PerBuild = true)] public static string Hmac(Ctx c) { return Op(c, "hmac"); }

        [Clause("AO-9.small-message", PerBuild = true)]
        public static string SmallMessage(Ctx c)
        {
            AoSide s = AoSubject.Make(c);
            AoFileSet.Load(c.AcceptanceDir, c.RepoRoot);   // the row belongs to the file set; it reads NOT RUN with the set
            return AoFileSet.SmallMessage(new FrozenSide(), s);
        }
    }
}
