namespace Acceptance
{
    /// <summary>AO-9 pool-25 (PRD 3.3): in this process, because the pool cap of 25 holds for the whole process.</summary>
    public static class AoPool9
    {
        [Clause("AO-9.pool-25", PerBuild = true, TimeoutSec = 900)]
        public static string Pool25(Ctx c)
        {
            AoSide s = AoSubject.Make(c);
            var files = AoFileSet.Load(c.AcceptanceDir, c.RepoRoot);
            string pool = AoThreads.CapPool();
            return AoFileSet.Pool25(new FrozenSide(), s, files) + " (" + pool + ")";
        }
    }
}
