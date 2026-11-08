using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// Test classes whose blocking waits sit in the code they test, not in the test: SqliteVault.Write retries with Thread.Sleep,
/// SshExeCheck.RunSsh waits on a process, and AsyncProxy futures offer only a blocking Wait. xunit runs a synchronous test on a pool thread,
/// so these classes run alone, after the parallel classes, and never hold pool threads while live tests start Hosts.
/// A dotnet-trace of a full run on 2026-11-07 found these, with the secret-guard runs, holding about 40 s of pool-thread time in 25 s.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class BlockingProductCalls
{
    public const string Name = "Blocking product calls";
}
