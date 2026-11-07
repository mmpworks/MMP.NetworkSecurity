using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The limits in ProcessWaits hold against a child that runs past them, and the output of a child that ends in time is whole.</summary>
[Collection(BlockingProductCalls.Name)]
public class ProcessWaitsTests
{
    // ping -n 11 runs about 10 s, which is longer than every limit below.
    static Process LongChild() => Process.Start(new ProcessStartInfo("ping", "-n 11 127.0.0.1") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;

    static Process EchoBoth() => Process.Start(new ProcessStartInfo("cmd", "/c echo to-out & echo to-err 1>&2") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;

    [Fact]
    public void ReadAll_stops_at_its_limit_while_the_child_still_writes()
    {
        using Process p = LongChild();
        Stopwatch clock = Stopwatch.StartNew();
        (bool exited, _, _, _) = ProcessWaits.ReadAll(p, TimeSpan.FromSeconds(1));
        clock.Stop();
        Assert.False(exited, "ReadAll reported an exit for a child that runs about 10 s");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), "ReadAll took " + clock.Elapsed.TotalSeconds.ToString("0.0") + " s with a 1 s limit");
        Assert.True(p.WaitForExit(5000), "ReadAll did not kill the child at its limit");
    }

    [Fact]
    public void ReadAll_returns_both_streams_of_a_child_that_ends_in_time()
    {
        using Process p = EchoBoth();
        (bool exited, int code, string output, string errors) = ProcessWaits.ReadAll(p, TimeSpan.FromSeconds(30));
        Assert.True(exited);
        Assert.Equal(0, code);
        Assert.Contains("to-out", output);
        Assert.Contains("to-err", errors);
    }

    [Fact]
    public async Task Collect_stops_at_its_limit_and_kills_the_child()
    {
        using Process p = LongChild();
        Stopwatch clock = Stopwatch.StartNew();
        (bool exited, _, _, _) = await ProcessWaits.Collect(p, TimeSpan.FromSeconds(1));
        clock.Stop();
        Assert.False(exited);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), "Collect took " + clock.Elapsed.TotalSeconds.ToString("0.0") + " s with a 1 s limit");
        Assert.True(p.HasExited || p.WaitForExit(5000), "Collect did not kill the child at its limit");
    }
}
