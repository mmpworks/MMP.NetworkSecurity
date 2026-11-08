#nullable enable
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace NetSec.Host.Tests;

/// <summary>
/// How a test waits for a child process. Each wait is async, so it holds no thread-pool thread while it waits. A blocking wait inside a
/// running test or fixture can starve the pool, and then output events and Task.Run in other live tests start late and time out
/// (the class of red behind HostFlagTests, BridgeLiveTests and ShowKeysFlipOrderTests, 2026-11-07).
/// </summary>
internal static class ProcessWaits
{
    /// <summary>
    /// Bounds how many child processes start at once, from Start to their ready line. With no blocking waits, xunit runs more live tests at
    /// the same moment, and a burst of Host and openssl startups can make one miss its ready line. A start awaits a slot (it holds no thread
    /// while it waits), and gives the slot back once its ready line arrives or its limit passes. No start holds a slot while it starts
    /// another, so the gate cannot deadlock. The ready-line clock starts after the slot is taken.
    /// </summary>
    public static readonly SemaphoreSlim StartSlots = new(Math.Max(2, Environment.ProcessorCount / 2));

    /// <summary>
    /// Runs synchronous work, such as openssl runs inside a make step, on its own thread and returns when it ends. The work blocks that thread,
    /// never a pool thread. An exception from the work comes back through the task.
    /// </summary>
    public static Task<T> OnOwnThread<T>(Func<T> work)
    {
        TaskCompletionSource<T> done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Thread thread = new(() =>
        {
            try { done.SetResult(work()); }
            catch (Exception e) { done.SetException(e); }
        }) { IsBackground = true, Name = "test-blocking-work" };
        thread.Start();
        return done.Task;
    }

    /// <summary>
    /// The result of a ready-line promise, or a TimeoutException when the limit passes first. WaitAsync alone can time out on a promise that is
    /// already set: under pool starvation its timer callback and the queued completion race, and the timer can win. A ready line that arrived
    /// means the process did not hang, so a promise that holds its result at the timeout counts as on time.
    /// </summary>
    public static async Task<T> Within<T>(Task<T> ready, TimeSpan limit)
    {
        try { return await ready.WaitAsync(limit); }
        catch (TimeoutException) when (ready.IsCompletedSuccessfully) { return ready.Result; }
    }

    /// <summary>The same as Within&lt;T&gt;, for a promise with no result.</summary>
    public static async Task Within(Task ready, TimeSpan limit)
    {
        try { await ready.WaitAsync(limit); }
        catch (TimeoutException) when (ready.IsCompletedSuccessfully) { }
    }

    /// <summary>
    /// True when the process exits within the limit. WaitForExitAsync also waits for the end of redirected output, so every
    /// OutputDataReceived line has arrived when this returns true. Process.WaitForExit(timeout) gives no such promise.
    /// </summary>
    public static async Task<bool> ExitedWithin(Process process, TimeSpan limit)
    {
        using CancellationTokenSource stop = new(limit);
        try
        {
            await process.WaitForExitAsync(stop.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// The synchronous form, for a synchronous test or helper: no Task wait at all. Both pipes are read by event, so neither can fill and stall
    /// the process, and the limit runs from the start: a reader that waited for the end of standard output first would let a hung child, or a
    /// grandchild that holds the handle, run past the limit (Jared, #233). On exit the parameterless WaitForExit drains both streams.
    /// A process still running at the limit is killed with its tree, and Exited is false.
    /// </summary>
    public static (bool Exited, int Code, string Output, string Errors) ReadAll(Process process, TimeSpan limit)
    {
        System.Text.StringBuilder output = new(), errors = new();
        process.OutputDataReceived += (_, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (errors) errors.AppendLine(e.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        bool exited = process.WaitForExit((int)limit.TotalMilliseconds);
        if (exited) process.WaitForExit();
        else
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        }
        string o, e2;
        lock (output) o = output.ToString();
        lock (errors) e2 = errors.ToString();
        return (exited, exited ? process.ExitCode : -1, o, e2);
    }

    /// <summary>
    /// Reads standard output and standard error at once, so neither pipe can fill and stall the process, and waits for the exit.
    /// A process still running at the limit is killed with its tree, and Exited is false.
    /// </summary>
    public static async Task<(bool Exited, int Code, string Output, string Errors)> Collect(Process process, TimeSpan limit)
    {
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> errors = process.StandardError.ReadToEndAsync();
        bool exited = await ExitedWithin(process, limit);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        }
        string o = await output, e = await errors;
        return (exited, exited ? process.ExitCode : -1, o, e);
    }
}
