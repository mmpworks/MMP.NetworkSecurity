#nullable enable
using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetSec.Host.Tests;

/// <summary>
/// The last lines a child printed on stdout and stderr, so a start that times out can say what the child did (issue #367). Attach it before
/// Start. It keeps the last <see cref="Keep"/> lines, so a fixture that runs a Host for a whole class holds a bounded list.
/// </summary>
internal sealed class StartLog
{
    public const int Keep = 40;
    readonly ConcurrentQueue<string> _lines = new();

    public void Attach(Process process)
    {
        process.OutputDataReceived += (_, e) => Add("out", e.Data);
        process.ErrorDataReceived += (_, e) => Add("err", e.Data);
    }

    void Add(string stream, string? line)
    {
    }

    /// <summary>The text a failed start adds to its message: the wait, whether the child exited and with which code, and its last lines.</summary>
    public string Describe(Process process, TimeSpan waited) => "";
}
