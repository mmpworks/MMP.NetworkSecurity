#nullable enable
using System;
using System.IO;
using System.Threading;

namespace NetSec.Host.Tests;

/// <summary>RED STUB (#400): the final signature, with no retry yet.</summary>
static class TempTree
{
    public const int Attempts = 25;
    public static readonly TimeSpan Pause = TimeSpan.FromMilliseconds(200);

    public static void Delete(string dir) => Delete(dir, Attempts, Pause, Thread.Sleep);

    public static void Delete(string dir, int attempts, TimeSpan pause, Action<TimeSpan> sleep) => Directory.Delete(dir, recursive: true);
}
