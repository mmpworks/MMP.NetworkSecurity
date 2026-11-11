#nullable enable
using System;
using System.IO;
using System.Threading;

namespace NetSec.TestSupport;

/// <summary>
/// Deletes a test's temp folder and waits out a short outside hold on it (#400). A process outside the test can open or write files in a new
/// temp git repo for a short time; in #400 a run found <c>.git/gk/config</c> with a <c>gk-last-accessed</c> line, written about 0.3 s after
/// the test made the repo. A delete in that window fails with ERROR_SHARING_VIOLATION (a file is open) or ERROR_DIR_NOT_EMPTY (a file came
/// in during the delete). Only those two run the delete again, after a pause, up to <see cref="Attempts"/> runs in all. Any other error raises
/// at once, and the last retried error raises too, so a handle the test itself leaks still fails the test. Both test projects compile this one
/// file (a linked Compile item), on net10.0 and net48.
/// </summary>
internal static class TempTree
{
    // HRESULT_FROM_WIN32 of each code, the HResult that .NET gives the IOException.
    const int SharingViolation = unchecked((int)0x80070020);   // ERROR_SHARING_VIOLATION = 32
    const int DirNotEmpty = unchecked((int)0x80070091);   // ERROR_DIR_NOT_EMPTY = 145
    public const int Attempts = 25;
    public static readonly TimeSpan Pause = TimeSpan.FromMilliseconds(200);   // 25 runs, 24 pauses: a hold longer than about 5 s still fails

    public static void Delete(string dir) => Delete(dir, Attempts, Pause, Thread.Sleep);

    public static void Delete(string dir, int attempts, TimeSpan pause, Action<TimeSpan> sleep) =>
        Delete(dir, attempts, pause, sleep, d => Directory.Delete(d, recursive: true));

    /// <summary>The retry loop with the delete as a seam, so a test can give it an error that a real file system shows only by chance (#406).</summary>
    internal static void Delete(string dir, int attempts, TimeSpan pause, Action<TimeSpan> sleep, Action<string> delete)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                delete(dir);
                return;
            }
            catch (DirectoryNotFoundException) when (attempt > 1) { return; }   // An earlier run removed the folder before its error
            catch (IOException e) when (IsHeld(e) && attempt < attempts) { sleep(pause); }
        }
    }

    static bool IsHeld(IOException e) => e.HResult == SharingViolation || e.HResult == DirNotEmpty;
}
