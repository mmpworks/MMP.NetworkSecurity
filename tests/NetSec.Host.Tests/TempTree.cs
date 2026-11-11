#nullable enable
using System;
using System.IO;
using System.Threading;

namespace NetSec.Host.Tests;

/// <summary>
/// Deletes a test's temp folder and waits out a short sharing lock (#400). A process outside the test (cause unverified in #400) can hold a
/// handle in a new temp folder for a short time, and a delete in that window fails with ERROR_SHARING_VIOLATION. Only that error runs the
/// delete again, after a pause, up to <see cref="Attempts"/> runs in all. Any other error raises at once, and the last sharing violation raises
/// too, so a handle the test itself leaks still fails the test.
/// </summary>
static class TempTree
{
    const int SharingViolation = unchecked((int)0x80070020);   // HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION), the HResult .NET gives that IOException
    public const int Attempts = 25;
    public static readonly TimeSpan Pause = TimeSpan.FromMilliseconds(200);   // 25 runs, 24 pauses: a lock longer than about 5 s still fails

    public static void Delete(string dir) => Delete(dir, Attempts, Pause, Thread.Sleep);

    public static void Delete(string dir, int attempts, TimeSpan pause, Action<TimeSpan> sleep)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                Directory.Delete(dir, recursive: true);
                return;
            }
            catch (DirectoryNotFoundException) when (attempt > 1) { return; }   // An earlier run removed the folder before its error
            catch (IOException e) when (e.HResult == SharingViolation && attempt < attempts) { sleep(pause); }
        }
    }
}
