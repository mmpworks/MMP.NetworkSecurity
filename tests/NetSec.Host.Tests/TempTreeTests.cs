#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// TempTree.Delete waits out a short sharing lock and nothing else (#400). A file held open with FileShare.None inside the folder makes the
/// fault: a delete of the folder fails with ERROR_SHARING_VIOLATION until that handle closes, which is the error a short outside lock gave in #400.
/// </summary>
public class TempTreeTests
{
    static string NewFolder()
    {
        string dir = Path.Combine(Path.GetTempPath(), "netsec-temptree-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    static FileStream Hold(string dir) => new(Path.Combine(dir, "held.bin"), FileMode.Create, FileAccess.ReadWrite, FileShare.None);

    [Fact]
    public async Task A_lock_that_ends_inside_the_retry_window_is_waited_out()
    {
        string dir = NewFolder();
        FileStream held = Hold(dir);
        Task release = Task.Delay(500).ContinueWith(_ => held.Dispose());
        TempTree.Delete(dir);
        await release;
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public void A_lock_that_outlasts_the_attempts_raises_the_sharing_violation()
    {
        string dir = NewFolder();
        List<TimeSpan> pauses = new();
        TimeSpan pause = TimeSpan.FromMilliseconds(50);
        using (Hold(dir))
        {
            IOException caught = Assert.ThrowsAny<IOException>(() => TempTree.Delete(dir, 4, pause, pauses.Add));
            Assert.Equal(unchecked((int)0x80070020), caught.HResult);
            Assert.Equal(new[] { pause, pause, pause }, pauses);   // 4 attempts in all, so 3 pauses between them
        }
        TempTree.Delete(dir);
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public void A_free_folder_goes_on_the_first_try()
    {
        string dir = NewFolder();
        File.WriteAllText(Path.Combine(dir, "a.txt"), "a");
        List<TimeSpan> pauses = new();
        TempTree.Delete(dir, 4, TimeSpan.FromMilliseconds(50), pauses.Add);
        Assert.False(Directory.Exists(dir));
        Assert.Empty(pauses);
    }

    [Fact]
    public void An_error_other_than_a_sharing_violation_raises_at_once()
    {
        string dir = Path.Combine(Path.GetTempPath(), "netsec-temptree-missing-" + Guid.NewGuid().ToString("N"));
        List<TimeSpan> pauses = new();
        Assert.Throws<DirectoryNotFoundException>(() => TempTree.Delete(dir, 4, TimeSpan.FromMilliseconds(50), pauses.Add));
        Assert.Empty(pauses);
    }
}
