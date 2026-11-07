using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using NetSec.Keys;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// Jared's should-fix on PR #136. A trace line picked while Show keys is ON must reach the socket ahead of the flip to OFF.
/// The UI reloads from /events when the flip frame arrives, so a shown line after it would put key bytes on an OFF screen.
/// </summary>
public class ShowKeysFlipOrderTests
{
    const string OffFrame = "{\"type\":\"security.show-keys\",\"on\":false}";

    /// <summary>
    /// Runs the flip on its own thread, never a pool thread. The toggle read that starts it holds the fence's read lock and waits up to 500 ms
    /// for it, so a flip queued to a busy pool could start late and fail "the flip did not finish" for no fault of the Host (ProcessWaits).
    /// </summary>
    static Task StartFlip(Action flipNow)
    {
        TaskCompletionSource done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Thread thread = new(() => { flipNow(); done.SetResult(); }) { IsBackground = true, Name = "show-keys-flip" };
        thread.Start();
        return done.Task;
    }

    [Fact]
    public async Task A_line_picked_before_a_flip_to_off_reaches_the_socket_ahead_of_the_flip_frame()
    {
        string dir = Path.Combine(Path.GetTempPath(), "netsec-flip-" + Guid.NewGuid().ToString("N"));
        int on = 1;
        Task flip = null;
        SessionManager manager = null;

        // The flip lands on another thread between the read of the toggle and the send of the line it picked.
        // The wait is bounded, so a Host that orders the two cannot deadlock here: it waits 500 ms and goes on.
        bool ShowKeys()
        {
            bool now = Volatile.Read(ref on) == 1;
            if (flip == null && now)
            {
                flip = StartFlip(() => { Volatile.Write(ref on, 0); manager.Broadcast(OffFrame); });
                flip.Wait(500);
            }
            return now;
        }

        manager = new SessionManager(dir, ShowKeys);
        try
        {
            ChannelReader<string> socket = manager.Connect(out _);
            LabSession session = manager.Start(10, 7, "run", null, null, CredentialSet.BuiltIn(new TrainingKeySource()), _ => { }, out var error);
            Assert.True(session != null, error?.ToString());
            Assert.True(flip != null, "the session never read the toggle");
            Assert.True(await Task.WhenAny(flip, Task.Delay(10_000)) == flip, "the flip did not finish");
            for (int i = 0; i < 600 && !session.Finished; i++) await Task.Delay(100);
            Assert.True(session.Finished, "lesson 10 did not finish in 60 s");

            List<string> frames = [];
            while (socket.TryRead(out string frame)) frames.Add(frame);
            int off = frames.IndexOf(OffFrame);
            Assert.True(off >= 0, "the socket never got the flip frame");
            string late = frames.Skip(off + 1).FirstOrDefault(f => f.Contains("\"hex\":", StringComparison.Ordinal));
            Assert.True(late == null, "a line with key bytes reached the socket after the flip to OFF: " + late?[..Math.Min(160, late.Length)]);
            Assert.True(frames.Take(off).Any(f => f.Contains("\"hex\":", StringComparison.Ordinal)), "no shown line went out before the flip, so the test proves nothing");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Jared's should-fix 2 on PR #141. session.save reads the toggle to pick the original file or a hidden copy.
    /// A flip to OFF that lands between that read and the session.saved frame must not leave a saved frame naming a file with key bytes after the flip frame.
    /// </summary>
    [Fact]
    public async Task A_save_picked_before_a_flip_to_off_reaches_the_socket_ahead_of_the_flip_frame()
    {
        string dir = Path.Combine(Path.GetTempPath(), "netsec-save-" + Guid.NewGuid().ToString("N"));
        int on = 1, armed = 0;
        Task flip = null;
        SessionManager manager = null;

        // Armed only for the save, so the lab's own lines go out ON. The wait is bounded, as in the test above.
        bool ShowKeys()
        {
            bool now = Volatile.Read(ref on) == 1;
            if (Volatile.Read(ref armed) == 1 && flip == null && now)
            {
                flip = StartFlip(() => { Volatile.Write(ref on, 0); manager.Broadcast(OffFrame); });
                flip.Wait(500);
            }
            return now;
        }

        manager = new SessionManager(dir, ShowKeys);
        try
        {
            ChannelReader<string> socket = manager.Connect(out _);
            LabSession session = manager.Start(1, 7, "run", null, null, CredentialSet.BuiltIn(new TrainingKeySource()), _ => { }, out var error);
            Assert.True(session != null, error?.ToString());
            for (int i = 0; i < 600 && !session.Finished; i++) await Task.Delay(100);
            Assert.True(session.Finished, "lesson 1 did not finish in 60 s");
            Assert.True(session.FileHoldsShownKeys, "control: the ON session file holds no shown key");

            Volatile.Write(ref armed, 1);
            manager.Save(session, file => "{\"type\":\"session.saved\",\"sessionFile\":" + System.Text.Json.JsonSerializer.Serialize(file) + "}");
            Assert.True(flip != null, "the save never read the toggle");
            Assert.True(await Task.WhenAny(flip, Task.Delay(10_000)) == flip, "the flip did not finish");

            List<string> frames = [];
            while (socket.TryRead(out string frame)) frames.Add(frame);
            int off = frames.IndexOf(OffFrame);
            int saved = frames.FindIndex(f => f.StartsWith("{\"type\":\"session.saved\"", StringComparison.Ordinal));
            Assert.True(off >= 0 && saved >= 0, "the socket is missing the flip frame or the saved frame");
            if (saved > off)
            {
                string named = System.Text.Json.JsonDocument.Parse(frames[saved]).RootElement.GetProperty("sessionFile").GetString();
                Assert.True(!File.ReadAllText(named).Contains("\"hex\":", StringComparison.Ordinal), "the saved frame came after the flip to OFF and names a file with key bytes: " + Path.GetFileName(named));
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
