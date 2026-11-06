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
                flip = Task.Run(() => { Volatile.Write(ref on, 0); manager.Broadcast(OffFrame); });
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
}
