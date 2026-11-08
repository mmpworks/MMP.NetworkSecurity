using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// L7-decrypt-recording on a live Host (docs/sections-plan.md, slice P4b). It runs on the session's own keys, so it goes through the session
/// and the Show keys path, never the open schedule walk. With Show keys OFF, on a learner's own tls11.server key, the recovered line shows
/// and no recovered key byte does.
/// </summary>
public class DecryptRecordingLiveTests
{
    static async Task<JsonElement> Until(ClientWebSocket ws, List<JsonElement> frames, Func<JsonElement, bool> stop, CancellationToken limit)
    {
        while (true)
        {
            byte[] buffer = new byte[1 << 16];
            using MemoryStream all = new();
            WebSocketReceiveResult r;
            do { r = await ws.ReceiveAsync(buffer, limit); all.Write(buffer, 0, r.Count); } while (!r.EndOfMessage);
            JsonElement frame = JsonDocument.Parse(all.ToArray()).RootElement.Clone();
            frames.Add(frame);
            if (stop(frame)) return frame;
        }
    }

    static Task Send(ClientWebSocket ws, string json, CancellationToken limit) =>
        ws.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, limit);

    static bool Is(JsonElement f, string type) => f.GetProperty("type").GetString() == type;

    [Fact]
    public async Task With_Show_keys_off_on_a_learner_key_the_line_shows_and_no_key_byte_does()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        await host.MakeFlow("my-certificates");
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        using ClientWebSocket ws = new();
        using CancellationTokenSource limit = new(TimeSpan.FromSeconds(60));
        await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{host.Port}/ws?token={host.Token}"), limit.Token);
        List<JsonElement> frames = [];
        await Send(ws, "{\"type\":\"session.start\",\"requestId\":\"p\",\"lesson\":7,\"seed\":3,\"mode\":\"run\"}", limit.Token);
        string parent = (await Until(ws, frames, f => Is(f, "session.started"), limit.Token)).GetProperty("sessionId").GetString()!;
        await Until(ws, frames, f => Is(f, "session.finished") && f.GetProperty("sessionId").GetString() == parent, limit.Token);

        frames.Clear();
        await Send(ws, "{\"type\":\"session.attack\",\"requestId\":\"a\",\"sessionId\":\"" + parent + "\",\"attackId\":\"L7-decrypt-recording\"}", limit.Token);
        string fork = (await Until(ws, frames, f => Is(f, "session.started"), limit.Token)).GetProperty("sessionId").GetString()!;
        JsonElement finished = await Until(ws, frames, f => Is(f, "session.finished") && f.GetProperty("sessionId").GetString() == fork, limit.Token);

        Assert.Equal("caught", finished.GetProperty("outcome").GetString());
        Assert.Equal("TLS11_NO_STORED_KEY", finished.GetProperty("code").GetString());
        Assert.Equal("forward secrecy", finished.GetProperty("check").GetString());

        JsonElement opened = frames.Where(f => Is(f, "trace")).Select(f => f.GetProperty("event"))
            .Single(e => e.GetProperty("type").GetString() == "attack.recording.opened");
        Assert.Equal(Convert.ToHexString(Encoding.UTF8.GetBytes("hello from the old world\n")), opened.GetProperty("plain").GetString(), ignoreCase: true);
        JsonElement[] secrets = opened.GetProperty("secrets").EnumerateArray().ToArray();
        Assert.Equal(4, secrets.Length);
        Assert.All(secrets, s =>
        {
            Assert.False(s.TryGetProperty("hex", out _), s.GetProperty("name").GetString() + " carries hex with Show keys off");
            Assert.StartsWith("fp:", s.GetProperty("fingerprint").GetString());
        });
    }
}
