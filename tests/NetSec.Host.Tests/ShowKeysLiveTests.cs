#nullable enable
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

/// <summary>The Show keys toggle at the Host's trace boundary (modes-design.md section 6): frames, /events, files, the key log, save, replay, key.in-use.</summary>
public sealed class ShowKeysLiveTests
{
    /// <summary>A socket that sends commands and waits for one frame by type.</summary>
    sealed class Ws(SecurityLiveTests.Host host) : IDisposable
    {
        readonly ClientWebSocket _ws = new();
        readonly CancellationTokenSource _limit = new(TimeSpan.FromSeconds(30));
        public readonly List<JsonElement> Frames = [];

        public async Task Open() => await _ws.ConnectAsync(new Uri($"ws://127.0.0.1:{host.Port}/ws?token={host.Token}"), _limit.Token);

        public Task Send(object command) => _ws.SendAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(command)), WebSocketMessageType.Text, true, _limit.Token);

        public async Task<JsonElement> Until(string type)
        {
            while (true)
            {
                byte[] buffer = new byte[1 << 16];
                using MemoryStream all = new();
                WebSocketReceiveResult r;
                do { r = await _ws.ReceiveAsync(buffer, _limit.Token); all.Write(buffer, 0, r.Count); } while (!r.EndOfMessage);
                JsonElement frame = JsonDocument.Parse(all.ToArray()).RootElement.Clone();
                Frames.Add(frame);
                if (frame.GetProperty("type").GetString() == type) return frame;
            }
        }

        public void Dispose() { _ws.Dispose(); _limit.Dispose(); }
    }

    static IEnumerable<JsonElement> SecretsIn(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty p in node.EnumerateObject())
            {
                if (p.Name == "secrets" && p.Value.ValueKind == JsonValueKind.Array) foreach (JsonElement s in p.Value.EnumerateArray()) yield return s;
                foreach (JsonElement s in SecretsIn(p.Value)) yield return s;
            }
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (JsonElement v in node.EnumerateArray()) foreach (JsonElement s in SecretsIn(v)) yield return s;
    }

    static List<JsonElement> SecretsOfText(string text) =>
        text.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith('{') || l.StartsWith('['))
            .SelectMany(l => SecretsIn(JsonDocument.Parse(l).RootElement.Clone())).ToList();

    static int WithHex(IEnumerable<JsonElement> secrets) => secrets.Count(s => s.TryGetProperty("hex", out _));

    static Task SetShowKeys(SecurityLiveTests.Host host, bool on) => host.Put("/api/security/show-keys", "{\"on\":" + (on ? "true" : "false") + "}");

    static string StartedId(List<JsonElement> frames) => frames.First(f => f.GetProperty("type").GetString() == "session.started").GetProperty("sessionId").GetString()!;
    static string StartedFile(List<JsonElement> frames) => frames.First(f => f.GetProperty("type").GetString() == "session.started").GetProperty("sessionFile").GetString()!;

    [Fact]
    public async Task An_off_session_holds_no_hex_in_frames_events_or_its_file()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        await SetShowKeys(host, false);
        List<JsonElement> frames = await host.Session(1);
        List<JsonElement> secrets = frames.SelectMany(SecretsIn).ToList();
        Assert.NotEmpty(secrets);
        Assert.Equal(0, WithHex(secrets));
        Assert.All(secrets, s =>
        {
            Assert.StartsWith("fp:", s.GetProperty("fingerprint").GetString());
            Assert.True(s.GetProperty("length").GetInt32() > 0);
            Assert.False(string.IsNullOrEmpty(s.GetProperty("hidden").GetString()));
        });
        Assert.Equal(0, WithHex(SecretsOfText((await host.Get("/api/sessions/" + StartedId(frames) + "/events")).Body)));
        Assert.Equal(0, WithHex(SecretsOfText(File.ReadAllText(StartedFile(frames)))));
    }

    [Fact]
    public async Task A_flip_redacts_an_open_session_and_the_flip_back_restores_it()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        List<JsonElement> frames = await host.Session(1);
        string events = "/api/sessions/" + StartedId(frames) + "/events";
        int shown = WithHex(SecretsOfText((await host.Get(events)).Body));
        Assert.True(shown > 0, "control: an ON session shows no hex");
        await SetShowKeys(host, false);
        Assert.Equal(0, WithHex(SecretsOfText((await host.Get(events)).Body)));
        await SetShowKeys(host, true);
        Assert.Equal(shown, WithHex(SecretsOfText((await host.Get(events)).Body)));
    }

    [Fact]
    public async Task The_flip_is_broadcast_to_the_socket()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        using Ws ws = new(host);
        await ws.Open();
        Task<JsonElement> seen = ws.Until("security.show-keys");
        await SetShowKeys(host, false);
        JsonElement frame = await seen;
        Assert.False(frame.GetProperty("on").GetBoolean());
    }

    static Task<(int Status, string Body)> PutShowKeys(SecurityLiveTests.Host host, bool on) =>
        host.Put("/api/security/show-keys", on ? "{\"on\":true}" : "{\"on\":false}");

    static async Task<bool> ShowKeysNow(SecurityLiveTests.Host host) =>
        JsonDocument.Parse((await host.Get("/api/security/show-keys")).Body).RootElement.GetProperty("on").GetBoolean();

    /// <summary>
    /// Off fails closed (issue #292): with modes.json held, turning Show keys off still hides keys at once and tells every socket. The
    /// named refusal says only that the choice was not saved for the next start.
    /// </summary>
    [Fact]
    public async Task Turning_show_keys_off_while_the_settings_file_is_held_still_hides_keys_and_tells_the_sockets()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        Assert.Equal(200, (await PutShowKeys(host, true)).Status);
        using Ws ws = new(host);
        await ws.Open();
        Task<JsonElement> seen = ws.Until("security.show-keys");
        (int Status, string Body) refused;
        using (SecurityLiveTests.HoldModesOpen(host)) refused = await PutShowKeys(host, false);
        SecurityLiveTests.AssertSaveRefused(refused.Status, refused.Body);
        Assert.False((await seen).GetProperty("on").GetBoolean(), "the sockets hear off");
        Assert.False(await ShowKeysNow(host), "keys stop showing although the save failed");
    }

    /// <summary>
    /// Every Show keys reader sees off right after a refused save (issue #292, Jared's check 4): the key route, the session's key log and
    /// the AES walk route. They all ask the store live, so this pins that no reader keeps its own copy.
    /// </summary>
    [Fact]
    public async Task Every_show_keys_reader_sees_off_right_after_a_refused_save()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        Assert.Equal(200, (await PutShowKeys(host, true)).Status);
        string id = StartedId(await host.Session(1));
        Assert.Equal(200, (await host.Get("/api/sessions/" + id + "/keylog")).Status);
        using (SecurityLiveTests.HoldModesOpen(host))
        {
            (int status, string body) = await PutShowKeys(host, false);
            SecurityLiveTests.AssertSaveRefused(status, body);
            JsonElement key = JsonDocument.Parse((await host.Get("/api/security/types/tls13.server/key")).Body).RootElement;
            Assert.Equal("toggle", key.GetProperty("hidden").GetString());
            Assert.Equal("KEYS_HIDDEN", JsonDocument.Parse((await host.Get("/api/sessions/" + id + "/keylog")).Body).RootElement.GetProperty("code").GetString());
            (int walkStatus, string walk) = await host.Get("/api/sessions/" + id + "/walk/aes/block?source=text&keyBits=128");
            Assert.Equal(409, walkStatus);
            Assert.Equal("KEYS_HIDDEN", JsonDocument.Parse(walk).RootElement.GetProperty("code").GetString());
        }
    }

    /// <summary>
    /// The restart gap (issue #292): after a refused off, memory says off and the file says on. The Host says "not saved" to the page and
    /// the key route hides keys at once; when the hold ends, a background retry saves the file and tells the sockets.
    /// </summary>
    [Fact]
    public async Task A_refused_show_keys_off_is_marked_not_saved_until_the_retry_saves_it()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        Assert.Equal(200, (await PutShowKeys(host, true)).Status);
        using Ws ws = new(host);
        await ws.Open();
        Task<JsonElement> flip = ws.Until("security.show-keys");
        using (SecurityLiveTests.HoldModesOpen(host))
        {
            (int status, string body) = await PutShowKeys(host, false);
            SecurityLiveTests.AssertSaveRefused(status, body);
            JsonElement frame = await flip;
            Assert.False(frame.GetProperty("saved").GetBoolean(), "the flip frame says the choice is not saved yet");
            JsonElement now = JsonDocument.Parse((await host.Get("/api/security/show-keys")).Body).RootElement;
            Assert.False(now.GetProperty("on").GetBoolean());
            Assert.False(now.GetProperty("saved").GetBoolean());
            JsonElement key = JsonDocument.Parse((await host.Get("/api/security/types/tls13.server/key")).Body).RootElement;
            Assert.Equal("toggle", key.GetProperty("hidden").GetString());
        }
        JsonElement healed = await ws.Until("security.saved");
        Assert.True(healed.GetProperty("saved").GetBoolean());
        Assert.True(JsonDocument.Parse((await host.Get("/api/security/show-keys")).Body).RootElement.GetProperty("saved").GetBoolean());
    }

    /// <summary>On may fail open (issue #292): with modes.json held, turning Show keys on is refused by name, and keys stay hidden.</summary>
    [Fact]
    public async Task Turning_show_keys_on_while_the_settings_file_is_held_is_refused_and_keys_stay_hidden()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        Assert.Equal(200, (await PutShowKeys(host, false)).Status);
        (int Status, string Body) refused;
        using (SecurityLiveTests.HoldModesOpen(host)) refused = await PutShowKeys(host, true);
        SecurityLiveTests.AssertSaveRefused(refused.Status, refused.Body);
        Assert.False(await ShowKeysNow(host));
    }

    [Fact]
    public async Task The_key_log_is_refused_while_off()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        string id = StartedId(await host.Session(1));
        Assert.Equal(200, (await host.Get("/api/sessions/" + id + "/keylog")).Status);
        await SetShowKeys(host, false);
        (int status, string body) = await host.Get("/api/sessions/" + id + "/keylog");
        Assert.Equal(409, status);
        Assert.Equal("KEYS_HIDDEN", JsonDocument.Parse(body).RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Key_in_use_names_the_type_version_and_provider_on_the_keys_stream()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        await host.MakeFlow("my-login");
        string keyHex = JsonDocument.Parse((await host.Get("/api/security/types/token.issuer/key")).Body).RootElement.GetProperty("hex").GetString()!;
        List<JsonElement> frames = await host.Session(10);
        string id = StartedId(frames);
        List<JsonElement> uses = frames.Where(f => f.GetProperty("type").GetString() == "trace").Select(f => f.GetProperty("event"))
            .Where(e => e.GetProperty("type").GetString() == "key.in-use").ToList();
        JsonElement issuer = uses.Single(e => e.GetProperty("typeId").GetString() == "token.issuer");
        Assert.Equal(id + "/keys", issuer.GetProperty("streamId").GetString());
        Assert.Equal("vault", issuer.GetProperty("provider").GetString());
        Assert.True(issuer.GetProperty("version").GetInt32() >= 1);
        JsonElement secret = issuer.GetProperty("secrets").EnumerateArray().Single();
        Assert.Equal("token.issuer", secret.GetProperty("name").GetString());
        Assert.Equal(keyHex, secret.GetProperty("hex").GetString(), ignoreCase: true);
        // A built-in key the lab reads names provider builtin, version 0, and shows its bytes.
        JsonElement root = uses.Single(e => e.GetProperty("typeId").GetString() == "pki.root-ca");
        Assert.Equal("builtin", root.GetProperty("provider").GetString());
        Assert.Equal(0, root.GetProperty("version").GetInt32());
        Assert.Equal(1, WithHex(root.GetProperty("secrets").EnumerateArray()));
        // Every type lesson 10 reads has its event.
        Assert.Equal(6, uses.Count);
    }

    [Fact]
    public async Task Save_while_off_returns_a_redacted_copy_and_replay_names_it()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        List<JsonElement> frames = await host.Session(1);
        string id = StartedId(frames), file = StartedFile(frames);
        Assert.True(WithHex(SecretsOfText(File.ReadAllText(file))) > 0, "control: the ON file holds no hex");
        await SetShowKeys(host, false);

        using Ws ws = new(host);
        await ws.Open();
        await ws.Send(new { type = "session.save", requestId = "s", sessionId = id });
        string copy = (await ws.Until("session.saved")).GetProperty("sessionFile").GetString()!;
        Assert.NotEqual(file, copy);
        Assert.Equal(0, WithHex(SecretsOfText(File.ReadAllText(copy))));
        Assert.True(WithHex(SecretsOfText(File.ReadAllText(file))) > 0, "OFF must not rewrite a file written ON");

        // Saved ON, replayed OFF: fingerprints reach the frames.
        await ws.Send(new { type = "session.load", requestId = "l1", file = Path.GetFileName(file) });
        await ws.Until("session.finished");
        Assert.Equal(0, WithHex(ws.Frames.SelectMany(SecretsIn)));

        // Saved OFF, replayed ON: still fingerprints, and session.started says the file hides its keys.
        await SetShowKeys(host, true);
        ws.Frames.Clear();
        await ws.Send(new { type = "session.load", requestId = "l2", file = Path.GetFileName(copy) });
        JsonElement started = await ws.Until("session.started");
        Assert.True(started.GetProperty("fileHidesKeys").GetBoolean());
        await ws.Until("session.finished");
        Assert.Equal(0, WithHex(ws.Frames.SelectMany(SecretsIn)));
    }

    /// <summary>
    /// The same class as PR #140, in session.load: a replay must pick each line by the toggle as it is when the line goes out.
    /// A file of 3,000 padded lines keeps the replay running while the flip lands. 3,000 frames stay under the socket queue
    /// of 4,096, so no frame drops and the order the socket sees is the order the Host sent.
    /// The flip is a separate HTTP call, so on a busy machine it can land after the replay ends. Then the run proves nothing:
    /// the test reads until both the flip frame and session.finished arrive, and tries again with longer lines, which make
    /// the replay slower. It fails, never passes, when no try puts the flip inside the replay.
    /// </summary>
    [Fact]
    public async Task A_replay_sends_no_hex_after_a_flip_to_off_that_lands_while_it_runs()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        string source = StartedFile(await host.Session(1));
        // Trace lines only: a session file ends with its trace.catch line, which a replay sends as its own frame, not as a trace.
        string[] lines = File.ReadAllLines(source).Where(l => l.Length > 0 && !l.StartsWith(LabSession.CatchLinePrefix, StringComparison.Ordinal)).ToArray();
        Assert.True(WithHex(SecretsOfText(string.Join("\n", lines))) > 0, "control: the ON file holds no hex");
        string big = Path.Combine(Path.GetDirectoryName(source)!, "replay-race.ndjson");
        var misses = new List<string>();

        foreach (int padSize in new[] { 16_000, 32_000, 48_000 })
        {
            await SetShowKeys(host, true);
            string pad = new('a', padSize);
            File.WriteAllLines(big, Enumerable.Range(0, 3000).Select(i => lines[i % lines.Length][..^1] + ",\"pad\":\"" + pad + "\"}"));
            using Ws ws = new(host);
            await ws.Open();
            await ws.Send(new { type = "session.load", requestId = "race", file = Path.GetFileName(big) });
            await ws.Until("session.started");
            await SetShowKeys(host, false);
            await ws.Until("session.finished");
            int finished = ws.Frames.Count - 1;
            int off = ws.Frames.FindIndex(f => f.GetProperty("type").GetString() == "security.show-keys");
            if (off < 0) { await ws.Until("security.show-keys"); off = ws.Frames.Count - 1; }

            int before = ws.Frames.Take(off).Count(f => f.GetProperty("type").GetString() == "trace");
            if (off > finished || before == 0 || before >= 3000)
            {
                misses.Add("pad " + padSize + ": the flip landed after " + before + " of 3000 trace frames" + (off > finished ? ", after session.finished" : ""));
                continue;
            }

            int traces = ws.Frames.Count(f => f.GetProperty("type").GetString() == "trace");
            Assert.True(traces == 3000, "the socket got " + traces + " of 3000 trace frames, so the order check would not hold");
            int late = WithHex(ws.Frames.Skip(off + 1).SelectMany(SecretsIn));
            Assert.True(late == 0, late + " secrets with hex reached the socket after the flip to OFF, out of " + ws.Frames.Skip(off + 1).Count(f => f.GetProperty("type").GetString() == "trace") + " trace frames after it");
            return;
        }
        Assert.Fail("no try put the flip inside the replay, so the test proves nothing: " + string.Join("; ", misses));
    }
}
