#nullable enable
using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>A real Host with its own security folder. A bad key must stop only the lessons that read it, and always by name.</summary>
public class SecurityLiveTests
{
    internal sealed class Host : IDisposable
    {
        readonly Process _process;
        readonly HttpClient _http = new();
        public readonly string Root = Path.Combine(Path.GetTempPath(), "netsec-live-" + Guid.NewGuid().ToString("N"));
        public readonly string Token = Guid.NewGuid().ToString("N");
        public readonly int Port;
        public string SecurityDir => Path.Combine(Root, "security");

        readonly TaskCompletionSource<bool> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Starts a Host and waits for its ready line without holding a pool thread (ProcessWaits).</summary>
        public static async Task<Host> StartAsync(Dictionary<string, string>? env = null)
        {
            await ProcessWaits.StartSlots.WaitAsync();
            try
            {
                Host host = new(env);
                try { await ProcessWaits.Within(host._ready.Task, TimeSpan.FromSeconds(60)); }
                catch (TimeoutException)
                {
                    host.Dispose();
                    Assert.Fail("the Host gave no ready line in 60 s");
                }
                return host;
            }
            finally { ProcessWaits.StartSlots.Release(); }
        }

        Host(Dictionary<string, string>? env)
        {
            Directory.CreateDirectory(Root);
            TcpListener free = new(IPAddress.Loopback, 0);
            free.Start();
            Port = ((IPEndPoint)free.LocalEndpoint).Port;
            free.Stop();
            ProcessStartInfo info = new("dotnet", "\"" + HostFixture.HostDll() + "\"") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            info.Environment["NETSEC_PORT"] = Port.ToString();
            info.Environment["NETSEC_TOKEN"] = Token;
            info.Environment["LOCALAPPDATA"] = Root;
            info.Environment["NETSEC_SECURITY_DIR"] = SecurityDir;
            foreach (KeyValuePair<string, string> pair in env ?? []) info.Environment[pair.Key] = pair.Value;
            _process = new Process { StartInfo = info };
            _process.OutputDataReceived += (_, e) => { if (e.Data != null && e.Data.StartsWith("HOST-READY")) _ready.TrySetResult(true); };
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            _http.DefaultRequestHeaders.Add("Authorization", "Bearer " + Token);
        }

        public async Task<(int Status, string Body)> Get(string path)
        {
            HttpResponseMessage r = await _http.GetAsync("http://127.0.0.1:" + Port + path);
            return ((int)r.StatusCode, await r.Content.ReadAsStringAsync());
        }

        public async Task<(int Status, string Body)> Put(string path, string json)
        {
            HttpResponseMessage r = await _http.PutAsync("http://127.0.0.1:" + Port + path, new StringContent(json, Encoding.UTF8, "application/json"));
            return ((int)r.StatusCode, await r.Content.ReadAsStringAsync());
        }

        async Task<(int Status, string Body)> Post(string path, string json)
        {
            HttpResponseMessage r = await _http.PostAsync("http://127.0.0.1:" + Port + path, new StringContent(json, Encoding.UTF8, "application/json"));
            return ((int)r.StatusCode, await r.Content.ReadAsStringAsync());
        }

        /// <summary>Walks a flow to its check and returns the check step's reply, which is what reaches the screen.</summary>
        public async Task<string> CheckReply(string flowId)
        {
            string run = JsonDocument.Parse((await Post("/api/security/flows/" + flowId + "/runs", "{}")).Body).RootElement.GetProperty("runId").GetString()!;
            int seq = 1;
            string last = "";
            foreach (string ev in new[] { "next", "make", "next", "check" })
            {
                (int status, string body) = await Post("/api/security/runs/" + run + "/events", JsonSerializer.Serialize(new { @event = ev, stepSeq = seq++, data = new { } }));
                Assert.True(status == 200, ev + " got " + status + ": " + body);
                last = body;
            }
            return last;
        }

        public async Task MakeFlow(string flowId)
        {
            string run = JsonDocument.Parse((await Post("/api/security/flows/" + flowId + "/runs", "{}")).Body).RootElement.GetProperty("runId").GetString()!;
            int seq = 1;
            foreach (string ev in new[] { "next", "make", "next", "check", "next" })
            {
                (int status, string body) = await Post("/api/security/runs/" + run + "/events", JsonSerializer.Serialize(new { @event = ev, stepSeq = seq++, data = new { } }));
                Assert.True(status == 200, ev + " got " + status + ": " + body);
                Assert.Empty(JsonDocument.Parse(body).RootElement.GetProperty("step").GetProperty("errors").EnumerateArray());
            }
        }

        /// <summary>session.start, then every frame up to the session's end or its error. Returns the frames.</summary>
        public async Task<List<JsonElement>> Session(int lesson, string transport = "glass")
        {
            using ClientWebSocket ws = new();
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(30));
            await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{Port}/ws?token={Token}"), limit.Token);
            await ws.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"session.start\",\"requestId\":\"r\",\"lesson\":" + lesson + ",\"seed\":3,\"mode\":\"run\",\"transport\":\"" + transport + "\"}"), WebSocketMessageType.Text, true, limit.Token);
            List<JsonElement> frames = [];
            while (true)
            {
                byte[] buffer = new byte[1 << 16];
                using MemoryStream all = new();
                WebSocketReceiveResult r;
                do { r = await ws.ReceiveAsync(buffer, limit.Token); all.Write(buffer, 0, r.Count); } while (!r.EndOfMessage);
                JsonElement frame = JsonDocument.Parse(all.ToArray()).RootElement.Clone();
                frames.Add(frame);
                string? type = frame.GetProperty("type").GetString();
                if (type is "session.finished" or "error") return frames;
            }
        }

        public void Dispose()
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(5000);
            _process.Dispose();
            _http.Dispose();
            Directory.Delete(Root, true);
        }
    }

    static string Last(List<JsonElement> frames) => frames[^1].GetProperty("type").GetString()!;

    [Fact]
    public async Task A_broken_key_stops_only_the_lessons_that_read_it_and_by_name()
    {
        using Host host = await Host.StartAsync();
        await host.MakeFlow("my-login");
        // The my-login keys live in the vault (slice V1), so a person with the file breaks one by changing its wrapped row.
        using (Microsoft.Data.Sqlite.SqliteConnection db = new("Data Source=" + Path.Combine(host.SecurityDir, "vault", "vault.db") + ";Pooling=False"))
        {
            db.Open();
            using Microsoft.Data.Sqlite.SqliteCommand q = db.CreateCommand();
            q.CommandText = "UPDATE key_versions SET wrapped = zeroblob(length(wrapped)) WHERE name = 'token.issuer'";
            Assert.Equal(1, q.ExecuteNonQuery());
        }

        Assert.Equal("session.finished", Last(await host.Session(0)));
        Assert.Equal("session.finished", Last(await host.Session(4)));

        List<JsonElement> refused = await host.Session(10);
        Assert.Equal("error", Last(refused));
        Assert.Equal("VAULT_UNWRAP_FAILED", refused[^1].GetProperty("code").GetString());
        Assert.Contains("token.issuer", refused[^1].GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_key_route_on_a_broken_key_answers_by_name()
    {
        using Host host = await Host.StartAsync();
        await host.MakeFlow("my-certificates");
        File.WriteAllText(Path.Combine(host.SecurityDir, "files", "tls13.server", "v1", "key.pem"), "this is no key");
        (int status, string body) = await host.Get("/api/security/types/tls13.server/key");
        Assert.True(status is >= 400 and < 500, status + ": " + body);
        Assert.Equal("KEY_FILE_FORMAT", JsonDocument.Parse(body).RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_key_broken_after_the_flow_stops_its_own_flow_step_by_name_and_not_with_a_server_error()
    {
        using Host host = await Host.StartAsync();
        await host.MakeFlow("my-certificates");
        File.WriteAllText(Path.Combine(host.SecurityDir, "files", "tls13.server", "v1", "key.pem"), "this is no key");
        (int status, string body) = await host.Get("/api/security");
        Assert.Equal(200, status);
        Assert.Contains("Broken", body);
    }
    /// <summary>The Check step reaches the screen with Show keys off, and OpenSSL takes the key on its command line. So the reply shows a mark in its place, and it still shows who judged.</summary>
    [Fact]
    public async Task The_lesson_key_check_shows_no_key_in_its_command()
    {
        using Host host = await Host.StartAsync();
        string reply = await host.CheckReply("my-lesson-keys");
        JsonElement[] facts = JsonDocument.Parse(reply).RootElement.GetProperty("step").GetProperty("facts").EnumerateArray().ToArray();
        Assert.Equal(2, facts.Length);
        Assert.All(facts, f =>
        {
            Assert.True(f.GetProperty("passed").GetBoolean(), f.ToString());
            Assert.Equal("openssl", f.GetProperty("judge").GetString());
            Assert.Contains("<key>", f.GetProperty("command").GetString());
        });
        foreach (string typeId in new[] { "lab.aes-key", "lab.seal-key" })
        {
            (int status, string body) = await host.Get($"/api/security/types/{typeId}/key");
            Assert.Equal(200, status);
            string hex = JsonDocument.Parse(body).RootElement.GetProperty("hex").GetString()!;
            Assert.Equal(32, hex.Length);
            Assert.DoesNotContain(hex, reply, StringComparison.OrdinalIgnoreCase);
        }
    }
}
