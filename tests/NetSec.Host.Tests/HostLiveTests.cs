using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>One Host process for the class, with its own session folder.</summary>
    public sealed class HostFixture : IDisposable
    {
        readonly Process _process;
        public readonly int Port;
        public readonly string Token = Guid.NewGuid().ToString("N");
        public readonly string AppData = Path.Combine(Path.GetTempPath(), "netsec-host-tests-" + Guid.NewGuid().ToString("N"));

        public HostFixture()
        {
            Directory.CreateDirectory(AppData);
            Port = FreePort();
            ProcessStartInfo info = new ProcessStartInfo("dotnet", "\"" + HostDll() + "\"") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            info.Environment["NETSEC_PORT"] = Port.ToString();
            info.Environment["NETSEC_TOKEN"] = Token;
            info.Environment["LOCALAPPDATA"] = AppData;
            TaskCompletionSource<string> ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            _process = new Process { StartInfo = info };
            _process.OutputDataReceived += (_, e) => { if (e.Data != null && e.Data.StartsWith("HOST-READY")) ready.TrySetResult(e.Data); };
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            if (!ready.Task.Wait(TimeSpan.FromSeconds(60)) || !ready.Task.Result.StartsWith("HOST-READY port=" + Port))
            {
                _process.Kill(entireProcessTree: true);
                throw new InvalidOperationException("the Host gave no ready line in 60 s");
            }
        }

        static string HostDll()
        {
            for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                string candidate = Path.Combine(dir.FullName, "src", "NetSec.Host", "bin", "Release", "net10.0", "NetSec.Host.dll");
                if (File.Exists(candidate)) return candidate;
            }
            throw new FileNotFoundException("NetSec.Host.dll is not built");
        }

        static int FreePort()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public void Dispose()
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(5000);
            _process.Dispose();
            Directory.Delete(AppData, recursive: true);
        }
    }

    public class HostLiveTests(HostFixture host) : IClassFixture<HostFixture>
    {
        const string Origin = "http://localhost:5173";

        sealed class Socket : IDisposable
        {
            readonly ClientWebSocket _ws = new ClientWebSocket();
            readonly CancellationTokenSource _limit = new CancellationTokenSource(TimeSpan.FromSeconds(40));

            public static async Task<Socket> Open(HostFixture host)
            {
                Socket s = new Socket();
                s._ws.Options.SetRequestHeader("Origin", Origin);
                await s._ws.ConnectAsync(new Uri($"ws://127.0.0.1:{host.Port}/ws?token={host.Token}"), s._limit.Token);
                return s;
            }

            public Task Send(string json) => _ws.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, _limit.Token);

            public async Task<JsonElement> Next()
            {
                byte[] buffer = new byte[1 << 16];
                using MemoryStream all = new MemoryStream();
                WebSocketReceiveResult r;
                do { r = await _ws.ReceiveAsync(buffer, _limit.Token); all.Write(buffer, 0, r.Count); } while (!r.EndOfMessage);
                return JsonDocument.Parse(all.ToArray()).RootElement.Clone();
            }

            /// <summary>Frames of one session, up to and including session.finished.</summary>
            public async Task<List<JsonElement>> UntilFinished(string sessionId)
            {
                List<JsonElement> frames = new List<JsonElement>();
                while (true)
                {
                    JsonElement f = await Next();
                    if (!f.TryGetProperty("sessionId", out JsonElement id) || id.GetString() != sessionId) continue;
                    frames.Add(f);
                    if (f.GetProperty("type").GetString() == "session.finished") return frames;
                }
            }

            public async Task<JsonElement> Until(string type)
            {
                while (true)
                {
                    JsonElement f = await Next();
                    if (f.GetProperty("type").GetString() == type) return f;
                }
            }

            public void Dispose() { _ws.Dispose(); _limit.Dispose(); }
        }

        static string[] TraceTypes(IEnumerable<JsonElement> frames) => frames
            .Where(f => f.GetProperty("type").GetString() == "trace")
            .Select(f => f.GetProperty("event").GetProperty("type").GetString())
            .ToArray();

        HttpRequestMessage Get(string path)
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{host.Port}{path}");
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
            request.Headers.TryAddWithoutValidation("Origin", Origin);
            return request;
        }

        async Task<JsonElement> GetJson(string path)
        {
            using HttpClient http = new HttpClient();
            HttpResponseMessage response = await http.SendAsync(Get(path));
            Assert.True(response.IsSuccessStatusCode, path + " got " + response.StatusCode);
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        }

        [Fact]
        public async Task Lesson_0_goes_live_with_started_first_and_finishes_completed()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":0,\"seed\":7,\"mode\":\"run\",\"transport\":\"glass\"}");
            JsonElement started = await s.Next();
            Assert.Equal("session.started", started.GetProperty("type").GetString());
            Assert.Equal("r1", started.GetProperty("requestId").GetString());
            Assert.True(started.GetProperty("trainingOnly").GetBoolean());
            Assert.Equal("glass", started.GetProperty("transportKind").GetString());
            string id = started.GetProperty("sessionId").GetString();

            List<JsonElement> frames = await s.UntilFinished(id);
            Assert.Equal("completed", frames.Last().GetProperty("outcome").GetString());
            JsonElement[] sent = frames.Where(f => f.GetProperty("type").GetString() == "trace" && f.GetProperty("event").GetProperty("type").GetString() == "wire.sent").Select(f => f.GetProperty("event")).ToArray();
            Assert.Contains(sent, e => e.GetProperty("actor").GetString() == "client" && e.GetProperty("to").GetString() == "server");
            Assert.Contains(sent, e => e.GetProperty("actor").GetString() == "server" && e.GetProperty("to").GetString() == "client");
            Assert.All(sent, e => Assert.True(e.GetProperty("seq").GetInt64() > 0 && e.GetProperty("seed").GetInt32() == 7));

            string file = started.GetProperty("sessionFile").GetString();
            Assert.StartsWith(host.AppData, file);
            Assert.True(File.ReadAllLines(file).Length >= sent.Length);

            JsonElement stored = await GetJson($"/api/sessions/{id}/events?after=2");
            Assert.True(stored.GetArrayLength() > 0);
            Assert.All(stored.EnumerateArray(), e => Assert.True(e.GetProperty("seq").GetInt64() > 2));
        }

        [Fact]
        public async Task Catalog_attack_forks_with_the_same_seed_and_names_the_check()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":0,\"seed\":11,\"mode\":\"run\"}");
            string parent = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            await s.UntilFinished(parent);

            await s.Send("{\"type\":\"session.attack\",\"requestId\":\"r2\",\"sessionId\":\"" + parent + "\",\"attackId\":\"L0-flip-wire-byte\"}");
            JsonElement started = await s.Until("session.started");
            Assert.Equal(11, started.GetProperty("seed").GetInt32());
            string fork = started.GetProperty("sessionId").GetString();
            List<JsonElement> frames = await s.UntilFinished(fork);
            Assert.Contains(frames, f => f.GetProperty("type").GetString() == "session.forked" && f.GetProperty("parentId").GetString() == parent);
            JsonElement finished = frames.Last();
            Assert.Equal("caught", finished.GetProperty("outcome").GetString());
            Assert.Equal("ECHO_MISMATCH", finished.GetProperty("code").GetString());
            Assert.Equal("echo compare", finished.GetProperty("check").GetString());
        }

        [Fact]
        public async Task A_flip_addressed_by_at_seq_hits_the_same_message_in_the_fork()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":0,\"seed\":12,\"mode\":\"run\"}");
            string parent = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            List<JsonElement> frames = await s.UntilFinished(parent);
            long atSeq = frames.First(f => f.GetProperty("type").GetString() == "trace"
                && f.GetProperty("event").GetProperty("type").GetString() == "wire.sent"
                && f.GetProperty("event").GetProperty("actor").GetString() == "client").GetProperty("seq").GetInt64();

            await s.Send("{\"type\":\"session.attack\",\"requestId\":\"r2\",\"sessionId\":\"" + parent + "\",\"atSeq\":" + atSeq + ",\"kind\":\"flip-byte\",\"offset\":3,\"xor\":1}");
            string fork = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            JsonElement finished = (await s.UntilFinished(fork)).Last();
            Assert.Equal("ECHO_MISMATCH", finished.GetProperty("code").GetString());
        }

        [Fact]
        public async Task Step_mode_holds_every_event_until_the_ui_steps()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":0,\"seed\":13,\"mode\":\"step\"}");
            string id = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            await Task.Delay(300);
            JsonElement none = await GetJson($"/api/sessions/{id}/events");
            Assert.Equal(0, none.GetArrayLength());

            await s.Send("{\"type\":\"session.step\",\"sessionId\":\"" + id + "\"}");
            await s.Until("trace");
            await s.Send("{\"type\":\"session.run\",\"sessionId\":\"" + id + "\"}");
            Assert.Equal("completed", (await s.UntilFinished(id)).Last().GetProperty("outcome").GetString());
        }

        [Fact]
        public async Task Unbuilt_lesson_and_real_mode_answer_by_code()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":5,\"mode\":\"run\"}");
            Assert.Equal("LESSON_NOT_BUILT", (await s.Until("error")).GetProperty("code").GetString());
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r2\",\"lesson\":0,\"mode\":\"run\",\"transport\":\"real\"}");
            Assert.Equal("REAL_MODE_NOT_BUILT", (await s.Until("error")).GetProperty("code").GetString());
        }

        [Fact]
        public async Task Lessons_list_holds_1_to_11_and_the_toy_sits_outside_it()
        {
            JsonElement rows = await GetJson("/api/lessons");
            Assert.Equal(Enumerable.Range(1, 11), rows.EnumerateArray().Select(r => r.GetProperty("lesson").GetInt32()));
            Assert.All(rows.EnumerateArray(), r => Assert.False(r.GetProperty("built").GetBoolean()));
            JsonElement toy = await GetJson("/api/lessons/0");
            Assert.True(toy.GetProperty("built").GetBoolean());
            Assert.Equal("L0-flip-wire-byte", toy.GetProperty("attacks")[0].GetProperty("attackId").GetString());
        }

        [Fact]
        public async Task Preflight_passes_on_origin_alone_and_refuses_a_foreign_origin()
        {
            using HttpClient http = new HttpClient();
            HttpRequestMessage good = new HttpRequestMessage(HttpMethod.Options, $"http://127.0.0.1:{host.Port}/api/health");
            good.Headers.TryAddWithoutValidation("Origin", Origin);
            HttpResponseMessage ok = await http.SendAsync(good);
            Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
            Assert.Equal(Origin, ok.Headers.GetValues("Access-Control-Allow-Origin").Single());
            HttpRequestMessage bad = new HttpRequestMessage(HttpMethod.Options, $"http://127.0.0.1:{host.Port}/api/health");
            bad.Headers.TryAddWithoutValidation("Origin", "http://evil.example");
            Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(bad)).StatusCode);
        }

        [Fact]
        public async Task Ce_start_runs_the_cf_exe_and_reports_its_proof_from_outside()
        {
            using HttpClient http = new HttpClient();
            HttpRequestMessage post = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{host.Port}/api/ce/start");
            post.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
            Assert.True((await http.SendAsync(post)).IsSuccessStatusCode);
            JsonElement status = default;
            for (int i = 0; i < 100; i++)
            {
                status = await GetJson("/api/ce");
                if (status.GetProperty("result").ValueKind == JsonValueKind.String) break;
                await Task.Delay(100);
            }
            Assert.Equal("CF-compiled, run on the desktop CLR, never run on CE", status.GetProperty("label").GetString());
            Assert.Equal("969db8053d3322ac", status.GetProperty("mscorlibToken").GetString());
            Assert.StartsWith("CE-READY pool=25/25", status.GetProperty("ready").GetString());
            Assert.Contains("\"ok\":true", status.GetProperty("result").GetString());
        }
    }
}
