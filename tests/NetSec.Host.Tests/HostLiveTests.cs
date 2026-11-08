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
    /// <summary>
    /// One Host process for the class, with its own session folder. It starts in InitializeAsync, which awaits the ready line, so building the
    /// fixture holds no thread-pool thread (ProcessWaits explains why that matters).
    /// </summary>
    public sealed class HostFixture : IAsyncLifetime
    {
        Process _process;
        public readonly int Port = FreePort();
        public readonly string Token = Guid.NewGuid().ToString("N");
        public readonly string AppData = Path.Combine(Path.GetTempPath(), "netsec-host-tests-" + Guid.NewGuid().ToString("N"));

        public async Task InitializeAsync()
        {
            await ProcessWaits.StartSlots.WaitAsync();
            try { await StartAsync(); }
            finally { ProcessWaits.StartSlots.Release(); }
        }

        async Task StartAsync()
        {
            Directory.CreateDirectory(AppData);
            ProcessStartInfo info = new ProcessStartInfo("dotnet", "\"" + HostDll() + "\"") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            info.Environment["NETSEC_PORT"] = Port.ToString();
            info.Environment["NETSEC_TOKEN"] = Token;
            info.Environment["LOCALAPPDATA"] = AppData;
            info.Environment["NETSEC_SECURITY_DIR"] = Path.Combine(AppData, "security");      // Never the learner's own .security/ folder
            TaskCompletionSource<string> ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            _process = new Process { StartInfo = info };
            _process.OutputDataReceived += (_, e) => { if (e.Data != null && e.Data.StartsWith("HOST-READY")) ready.TrySetResult(e.Data); };
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            string line = null;
            try { line = await ready.Task.WaitAsync(TimeSpan.FromSeconds(60)); }
            catch (TimeoutException) { }
            if (line == null || !line.StartsWith("HOST-READY port=" + Port))
            {
                _process.Kill(entireProcessTree: true);
                throw new InvalidOperationException("the Host gave no ready line in 60 s");
            }
        }

        public static string HostDll()
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

        public async Task DisposeAsync()
        {
            if (_process != null)
            {
                try { _process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                await ProcessWaits.ExitedWithin(_process, TimeSpan.FromSeconds(5));
                _process.Dispose();
            }
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

        async Task<string> FinishedLessonOne(int seed)
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":1,\"seed\":" + seed + ",\"mode\":\"run\",\"transport\":\"glass\"}");
            string id = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            await s.UntilFinished(id);
            return id;
        }

        /// <summary>Design section 2.7: a size the run did not use walks a practice key from the session seed, and the reply says so.</summary>
        [Fact]
        public async Task The_walk_at_192_bits_runs_a_practice_key_and_says_so()
        {
            string id = await FinishedLessonOne(7);
            JsonElement run = await GetJson($"/api/sessions/{id}/walk/aes/block?source=text&keyBits=128");
            JsonElement practice = await GetJson($"/api/sessions/{id}/walk/aes/block?source=text&keyBits=192");
            Assert.Equal("run", run.GetProperty("keySource").GetString());
            Assert.Equal("practice", practice.GetProperty("keySource").GetString());
            byte[] drawn = new byte[24];
            new NetSec.Platform.SeededRandom(7 ^ 192).Fill(drawn, 0, drawn.Length);
            Assert.Equal(Convert.ToHexString(drawn, 0, 4).ToLowerInvariant(), practice.GetProperty("keyWords")[0].GetProperty("word").GetString());
            Assert.Equal(12, practice.GetProperty("rounds").GetInt32());
            Assert.Equal(52, practice.GetProperty("keyWords").GetArrayLength());
            Assert.Equal("notSent", practice.GetProperty("wire").GetProperty("status").GetString());
            Assert.Equal(run.GetProperty("inputHex").GetString(), practice.GetProperty("inputHex").GetString());
            Assert.NotEqual(run.GetProperty("keyWords")[0].GetProperty("word").GetString(), practice.GetProperty("keyWords")[0].GetProperty("word").GetString());
            Assert.Equal(practice.GetProperty("inputHex").GetString(), practice.GetProperty("inverse").GetProperty("output").GetString());
            JsonElement again = await GetJson($"/api/sessions/{id}/walk/aes/block?source=text&keyBits=192");
            Assert.Equal(practice.GetProperty("forward").GetProperty("output").GetString(), again.GetProperty("forward").GetProperty("output").GetString());
        }

        [Theory]
        [InlineData("source=ecb&block=0", 409, "WALK_NOT_BUILT")]
        [InlineData("source=gcm&block=0", 409, "WALK_NOT_BUILT")]
        [InlineData("source=text", 400, "WALK_BAD_ARGUMENT")]
        [InlineData("keyBits=128", 400, "WALK_BAD_ARGUMENT")]
        [InlineData("source=text&keyBits=abc", 400, "WALK_BAD_ARGUMENT")]
        public async Task A_block_query_the_walk_cannot_answer_says_why(string query, int status, string code)
        {
            string id = await FinishedLessonOne(7);
            using HttpClient http = new HttpClient();
            HttpResponseMessage response = await http.SendAsync(Get($"/api/sessions/{id}/walk/aes/block?{query}"));
            Assert.Equal(status, (int)response.StatusCode);
            JsonElement body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal(code, body.GetProperty("code").GetString());
            Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? "");
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
        public async Task Lesson_11_loads_the_native_library_in_the_host_and_finishes_with_measured_numbers()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":11,\"seed\":7,\"mode\":\"run\",\"transport\":\"glass\"}");
            JsonElement started = await s.Next();
            Assert.Equal("session.started", started.GetProperty("type").GetString());
            List<JsonElement> frames = await s.UntilFinished(started.GetProperty("sessionId").GetString());
            Assert.Equal("completed", frames.Last().GetProperty("outcome").GetString());
            string[] types = frames.Where(f => f.GetProperty("type").GetString() == "trace").Select(f => f.GetProperty("event").GetProperty("type").GetString()).ToArray();
            Assert.Equal(4, types.Count(t => t == "timing.samples"));
            Assert.Contains("timing.verdict", types);
            Assert.Contains("timing.managed", types);
            Assert.Equal(2, types.Count(t => t == "timing.guess.finished"));
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

        /// <summary>The contract's order is started, forked, then the fork's own frames. Lesson 0 can finish in the time the Host takes to send a frame, so one try proves little.</summary>
        [Fact]
        public async Task A_fork_says_forked_before_it_finishes_every_time()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":0,\"seed\":11,\"mode\":\"run\"}");
            string parent = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            await s.UntilFinished(parent);

            for (int i = 0; i < 40; i++)
            {
                await s.Send("{\"type\":\"session.attack\",\"requestId\":\"a" + i + "\",\"sessionId\":\"" + parent + "\",\"attackId\":\"L0-flip-wire-byte\"}");
                string fork = (await s.Until("session.started")).GetProperty("sessionId").GetString();
                List<JsonElement> frames = await s.UntilFinished(fork);
                Assert.Equal("session.forked", frames[0].GetProperty("type").GetString());
                parent = fork;      // The Host keeps the last 20 sessions, so the next attack forks this one.
            }
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
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":99,\"mode\":\"run\"}");
            Assert.Equal("LESSON_NOT_BUILT", (await s.Until("error")).GetProperty("code").GetString());
            // Lessons leave this list as they release, so the test asks the Host which ones are still unbuilt.
            JsonElement rows = await GetJson("/api/lessons");
            foreach (JsonElement row in rows.EnumerateArray().Where(r => !r.GetProperty("built").GetBoolean()))
            {
                await s.Send("{\"type\":\"session.start\",\"requestId\":\"r3\",\"lesson\":" + row.GetProperty("lesson").GetInt32() + ",\"mode\":\"run\"}");
                Assert.Equal("LESSON_NOT_BUILT", (await s.Until("error")).GetProperty("code").GetString());
            }
            // Lesson 0 has no OS path.
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r2\",\"lesson\":0,\"mode\":\"run\",\"transport\":\"os\"}");
            Assert.Equal("OS_TRANSPORT_NOT_BUILT", (await s.Until("error")).GetProperty("code").GetString());
            // "real" was the old name. It is refused by name, so an old caller never runs a glass session in silence.
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r4\",\"lesson\":5,\"mode\":\"run\",\"transport\":\"real\"}");
            JsonElement unknown = await s.Until("error");
            Assert.Equal("TRANSPORT_UNKNOWN", unknown.GetProperty("code").GetString());
            Assert.Contains("os", unknown.GetProperty("message").GetString());
        }

        /// <summary>A lab can do slow work before its first event. A step sent right after session.started must still release that event, with no resend.</summary>
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        public async Task A_step_right_after_session_started_releases_the_first_event(int lesson)
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":" + lesson + ",\"seed\":7,\"mode\":\"step\"}");
            JsonElement started = await s.Until("session.started");
            string id = started.GetProperty("sessionId").GetString();
            await s.Send("{\"type\":\"session.step\",\"sessionId\":\"" + id + "\"}");
            await s.Until("trace").WaitAsync(TimeSpan.FromSeconds(20));
            await s.Send("{\"type\":\"session.run\",\"sessionId\":\"" + id + "\"}");
            await s.UntilFinished(id);
        }

        [Fact]
        public async Task Lesson_10_runs_through_the_host_to_the_end_with_its_rows_listed()
        {
            using Socket s = await Socket.Open(host);
            await s.Send("{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":10,\"seed\":13,\"mode\":\"run\"}");
            string id = (await s.Until("session.started")).GetProperty("sessionId").GetString();
            Assert.Equal("completed", (await s.UntilFinished(id)).Last().GetProperty("outcome").GetString());
            JsonElement row = await GetJson("/api/lessons/10");
            Assert.True(row.GetProperty("built").GetBoolean());
            Assert.Equal(13, row.GetProperty("attacks").GetArrayLength());
        }

        [Fact]
        public async Task Lessons_list_holds_1_to_11_and_the_toy_sits_outside_it()
        {
            JsonElement rows = await GetJson("/api/lessons");
            Assert.Equal(Enumerable.Range(1, 11), rows.EnumerateArray().Select(r => r.GetProperty("lesson").GetInt32()));
            int[] built = rows.EnumerateArray().Where(r => r.GetProperty("built").GetBoolean()).Select(r => r.GetProperty("lesson").GetInt32()).ToArray();
            foreach (int lesson in new[] { 1, 2, 3, 4, 5, 10, 11 }) Assert.Contains(lesson, built);
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
