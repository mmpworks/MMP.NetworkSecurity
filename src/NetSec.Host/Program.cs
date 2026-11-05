using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetSec.Errors;
using NetSec.Host;
using NetSec.Labs;
using NetSec.Trace;

// Binds 127.0.0.1 only. NETSEC_PORT overrides the port. NETSEC_TOKEN is the session token: Electron makes one and passes it here
// and to the renderer. LOCALAPPDATA moves the session folder. docs/program-design.md section 5 is the contract.
int port = int.TryParse(Environment.GetEnvironmentVariable("NETSEC_PORT"), out int p) ? p : 5180;
string? givenToken = Environment.GetEnvironmentVariable("NETSEC_TOKEN");
string token = string.IsNullOrEmpty(givenToken) ? Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)) : givenToken;
string appData = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? Path.GetTempPath();
string sessionsDir = Path.Combine(appData, "MMP.NetworkSecurity", "sessions");

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
builder.Logging.SetMinimumLevel(LogLevel.Warning);

WebApplication app = builder.Build();
SessionManager sessions = new(sessionsDir);
CeProcess ce = new();
HostGuard guard = new(token);
LessonRows lessons = new();

app.Use(guard.Invoke);
app.UseWebSockets();

app.MapGet("/api/health", () => Results.Json(new
{
    schema = TraceEvent.CurrentSchema,
    build = typeof(TraceEvent).Assembly.GetName().Version?.ToString(),
    referees = Array.Empty<string>(),
    droppedEvents = sessions.DroppedEvents,
}));
app.MapGet("/api/lessons", () => Results.Json(lessons.All()));
// GEM:server-replaces-never-merges: on reconnect the UI replaces its copy of a session from this list.
app.MapGet("/api/sessions/{id}/events", (string id, long? after) =>
    sessions.Find(id) is { } s
        ? Results.Content("[" + string.Join(",", s.After(after ?? 0).Select(e => e.Line)) + "]", "application/json")
        : NoSuchSession(id));
app.MapGet("/api/sessions/{id}/keylog", (string id) =>
    sessions.Find(id) is not null ? Results.Text("", "text/plain") : NoSuchSession(id));
app.MapGet("/api/ce", () => Results.Json(ce.Status()));
app.MapPost("/api/ce/start", async () => Results.Json(await ce.StartAsync()));
app.MapPost("/api/ce/stop", () => { ce.Stop(); return Results.Json(ce.Status()); });

app.Map("/ws", async ctx =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using WebSocket socket = await ctx.WebSockets.AcceptWebSocketAsync();
    await new HostSocket(socket, sessions).ServeAsync(ctx.RequestAborted);
});

app.Lifetime.ApplicationStopping.Register(ce.Stop);
app.Lifetime.ApplicationStarted.Register(() => Console.WriteLine(
    $"HOST-READY port={port}" + (string.IsNullOrEmpty(givenToken) ? $" token={token}" : "")));
app.Run();

static IResult NoSuchSession(string id) => Results.Json(
    new { code = "SESSION_NOT_FOUND", message = $"No session {id}.", retryable = false, requestId = Guid.NewGuid().ToString("N") },
    statusCode: 404);

namespace NetSec.Host
{
    public sealed class LessonRows
    {
        static readonly string[] Titles =
        [
            "A pipe with two ends",
            "Secrets and locks", "Tamper seals", "Agreeing on a secret in public", "Who are you",
            "TLS 1.3 message by message", "Key per sale", "The old world", "SSH", "The bridge",
            "Client proof and permission", "Unmanaged space",
        ];

        readonly Dictionary<int, JsonElement> _lastRuns = ReadLastRuns();

        /// <summary>built comes from the lab catalog. lastRun comes from docs/_runs/lessons.json when the file exists.</summary>
        public object[] All() => Enumerable.Range(0, Titles.Length).Select(n => (object)new
        {
            lesson = n,
            title = Titles[n],
            labId = LabCatalog.Find(n)?.LabId,
            lanes = n == 9 ? new[] { "ce", "gateway", "server" } : n == 6 ? new[] { "reader", "bank" } : new[] { "client", "server" },
            attacks = AttackCatalog.All.Where(a => a.Lesson == n).Select(a => new { attackId = a.AttackId, kind = a.Kind, expectCode = a.ExpectCode, expectCheck = a.ExpectCheck }),
            built = LabCatalog.Find(n) is not null,
            lastRun = _lastRuns.TryGetValue(n, out JsonElement run) ? run : (JsonElement?)null,
        }).ToArray();

        static Dictionary<int, JsonElement> ReadLastRuns()
        {
            Dictionary<int, JsonElement> runs = [];
            for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                string path = Path.Combine(dir.FullName, "docs", "_runs", "lessons.json");
                if (!File.Exists(path)) continue;
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
                foreach (JsonElement row in doc.RootElement.GetProperty("lessons").EnumerateArray())
                    runs[row.GetProperty("lesson").GetInt32()] = row.Clone();
                break;
            }
            return runs;
        }
    }

    /// <summary>One WebSocket: commands in, frames out. Frames carry the sessionId, so a reconnected socket keeps the live stream.</summary>
    public sealed class HostSocket(WebSocket socket, SessionManager sessions)
    {
        LabSession? _current;

        public async Task ServeAsync(CancellationToken ct)
        {
            var reader = sessions.Connect(out var client);
            Task sender = SendLoop(reader, ct);
            try
            {
                while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    string? text = await ReceiveText(ct);
                    if (text is null) break;
                    Handle(text);
                }
            }
            catch (OperationCanceledException) { }
            catch (WebSocketException) { }
            finally
            {
                sessions.Disconnect(client);
                await sender;
            }
        }

        async Task SendLoop(System.Threading.Channels.ChannelReader<string> reader, CancellationToken ct)
        {
            try
            {
                await foreach (string frame in reader.ReadAllAsync(ct))
                    await socket.SendAsync(Encoding.UTF8.GetBytes(frame), WebSocketMessageType.Text, true, ct);
            }
            catch (OperationCanceledException) { }
            catch (WebSocketException) { }
        }

        async Task<string?> ReceiveText(CancellationToken ct)
        {
            byte[] buffer = new byte[8192];
            using MemoryStream message = new();
            while (true)
            {
                WebSocketReceiveResult result = await socket.ReceiveAsync(buffer, ct);
                if (result.MessageType == WebSocketMessageType.Close) return null;
                message.Write(buffer, 0, result.Count);
                if (result.EndOfMessage) return Encoding.UTF8.GetString(message.ToArray());
            }
        }

        void Handle(string text)
        {
            string? requestId = null;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(text);
                JsonElement m = doc.RootElement;
                requestId = Text(m, "requestId");
                switch (Text(m, "type"))
                {
                    case "session.start": Start(m, requestId); break;
                    case "session.step": Stepper(m)?.Step(); break;
                    case "session.run": Stepper(m)?.Run(); break;
                    case "session.pause": Stepper(m)?.Pause(); break;
                    case "session.attack": Attack(m, requestId); break;
                    case "session.save": Save(m, requestId); break;
                    case "session.load": Load(m, requestId); break;
                    default: Fail(requestId, "COMMAND_UNKNOWN", $"Unknown command {Text(m, "type")}."); break;
                }
            }
            catch (JsonException e) { Fail(requestId, "COMMAND_NOT_JSON", e.Message); }
        }

        void Start(JsonElement m, string? requestId)
        {
            if (Text(m, "transport") == "real")
            {
                Fail(requestId, ErrorCodes.RealModeNotBuilt, "Real mode is not built yet.");
                return;
            }
            int lesson = Number(m, "lesson", -1);
            int seed = Number(m, "seed", RandomSeed());
            Begin(lesson, seed, Text(m, "mode") ?? "run", null, null, requestId);
        }

        void Attack(JsonElement m, string? requestId)
        {
            LabSession? parent = Text(m, "sessionId") is { } id ? sessions.Find(id) : _current;
            if (parent is null) { Fail(requestId, "SESSION_NOT_FOUND", "No session to fork."); return; }
            string forkId = SessionManager.NewId();
            AttackDefinition? attack = Text(m, "attackId") is { } attackId
                ? AttackCatalog.All.FirstOrDefault(a => a.AttackId == attackId)
                : FreeAttack(m, parent, forkId);
            if (attack is null) { Fail(requestId, "ATTACK_NOT_FOUND", "No such attack, or that byte cannot be flipped."); return; }
            LabSession? fork = Begin(parent.Lesson, parent.Seed, Text(m, "mode") ?? "run", attack, forkId, requestId);
            if (fork is not null)
                Send(new { type = "session.forked", requestId, sessionId = fork.SessionId, parentId = parent.SessionId, attackId = attack.AttackId });
        }

        static AttackDefinition? FreeAttack(JsonElement m, LabSession parent, string forkId)
        {
            string kind = Text(m, "kind") ?? "flip-byte";
            if (kind != "flip-byte") return null;
            TamperPlan? plan = parent.PlanFor(Number(m, "atSeq", -1), forkId, Number(m, "offset", 0), Number(m, "xor", 1));
            return plan is null ? null : new AttackDefinition { AttackId = "free-flip-byte", Lesson = parent.Lesson, Kind = kind, Plan = plan };
        }

        LabSession? Begin(int lesson, int seed, string mode, AttackDefinition? attack, string? sessionId, string? requestId)
        {
            LabSession? session = sessions.Start(lesson, seed, mode, attack, sessionId, started =>
            {
                _current = started;
                Send(new
                {
                    type = "session.started",
                    requestId,
                    sessionId = started.SessionId,
                    seed,
                    transportKind = "glass",
                    trainingOnly = true,
                    sessionFile = started.SessionFile,
                });
            }, out NetSecError? error);
            if (session is null) Fail(requestId, error!.Code, error.Message);
            return session;
        }

        void Save(JsonElement m, string? requestId)
        {
            LabSession? session = Text(m, "sessionId") is { } id ? sessions.Find(id) : _current;
            if (session is null) { Fail(requestId, "SESSION_NOT_FOUND", "No session to save."); return; }
            Send(new { type = "session.saved", requestId, sessionId = session.SessionId, sessionFile = session.SessionFile });
        }

        void Load(JsonElement m, string? requestId)
        {
            string? name = Text(m, "file");
            string root = Path.GetFullPath(sessions.SessionsDir);
            string? path = name is null ? null : Path.GetFullPath(Path.Combine(root, name));
            if (path is null || !path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
            {
                Fail(requestId, "SESSION_FILE_NOT_FOUND", "That saved trace is not in the session folder.");
                return;
            }
            string sessionId = SessionManager.NewId();
            Send(new { type = "session.started", requestId, sessionId, replay = true, sessionFile = path });
            long seq = 0;
            foreach (string line in File.ReadLines(path))
                sessions.Broadcast($"{{\"type\":\"trace\",\"sessionId\":{JsonSerializer.Serialize(sessionId)},\"seq\":{++seq},\"event\":{line}}}");
            Send(new { type = "session.finished", sessionId, outcome = "replay", code = (string?)null, check = (string?)null });
        }

        NetSec.Io.StepGate? Stepper(JsonElement m)
        {
            LabSession? session = Text(m, "sessionId") is { } id ? sessions.Find(id) : _current;
            return session?.Gate as NetSec.Io.StepGate;
        }

        void Fail(string? requestId, string code, string message) =>
            Send(new { type = "error", requestId, code, message, retryable = false });

        void Send(object frame) => sessions.Broadcast(JsonSerializer.Serialize(frame));

        static string? Text(JsonElement m, string name) =>
            m.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        static int Number(JsonElement m, string name, int fallback) =>
            m.TryGetProperty(name, out JsonElement v) && v.TryGetInt32(out int n) ? n : fallback;

        static int RandomSeed() => RandomNumberGenerator.GetInt32(1, int.MaxValue);
    }
}
