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
using NetSec.Labs;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// The kill condition of docs/logical-clock-plan.md, against a real Host. One seed, many runs per case: every engine-stream event carries a
/// clock, and the clocks are the same in every run. A run with a catch is compared on the events before the catch plus the catch, for the 8
/// forks whose tails vary; every other case is compared whole. NETSEC_CLOCK_RUNS=1 (under tools/heavy_lock.py) gives 20 runs per case, the
/// second half beside a CPU burner on every core; the shared suite gives 2 idle runs.
/// </summary>
public sealed class LogicalClockRunTests
{
    static readonly bool KillRuns = Environment.GetEnvironmentVariable("NETSEC_CLOCK_RUNS") == "1";
    static int Runs => KillRuns ? 20 : 2;

    /// <summary>The 8 caught forks whose stream tails vary between runs (the plan's survey). They are compared up to the catch.</summary>
    static readonly HashSet<string> VaryingTails =
    [
        "L1-flip-gcm", "L2-flip-hash-message", "L2-flip-hmac-message", "L2-flip-hmac-tag",
        "L2-extend-hmac", "L7-downgrade", "L3-swap-server-share", "L3-flip-mlkem-ciphertext",
    ];

    /// <summary>The plan's 9 cases, then every caught fork not already named.</summary>
    public static IEnumerable<object?[]> Cases()
    {
        List<(int Lesson, string? Attack)> named =
        [
            (1, null), (7, null), (9, null), (10, null), (11, null),
            (7, "L7-decrypt-recording"), (6, "L6-replay-sale"), (5, "L5-clear-close-notify"), (5, "L5-flip-record-length"),
        ];
        foreach ((int lesson, string? attack) in named) yield return [lesson, attack];
        foreach (AttackDefinition a in AttackCatalog.All.Where(a => a.Expect == AttackOutcome.Rejected && !named.Any(n => n.Attack == a.AttackId)))
            yield return [a.Lesson, a.AttackId];
    }

    /// <summary>Every lesson and every attack fork, one run each: every engine event has a clock, no link is ambiguous, and one trace.catch frame comes.</summary>
    public static IEnumerable<object?[]> EveryRun()
    {
        for (int lesson = 0; lesson <= 11; lesson++) yield return [lesson, null];
        foreach (AttackDefinition a in AttackCatalog.All) yield return [a.Lesson, a.AttackId];
    }

    sealed record Ev(string Stream, long StreamSeq, string Type, string Message, long? Clock, bool Unmatched)
    {
        public string Id => Stream + "#" + StreamSeq;
        public string Key => $"{Id} {Type} {Message} clock={(Clock?.ToString() ?? "none")}{(Unmatched ? " unmatched" : "")}";
    }

    sealed record Run(List<Ev> Engine, string? CatchId, HashSet<string> AfterCatch, int CatchFrames, List<string> Ambiguous);

    static string Str(JsonElement e, string name) => e.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    /// <summary>A stream id without its first segment (the session or trace id), so two runs name a stream the same way.</summary>
    static string Local(string id) => id.Split('/', 2).ElementAtOrDefault(1) ?? id;

    /// <summary>An engine stream is &lt;actor&gt;/&lt;connection&gt; after the prefix; wire streams and one-segment streams (keys) are not.</summary>
    static bool IsEngine(string local) => local.Contains('/') && !local.EndsWith("/wire", StringComparison.Ordinal);

    static Run Read(List<JsonElement> frames)
    {
        List<Ev> engine = [];
        foreach (JsonElement f in frames.Where(f => Str(f, "type") == "trace"))
        {
            JsonElement e = f.GetProperty("event");
            string local = Local(Str(e, "streamId"));
            if (!IsEngine(local)) continue;
            long? clock = e.TryGetProperty("clock", out JsonElement c) && c.ValueKind == JsonValueKind.Number ? c.GetInt64() : null;
            bool unmatched = e.TryGetProperty("unmatched", out JsonElement u) && u.ValueKind == JsonValueKind.True;
            engine.Add(new Ev(local, e.GetProperty("streamSeq").GetInt64(), Str(e, "type"), Str(e, "message"), clock, unmatched));
        }
        JsonElement[] catches = frames.Where(f => Str(f, "type") == "trace.catch").ToArray();
        string? catchId = null;
        HashSet<string> after = [];
        if (catches.Length > 0)
        {
            JsonElement k = catches[^1];
            catchId = k.TryGetProperty("catchEventId", out JsonElement id) && id.ValueKind == JsonValueKind.String ? Local(id.GetString()!) : null;
            if (k.TryGetProperty("afterCatch", out JsonElement list) && list.ValueKind == JsonValueKind.Array)
                foreach (JsonElement x in list.EnumerateArray()) after.Add(Local(x.GetString()!));
        }
        List<string> ambiguous = frames.Where(f => Str(f, "type") == "clock.link-ambiguous").Select(f => f.GetRawText()).ToList();
        return new Run(engine, catchId, after, catches.Length, ambiguous);
    }

    /// <summary>The entries a run is compared on, per stream in stream order: the whole run, or for a varying-tail fork the events before the catch plus the catch.</summary>
    static Dictionary<string, string[]> Compared(Run run, bool upToCatch) =>
        run.Engine.Where(e => !upToCatch || run.CatchId is null || !run.AfterCatch.Contains(e.Id))
            .GroupBy(e => e.Stream).ToDictionary(g => g.Key, g => g.OrderBy(e => e.StreamSeq).Select(e => e.Key).ToArray());

    static string? FirstDifference(Dictionary<string, string[]> a, Dictionary<string, string[]> b)
    {
        foreach (string stream in a.Keys.Union(b.Keys).OrderBy(k => k, StringComparer.Ordinal))
        {
            string[] x = a.GetValueOrDefault(stream) ?? [], y = b.GetValueOrDefault(stream) ?? [];
            int i = 0;
            while (i < x.Length && i < y.Length && x[i] == y[i]) i++;
            if (i < x.Length || i < y.Length)
                return $"{stream} entry {i + 1}: run 1 '{(i < x.Length ? x[i] : "(end)")}', this run '{(i < y.Length ? y[i] : "(end)")}'";
        }
        return null;
    }

    static string Label(int lesson, string? attack) => attack ?? $"lesson {lesson}";

    static void Note(string line)
    {
        string? outDir = Environment.GetEnvironmentVariable("NETSEC_CLOCK_OUT");
        if (outDir is not null) File.AppendAllText(Path.Combine(outDir, "logical-clock-runs.txt"), line + Environment.NewLine);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Same_seed_gives_every_engine_event_the_same_clock(int lesson, string? attack)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        bool upToCatch = attack is not null && VaryingTails.Contains(attack);
        Dictionary<string, string[]>? first = null;
        string? firstCatch = null;
        int equal = 0;
        List<string> notes = [];
        for (int run = 0; run < Runs; run++)
        {
            bool loaded = KillRuns && run >= Runs / 2;
            using CancellationTokenSource stop = new();
            Task burn = loaded ? Burn(stop.Token) : Task.CompletedTask;
            List<JsonElement> frames;
            try { frames = await RunOnce(host, lesson, attack); }
            finally { stop.Cancel(); await burn; }
            Run r = Read(frames);
            string where = (loaded ? "load" : "idle") + $" run {run + 1}: ";
            List<string> missing = r.Engine.Where(e => e.Clock is null).Select(e => e.Key).Take(3).ToList();
            if (missing.Count > 0) { notes.Add(where + "engine events with no clock, first " + string.Join("; ", missing)); continue; }
            if (r.CatchFrames != 1) { notes.Add(where + $"{r.CatchFrames} trace.catch frames"); continue; }
            Dictionary<string, string[]> shape = Compared(r, upToCatch);
            if (first is null) { first = shape; firstCatch = r.CatchId; equal++; continue; }
            string? diff = FirstDifference(first, shape);
            if (diff is not null) notes.Add(where + diff);
            else if (r.CatchId != firstCatch) notes.Add(where + $"catch {r.CatchId ?? "none"}, run 1 catch {firstCatch ?? "none"}");
            else equal++;
        }
        string line = $"{Label(lesson, attack)}: same clocks in {equal} of {Runs} ({(upToCatch ? "up to the catch" : "whole")}, catch {firstCatch ?? "none"})";
        Note(line + string.Concat(notes.Select(n => Environment.NewLine + "  " + n)));
        Assert.True(equal == Runs, line + Environment.NewLine + string.Join(Environment.NewLine, notes));
    }

    [Theory]
    [MemberData(nameof(EveryRun))]
    public async Task Every_lesson_and_fork_clocks_each_engine_event_with_no_ambiguous_link(int lesson, string? attack)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        Run r = Read(await RunOnce(host, lesson, attack));
        Assert.True(r.Engine.Count > 0, $"{Label(lesson, attack)}: no engine events");
        Assert.Empty(r.Engine.Where(e => e.Clock is null).Select(e => e.Key));
        Assert.Empty(r.Ambiguous);
        Assert.Equal(1, r.CatchFrames);
    }

    static Task Burn(CancellationToken stop) => Task.WhenAll(Enumerable.Range(0, Environment.ProcessorCount).Select(_ => Task.Factory.StartNew(() =>
    {
        double x = 1;
        while (!stop.IsCancellationRequested) x = Math.Sqrt(x + 1.5);
    }, TaskCreationOptions.LongRunning)));

    static async Task Send(ClientWebSocket ws, string text, CancellationToken ct) => await ws.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, true, ct);

    static async Task<JsonElement> Until(ClientWebSocket ws, List<JsonElement> frames, Func<JsonElement, bool> stop, CancellationToken ct)
    {
        byte[] buffer = new byte[1 << 16];
        while (true)
        {
            using MemoryStream all = new();
            WebSocketReceiveResult r;
            do { r = await ws.ReceiveAsync(buffer, ct); all.Write(buffer, 0, r.Count); } while (!r.EndOfMessage);
            JsonElement f = JsonDocument.Parse(all.ToArray()).RootElement.Clone();
            frames.Add(f);
            if (stop(f)) return f;
        }
    }

    static bool Is(JsonElement f, string type) => Str(f, "type") == type;
    static string Sid(JsonElement f) => Str(f, "sessionId");

    /// <summary>One run: the lesson's session, or with an attack id the fork of a finished session. Returns the run's frames up to session.finished.</summary>
    static async Task<List<JsonElement>> RunOnce(SecurityLiveTests.Host host, int lesson, string? attackId)
    {
        using ClientWebSocket ws = new();
        using CancellationTokenSource limit = new(TimeSpan.FromSeconds(120));
        await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{host.Port}/ws?token={host.Token}"), limit.Token);
        List<JsonElement> frames = [];
        await Send(ws, "{\"type\":\"session.start\",\"requestId\":\"p\",\"lesson\":" + lesson + ",\"seed\":3,\"mode\":\"run\"}", limit.Token);
        JsonElement started = await Until(ws, frames, f => Is(f, "session.started") || Is(f, "error"), limit.Token);
        Assert.False(Is(started, "error"), $"lesson {lesson} did not start: {started.GetRawText()}");
        string parent = Sid(started);
        await Until(ws, frames, f => (Is(f, "session.finished") || Is(f, "error")) && Sid(f) == parent, limit.Token);
        if (attackId is null) return frames.Where(f => Sid(f) == parent).ToList();
        frames.Clear();
        await Send(ws, "{\"type\":\"session.attack\",\"requestId\":\"a\",\"sessionId\":\"" + parent + "\",\"attackId\":\"" + attackId + "\"}", limit.Token);
        string fork = Sid(await Until(ws, frames, f => Is(f, "session.started"), limit.Token));
        await Until(ws, frames, f => (Is(f, "session.finished") || Is(f, "error")) && Sid(f) == fork, limit.Token);
        return frames.Where(f => Sid(f) == fork).ToList();
    }
}
