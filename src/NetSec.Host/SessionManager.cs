using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.Host;

/// <summary>One run of one lab. Stamps the session-wide seq and the seed, stores each event, and appends it to the session file.</summary>
public sealed class LabSession : ITraceSink
{
    const int EventCap = 20_000;

    readonly Lock _gate = new();
    readonly List<StoredEvent> _events = [];
    readonly StreamWriter _file;
    readonly Action<string> _broadcast;
    long _seq;

    public string SessionId { get; }
    public int Lesson { get; }
    public int Seed { get; }
    public string SessionFile { get; }
    public IStepGate Gate { get; }
    public bool Finished { get; private set; }

    /// <summary>The keys this run reads, fixed at the start. A fork reuses them.</summary>
    public CredentialSet Credentials { get; }

    public LabSession(string sessionId, int lesson, int seed, string mode, string sessionsDir, CredentialSet credentials, Action<string> broadcast)
    {
        Credentials = credentials;
        SessionId = sessionId;
        Lesson = lesson;
        Seed = seed;
        _broadcast = broadcast;
        Gate = mode == "step" ? new StepGate() : new FreeRunGate();
        SessionFile = Path.Combine(sessionsDir, $"{lesson:00}-{seed}-{DateTime.UtcNow:yyyyMMddTHHmmss}-{sessionId}.ndjson");
        _file = new StreamWriter(SessionFile, append: false, Encoding.UTF8) { AutoFlush = true };
    }

    public void Write(TraceEvent e)
    {
        lock (_gate)
        {
            string body = TraceJson.ToLine(e);
            string line = $"{{\"seq\":{++_seq},\"seed\":{Seed},{body[1..]}";
            if (_events.Count < EventCap) _events.Add(new StoredEvent(_seq, e.StreamId, e.StreamSeq, e.Type, e.Message, line));
            _file.WriteLine(line);
            _broadcast($"{{\"type\":\"trace\",\"sessionId\":{JsonSerializer.Serialize(SessionId)},\"seq\":{_seq},\"event\":{line}}}");
        }
    }

    public IReadOnlyList<StoredEvent> After(long seq)
    {
        lock (_gate) return _events.Where(e => e.Seq > seq).ToList();
    }

    /// <summary>The plan that flips a byte of the message at session seq atSeq, addressed so a same-seed rerun hits the same message.</summary>
    public TamperPlan? PlanFor(long atSeq, string newSessionId, int offset, int xor)
    {
        lock (_gate)
        {
            int at = _events.FindIndex(e => e.Seq == atSeq);
            if (at < 0) return null;
            StoredEvent target = _events[at];
            bool onWire = target.StreamId.EndsWith("/wire", StringComparison.Ordinal);
            if (onWire) target = _events.Take(at).Last(e => e.StreamId == target.StreamId[..^"/wire".Length] && e.Message == target.Message);
            return new TamperPlan
            {
                Point = onWire ? TamperPoint.Wire : TamperPoint.Plain,
                StreamId = target.StreamId.Replace(SessionId + "/", newSessionId + "/", StringComparison.Ordinal),
                StreamSeq = target.StreamSeq,
                Offset = offset,
                Xor = xor,
            };
        }
    }

    public void Finish()
    {
        lock (_gate)
        {
            Finished = true;
            _file.Dispose();
        }
    }
}

public sealed record StoredEvent(long Seq, string StreamId, long StreamSeq, string Type, string? Message, string Line);

/// <summary>Holds the last 20 sessions and fans frames out to every socket. A slow socket drops its oldest frames, and the count shows.</summary>
public sealed class SessionManager
{
    const int KeepSessions = 20;
    const int ClientQueue = 4096;

    readonly Lock _gate = new();
    readonly Dictionary<string, LabSession> _sessions = [];
    readonly Queue<string> _order = new();
    readonly List<Channel<string>> _clients = [];
    long _droppedEvents;

    public string SessionsDir { get; }
    public long DroppedEvents => Interlocked.Read(ref _droppedEvents);

    public SessionManager(string sessionsDir)
    {
        SessionsDir = sessionsDir;
        Directory.CreateDirectory(sessionsDir);
    }

    public LabSession? Find(string id)
    {
        lock (_gate) return _sessions.GetValueOrDefault(id);
    }

    public ChannelReader<string> Connect(out Channel<string> client)
    {
        // GEM:fail-soft-must-count: a dropped frame raises a visible counter, and the UI repairs the gap from ?after=N.
        client = Channel.CreateBounded<string>(
            new BoundedChannelOptions(ClientQueue) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true },
            _ => Interlocked.Increment(ref _droppedEvents));
        lock (_gate) _clients.Add(client);
        return client.Reader;
    }

    public void Disconnect(Channel<string> client)
    {
        lock (_gate) _clients.Remove(client);
        client.Writer.TryComplete();
    }

    public void Broadcast(string frame)
    {
        Channel<string>[] clients;
        lock (_gate) clients = _clients.ToArray();
        foreach (Channel<string> c in clients) c.Writer.TryWrite(frame);
    }

    /// <summary>
    /// Starts a session and returns it, or a named error when the lesson has no lab. announce runs before the lab does,
    /// so session.started always goes out ahead of the session's first trace frame.
    /// </summary>
    public LabSession? Start(int lesson, int seed, string mode, AttackDefinition? attack, string? sessionId, CredentialSet credentials, Action<LabSession> announce, out NetSecError? error)
    {
        ILab? lab = LabCatalog.Find(lesson);
        if (lab is null)
        {
            error = NetSecError.Of(ErrorCodes.LessonNotBuilt, $"Lesson {lesson} is not built yet.");
            return null;
        }
        error = null;
        string id = sessionId ?? NewId();
        LabSession session = new(id, lesson, seed, mode, SessionsDir, credentials, Broadcast);
        Keep(session);
        announce(session);
        WriteKeyFacts(session, credentials);
        LabContext context = new()
        {
            Seed = seed,
            SessionId = id,
            TraceId = id,
            Gate = session.Gate,
            Sink = session,
            Clock = new MonotonicClock(),
            Random = new SeededRandom(seed),
            Attack = attack,
            Credentials = credentials,
        };
        IFuture<LabResult> run = lab.Run(context);
        run.GetAwaiter().OnCompleted(() => Finish(session, run));
        return session;
    }

    /// <summary>A verifier holds the issuer public key without any message that shows it, so the Host states it on its own stream. The engine streams do not change.</summary>
    static void WriteKeyFacts(LabSession session, CredentialSet credentials)
    {
        if (Array.IndexOf(LabCatalog.Needs(session.Lesson), SecurityTypes.TokenIssuer) < 0) return;
        TraceStream keys = new(session.SessionId + "/keys", session.SessionId, session.SessionId, null, "issuer", new MonotonicClock());
        session.Write(keys.Stamp(new TraceEventDraft
        {
            Type = "key.public",
            Secrets = [new TraceSecret { Holder = "issuer", Name = "auth.issuer-public", Bytes = credentials.Find(KeyIds.TokenIssuer).CopyPublic() }],
        }));
    }

    public static string NewId() => "s" + Guid.NewGuid().ToString("N")[..12];

    void Keep(LabSession session)
    {
        lock (_gate)
        {
            _sessions[session.SessionId] = session;
            _order.Enqueue(session.SessionId);
            while (_order.Count > KeepSessions) _sessions.Remove(_order.Dequeue());
        }
    }

    void Finish(LabSession session, IFuture<LabResult> run)
    {
        session.Finish();
        if (run.IsFaulted || run.IsCanceled)
        {
            Broadcast(JsonSerializer.Serialize(new
            {
                type = "session.finished",
                sessionId = session.SessionId,
                outcome = "faulted",
                code = "LAB_FAULTED",
                check = (string?)null,
            }));
            return;
        }
        LabResult r = run.Result;
        Broadcast(JsonSerializer.Serialize(new
        {
            type = "session.finished",
            sessionId = session.SessionId,
            outcome = r.Completed ? "completed" : "caught",
            code = r.FailedCode,
            check = r.FailedCheck,
        }));
    }
}
