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
    readonly Func<bool> _showKeys;
    long _seq;

    public string SessionId { get; }
    public int Lesson { get; }
    public int Seed { get; }
    public string SessionFile { get; }
    public IStepGate Gate { get; }
    public bool Finished { get; private set; }

    /// <summary>The keys this run reads, fixed at the start. A fork reuses them.</summary>
    public CredentialSet Credentials { get; }

    /// <summary>glass for a course engine, os for Windows SslStream (OsTransport). An os session holds no secret, so it keeps no key log.</summary>
    public string TransportKind { get; }

    /// <summary>True once the session file holds a line with key bytes: session.save while Show keys is OFF then writes a hidden copy.</summary>
    public bool FileHoldsShownKeys { get; private set; }

    public LabSession(string sessionId, int lesson, int seed, string mode, string sessionsDir, CredentialSet credentials, Action<string> broadcast, string transportKind = "glass", Func<bool>? showKeys = null)
    {
        _showKeys = showKeys ?? (() => true);
        Credentials = credentials;
        TransportKind = transportKind;
        SessionId = sessionId;
        Lesson = lesson;
        Seed = seed;
        _broadcast = broadcast;
        Gate = mode == "step" ? new StepGate() : new FreeRunGate();
        SessionFile = Path.Combine(sessionsDir, $"{lesson:00}-{seed}-{DateTime.UtcNow:yyyyMMddTHHmmss}-{sessionId}.ndjson");
        _file = new StreamWriter(SessionFile, append: false, Encoding.UTF8) { AutoFlush = true };
    }

    /// <summary>
    /// The Show keys boundary (modes-design.md section 6.4). Each event becomes two lines, shown and hidden, and both are stored, so a flip of the
    /// toggle changes what /events gives at once. The file and the broadcast take the line the toggle names now. The event itself is not changed.
    /// </summary>
    public void Write(TraceEvent e)
    {
        lock (_gate)
        {
            long seq = ++_seq;
            string shown = Stamp(seq, TraceJson.ToLine(e)), hidden = Stamp(seq, TraceJson.ToLine(TraceRedaction.Hide(e)));
            if (_events.Count < EventCap) _events.Add(new StoredEvent(seq, e.StreamId, e.StreamSeq, e.Type, e.Message, shown, hidden));
            bool show = _showKeys();
            string line = show ? shown : hidden;
            if (show && shown != hidden) FileHoldsShownKeys = true;
            _file.WriteLine(line);
            _broadcast($"{{\"type\":\"trace\",\"sessionId\":{JsonSerializer.Serialize(SessionId)},\"seq\":{seq},\"event\":{line}}}");
        }
    }

    string Stamp(long seq, string body) => $"{{\"seq\":{seq},\"seed\":{Seed},{body[1..]}";

    public IReadOnlyList<StoredEvent> After(long seq)
    {
        lock (_gate) return _events.Where(e => e.Seq > seq).ToList();
    }

    /// <summary>The stored lines after seq, as the toggle names them now.</summary>
    public IEnumerable<string> LinesAfter(long seq)
    {
        bool show = _showKeys();
        return After(seq).Select(e => show ? e.Line : e.HiddenLine);
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

public sealed record StoredEvent(long Seq, string StreamId, long StreamSeq, string Type, string? Message, string Line, string HiddenLine);

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

    readonly Func<bool> _showKeys;

    /// <summary>showKeys reads the toggle at each write and each read, so a flip takes effect at once.</summary>
    public SessionManager(string sessionsDir, Func<bool>? showKeys = null)
    {
        _showKeys = showKeys ?? (() => true);
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
    /// <summary>osLab, when given, runs instead of the lesson's course lab, and the session is an os session.</summary>
    public LabSession? Start(int lesson, int seed, string mode, AttackDefinition? attack, string? sessionId, CredentialSet credentials, Action<LabSession> announce, out NetSecError? error, ILab? osLab = null)
    {
        ILab? lab = osLab ?? LabCatalog.Find(lesson);
        if (lab is null)
        {
            error = NetSecError.Of(ErrorCodes.LessonNotBuilt, $"Lesson {lesson} is not built yet.");
            return null;
        }
        error = null;
        string id = sessionId ?? NewId();
        LabSession session = new(id, lesson, seed, mode, SessionsDir, credentials, Broadcast, osLab is null ? "glass" : OsTransport.OsTransportFactory.Kind, _showKeys);
        Keep(session);
        announce(session);
        if (osLab is null) WriteKeyFacts(session, credentials);
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
    /// <summary>
    /// The Host's own stream, &lt;sessionId&gt;/keys, outside every engine stream, so stream numbers, tamper addresses and the golden traces stay as they are.
    /// key.in-use names each type the lab reads with the bytes it runs on (modes-design.md section 6.3), in both toggle states; the toggle hides them at
    /// the boundary like any secret. key.public states the issuer public key a verifier holds without any message that shows it.
    /// </summary>
    static void WriteKeyFacts(LabSession session, CredentialSet credentials)
    {
        TraceStream keys = new(session.SessionId + "/keys", session.SessionId, session.SessionId, null, "host", new MonotonicClock());
        string[] reads = LabCatalog.Needs(session.Lesson);
        foreach (string typeId in reads) session.Write(keys.Stamp(KeyInUse(typeId, credentials)));
        if (Array.IndexOf(reads, SecurityTypes.TokenIssuer) < 0) return;
        session.Write(keys.Stamp(new TraceEventDraft
        {
            Type = "key.public",
            Secrets = [new TraceSecret { Holder = "issuer", Name = "auth.issuer-public", Bytes = credentials.Find(KeyIds.TokenIssuer).CopyPublic() }],
        }));
    }

    const string Builtin = "builtin";

    /// <summary>The learner's key when the set holds one, else the built-in training key. A type with no long-term key (a trust list, a per-run lab key) names no bytes.</summary>
    static TraceEventDraft KeyInUse(string typeId, CredentialSet credentials)
    {
        Credential? mine = credentials.Mine().FirstOrDefault(c => c.TypeId == typeId);
        ITrainingKey? key = mine is not null ? mine.Key : SecurityTypes.BuiltInKeyOf(typeId) is { } keyId ? new TrainingKeySource().Find(keyId) : null;
        return new TraceEventDraft
        {
            Type = "key.in-use",
            Message = $"{typeId} runs on {(mine is null ? "the built-in key" : $"version {mine.Version} from {mine.ProviderKind}")}.",
            KeyUse = new TraceKeyUse { TypeId = typeId, Version = mine?.Version ?? 0, Provider = mine?.ProviderKind ?? Builtin },
            Secrets = key is null ? [] : [new TraceSecret { Holder = "host", Name = typeId, Bytes = key.CopyMaterial() }],
        };
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
