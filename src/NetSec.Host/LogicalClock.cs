using NetSec.Trace;

namespace NetSec.Host;

/// <summary>One event ready to write: its Lamport clock (null for a clockless event), the unmatched flag, and the send a receive matched.</summary>
public readonly record struct Clocked(TraceEvent Event, long? Clock, bool Unmatched, string? MatchedSendId);

/// <summary>A connection where more than 2 actors write sends or receives, so a receive's sender is ambiguous.</summary>
public sealed record LinkAmbiguity(string Connection, string[] Actors);

/// <summary>What one Admit or Close gives: the events to write now, in order, and any connection that just became ambiguous.</summary>
public sealed record ClockStep(IReadOnlyList<Clocked> Ready, IReadOnlyList<LinkAmbiguity> Ambiguous);

/// <summary>
/// How a stream id names its side (docs/logical-clock-plan.md, design items 2 and 8). The first segment is the session or trace id. After it,
/// an engine stream is &lt;actor&gt;/&lt;connection&gt;; &lt;engine stream&gt;/wire is that stream's wire; a one-segment id (keys) is a stream of its own.
/// </summary>
public static class ClockStreams
{
    const string WireSuffix = "/wire";

    public static string Local(string streamId) => streamId.IndexOf('/') is var i and >= 0 ? streamId[(i + 1)..] : streamId;

    public static bool IsWire(string local) => local.EndsWith(WireSuffix, StringComparison.Ordinal);

    public static bool IsEngine(string local) => local.Contains('/') && !IsWire(local);

    /// <summary>The side a clockless event belongs to: a wire stream's engine stream, or the stream itself.</summary>
    public static string SideOf(string local) => IsWire(local) ? local[..^WireSuffix.Length] : local;

    public static bool IsSend(TraceEvent e) => e.Type is { } t && t.EndsWith(".sent", StringComparison.Ordinal);

    public static bool IsReceive(TraceEvent e) => e.Type is { } t && t.EndsWith(".received", StringComparison.Ordinal);
}

/// <summary>
/// The Host's Lamport clock over the engine streams of one session (docs/logical-clock-plan.md). Each engine event takes own + 1; a receive
/// takes max(own, its send's clock) + 1, matched by (connection, sender) link and ordinal. A receive whose send has not arrived holds its side
/// (the engine stream and its wire) until the send arrives or the session closes. Not thread safe: LabSession calls it under its lock.
/// </summary>
public sealed class LogicalClock
{
    /// <summary>One engine stream: its clock so far, and the events held behind a receive that waits for its send, in stream order.</summary>
    sealed class Side
    {
        public long Own;
        public readonly Queue<TraceEvent> Held = new();
    }

    readonly record struct Link(string Connection, string Actor);

    readonly Dictionary<string, Side> _sides = new(StringComparer.Ordinal);
    readonly Dictionary<Link, List<(long Clock, string EventId)>> _sends = [];
    readonly Dictionary<Link, int> _receives = [];
    readonly Dictionary<string, List<string>> _writers = new(StringComparer.Ordinal);
    readonly HashSet<string> _ambiguous = new(StringComparer.Ordinal);

    public ClockStep Admit(TraceEvent e)
    {
        List<Clocked> ready = [];
        List<LinkAmbiguity> ambiguous = [];
        string local = ClockStreams.Local(e.StreamId);
        if (!ClockStreams.IsEngine(local))
        {
            // A wire event waits behind its held engine stream, so it keeps its place after the engine event that produced it.
            if (ClockStreams.IsWire(local) && _sides.TryGetValue(ClockStreams.SideOf(local), out Side? owner) && owner.Held.Count > 0) owner.Held.Enqueue(e);
            else ready.Add(new Clocked(e, null, false, null));
            return new ClockStep(ready, ambiguous);
        }
        if (Register(e, local) is { } newlyAmbiguous) ambiguous.Add(newlyAmbiguous);
        Side side = SideFor(local);
        side.Held.Enqueue(e);
        DrainAll(ready);
        return new ClockStep(ready, ambiguous);
    }

    /// <summary>Session end: every held receive with no send is written unmatched, in stream order, and the events behind it follow.</summary>
    public ClockStep Close()
    {
        List<Clocked> ready = [];
        DrainAll(ready);
        while (_sides.Where(p => p.Value.Held.Count > 0).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Value).FirstOrDefault() is { } stuck)
        {
            ready.Add(Write(stuck, stuck.Held.Dequeue(), forceUnmatched: true));
            DrainAll(ready);
        }
        return new ClockStep(ready, []);
    }

    Side SideFor(string local)
    {
        if (!_sides.TryGetValue(local, out Side? side)) _sides[local] = side = new Side();
        return side;
    }

    static (string Actor, string Connection) Split(string local)
    {
        int slash = local.IndexOf('/');
        return (local[..slash], local[(slash + 1)..]);
    }

    /// <summary>Records which actors write sends or receives on a connection, on arrival. The third one makes the connection ambiguous, once.</summary>
    LinkAmbiguity? Register(TraceEvent e, string local)
    {
        if (!ClockStreams.IsSend(e) && !ClockStreams.IsReceive(e)) return null;
        (string actor, string connection) = Split(local);
        if (!_writers.TryGetValue(connection, out List<string>? writers)) _writers[connection] = writers = [];
        if (writers.Contains(actor)) return null;
        writers.Add(actor);
        if (writers.Count <= 2 || !_ambiguous.Add(connection)) return null;
        return new LinkAmbiguity(connection, [.. writers.OrderBy(a => a, StringComparer.Ordinal)]);
    }

    /// <summary>Writes every side's held events that can go now. A send can free a receive on another side, so it repeats until nothing moves.</summary>
    void DrainAll(List<Clocked> ready)
    {
        bool moved = true;
        while (moved)
        {
            moved = false;
            foreach ((string _, Side side) in _sides.OrderBy(p => p.Key, StringComparer.Ordinal))
                while (side.Held.Count > 0 && TryWrite(side, side.Held.Peek()) is { } c)
                {
                    side.Held.Dequeue();
                    ready.Add(c);
                    moved = true;
                }
        }
    }

    /// <summary>The event clocked now, or null when it is a receive whose send has not arrived.</summary>
    Clocked? TryWrite(Side side, TraceEvent e)
    {
        string local = ClockStreams.Local(e.StreamId);
        if (!ClockStreams.IsEngine(local)) return new Clocked(e, null, false, null);
        if (!ClockStreams.IsReceive(e) || _ambiguous.Contains(Split(local).Connection)) return Write(side, e, forceUnmatched: false);
        return SendFor(local) is null ? null : Write(side, e, forceUnmatched: false);
    }

    /// <summary>The send a receive on this engine stream matches next: the k-th send by the other writer on the connection.</summary>
    (long Clock, string EventId)? SendFor(string local)
    {
        (string actor, string connection) = Split(local);
        string? peer = _writers.GetValueOrDefault(connection)?.FirstOrDefault(a => a != actor);
        if (peer is null || !_sends.TryGetValue(new Link(connection, peer), out var sends)) return null;
        int k = _receives.GetValueOrDefault(new Link(connection, actor));
        return k < sends.Count ? sends[k] : null;
    }

    /// <summary>
    /// Gives one engine event its clock. A send records its clock on its link. A receive on an ambiguous connection, or forced at close, takes
    /// own + 1 and the unmatched flag; any other receive takes max(own, its send) + 1. A send on an ambiguous connection is unmatched too.
    /// </summary>
    Clocked Write(Side side, TraceEvent e, bool forceUnmatched)
    {
        string local = ClockStreams.Local(e.StreamId);
        if (!ClockStreams.IsEngine(local)) return new Clocked(e, null, false, null);
        (string actor, string connection) = Split(local);
        bool ambiguous = _ambiguous.Contains(connection) && (ClockStreams.IsSend(e) || ClockStreams.IsReceive(e));
        if (ClockStreams.IsReceive(e) && !ambiguous && !forceUnmatched && SendFor(local) is { } send)
        {
            Count(connection, actor);
            side.Own = Math.Max(side.Own, send.Clock) + 1;
            return new Clocked(e, side.Own, false, send.EventId);
        }
        side.Own++;
        if (ClockStreams.IsReceive(e)) Count(connection, actor);
        if (ClockStreams.IsSend(e) && !ambiguous)
        {
            Link link = new(connection, actor);
            if (!_sends.TryGetValue(link, out var sends)) _sends[link] = sends = [];
            sends.Add((side.Own, e.EventId));
        }
        return new Clocked(e, side.Own, ambiguous || forceUnmatched, null);
    }

    void Count(string connection, string actor)
    {
        Link link = new(connection, actor);
        _receives[link] = _receives.GetValueOrDefault(link) + 1;
    }
}
