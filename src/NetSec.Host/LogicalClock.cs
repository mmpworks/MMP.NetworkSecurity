using NetSec.Trace;

namespace NetSec.Host;

/// <summary>One event ready to write: its Lamport clock (null for a clockless event), the unmatched flag, and the send a receive matched.</summary>
public readonly record struct Clocked(TraceEvent Event, long? Clock, bool Unmatched, string? MatchedSendId);

/// <summary>A connection where more than 2 actors write sends or receives, so a receive's sender is ambiguous.</summary>
public sealed record LinkAmbiguity(string Connection, string[] Actors);

/// <summary>What one Admit or Close gives: the events to write now, in order, and any connection that just became ambiguous.</summary>
public sealed record ClockStep(IReadOnlyList<Clocked> Ready, IReadOnlyList<LinkAmbiguity> Ambiguous);

/// <summary>RED STUB: no clock yet.</summary>
public sealed class LogicalClock
{
    public ClockStep Admit(TraceEvent e) => new([new Clocked(e, null, false, null)], []);

    public ClockStep Close() => new([], []);
}

/// <summary>The catch of a run and the events after it.</summary>
public sealed record CatchResult(string? CatchEventId, string[] AfterCatch);

/// <summary>RED STUB.</summary>
public static class TraceCatch
{
    public static CatchResult Find(IReadOnlyList<Clocked> written) => new(null, []);
}

/// <summary>RED STUB.</summary>
public static class TraceOrder
{
    public static IReadOnlyList<Clocked> Sort(IReadOnlyList<Clocked> written) => written;
}
