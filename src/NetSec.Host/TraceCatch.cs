using NetSec.Labs;

namespace NetSec.Host;

/// <summary>The catch of a run (its event id, or null) and the ids of the events after it, in write order.</summary>
public sealed record CatchResult(string? CatchEventId, string[] AfterCatch);

/// <summary>
/// The catch and "after the catch" (docs/logical-clock-plan.md, "The catch"). The catch is the first failed check whose code names a cause
/// (LabPair.NamesACause, the rule FrameEngine's result uses), first in (clock, side) order. Before the catch means happens-before it: walk
/// back along the catch's stream, and through each matched receive to its send and the events before that send. Everything else is after.
/// </summary>
public static class TraceCatch
{
    public static CatchResult Find(IReadOnlyList<Clocked> written)
    {
        Clocked? first = written
            .Where(c => c.Clock is not null && c.Event.Check is { Passed: false } check && LabPair.NamesACause(check.Code))
            .OrderBy(c => c.Clock).ThenBy(c => ClockStreams.Local(c.Event.StreamId), StringComparer.Ordinal)
            .Cast<Clocked?>().FirstOrDefault();
        if (first is not { } k) return new CatchResult(null, []);
        Dictionary<string, long> reached = Reached(written, k);
        bool Before(Clocked c) => reached.TryGetValue(ClockStreams.Local(c.Event.StreamId), out long max) && c.Event.StreamSeq <= max;
        List<string> after = [];
        Dictionary<string, Clocked> lastEngine = new(StringComparer.Ordinal);
        foreach (Clocked c in written)
        {
            string local = ClockStreams.Local(c.Event.StreamId);
            if (c.Clock is not null)
            {
                lastEngine[local] = c;
                if (!Before(c)) after.Add(c.Event.EventId);
            }
            // A clockless event goes with its side's last engine event before it; with none it sits at clock 0, before everything.
            else if (lastEngine.TryGetValue(ClockStreams.SideOf(local), out Clocked anchor) && !Before(anchor)) after.Add(c.Event.EventId);
        }
        return new CatchResult(k.Event.EventId, [.. after]);
    }

    /// <summary>The backward walk: per engine stream, the highest stream seq that happens before or is the catch.</summary>
    static Dictionary<string, long> Reached(IReadOnlyList<Clocked> written, Clocked k)
    {
        Dictionary<string, List<Clocked>> byStream = written.Where(c => c.Clock is not null)
            .GroupBy(c => ClockStreams.Local(c.Event.StreamId), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(c => c.Event.StreamSeq).ToList(), StringComparer.Ordinal);
        Dictionary<string, Clocked> byId = written.Where(c => c.Clock is not null).ToDictionary(c => c.Event.EventId, StringComparer.Ordinal);
        Dictionary<string, long> reached = new(StringComparer.Ordinal);
        Stack<Clocked> work = new([k]);
        while (work.TryPop(out Clocked top))
        {
            string stream = ClockStreams.Local(top.Event.StreamId);
            long from = reached.GetValueOrDefault(stream);
            if (top.Event.StreamSeq <= from) continue;
            reached[stream] = top.Event.StreamSeq;
            foreach (Clocked c in byStream[stream].Where(c => c.Event.StreamSeq > from && c.Event.StreamSeq <= top.Event.StreamSeq))
                if (c.MatchedSendId is { } sendId && byId.TryGetValue(sendId, out Clocked send)) work.Push(send);
        }
        return reached;
    }
}

/// <summary>
/// The page's order (design item 8): by (clock, side), and in write order on a tie. A clockless event takes the clock of its side's last engine
/// event written before it, or 0 with none. Side is the engine stream after the session prefix; a wire event's side is its engine stream.
/// The seam for the page's order. Today only LogicalClockTests call it, and app/src does not read "clock" yet. When the page orders by
/// (clock, side), it must give the order this method gives, or the Host sends frames sorted with this method.
/// </summary>
public static class TraceOrder
{
    public static IReadOnlyList<Clocked> Sort(IReadOnlyList<Clocked> written)
    {
        Dictionary<string, long> last = new(StringComparer.Ordinal);
        List<(long Clock, string Side, int Index, Clocked Event)> keyed = [];
        for (int i = 0; i < written.Count; i++)
        {
            Clocked c = written[i];
            string side = ClockStreams.SideOf(ClockStreams.Local(c.Event.StreamId));
            long clock = c.Clock ?? last.GetValueOrDefault(side);
            if (c.Clock is { } own) last[side] = own;
            keyed.Add((clock, side, i, c));
        }
        return [.. keyed.OrderBy(x => x.Clock).ThenBy(x => x.Side, StringComparer.Ordinal).ThenBy(x => x.Index).Select(x => x.Event)];
    }
}
