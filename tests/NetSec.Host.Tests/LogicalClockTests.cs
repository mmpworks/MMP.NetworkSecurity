#nullable enable
using System.Collections.Generic;
using System.Linq;
using NetSec.Errors;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Fixed-trace tests for the rules of docs/logical-clock-plan.md ("Anchor", items 1 to 9). No Host process: the clock and the catch are pure.</summary>
public sealed class LogicalClockTests
{
    readonly Dictionary<string, TraceStream> _streams = [];

    /// <summary>The next event on the stream "s1/&lt;local&gt;". The actor is the first segment, as in the labs.</summary>
    TraceEvent Ev(string local, string type, string? message = null, string? failedCode = null)
    {
        if (!_streams.TryGetValue(local, out TraceStream? s))
            _streams[local] = s = new TraceStream("s1/" + local, "s1", "s1", null, local.Split('/')[0], new FixedClock(0));
        TraceEventDraft draft = new() { Type = type, Message = message };
        if (failedCode is not null) draft.Check = new TraceCheck { Id = "c", Name = "check", Passed = false, Code = failedCode };
        return s.Stamp(draft);
    }

    static List<Clocked> All(LogicalClock clock, params TraceEvent[] events)
    {
        List<Clocked> written = [];
        foreach (TraceEvent e in events) written.AddRange(clock.Admit(e).Ready);
        written.AddRange(clock.Close().Ready);
        return written;
    }

    static long? ClockOf(List<Clocked> written, string eventId) => written.Single(c => c.Event.EventId == eventId).Clock;

    [Fact]
    public void A_receive_takes_the_larger_of_its_own_clock_and_the_send_plus_one()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("client/aes", "note"), Ev("client/aes", "note"), Ev("client/aes", "aes.message.sent", "A"),
            Ev("server/aes", "aes.message.received", "A"), Ev("server/aes", "note"),
            Ev("server/aes", "note"), Ev("server/aes", "note"), Ev("server/aes", "note"), Ev("client/aes", "aes.message.sent", "B"),
            Ev("server/aes", "aes.message.received", "B"));
        Assert.Equal(3, ClockOf(w, "s1/client/aes#3"));
        Assert.Equal(4, ClockOf(w, "s1/server/aes#1"));
        Assert.Equal(5, ClockOf(w, "s1/server/aes#2"));
        Assert.Equal(4, ClockOf(w, "s1/client/aes#4"));
        Assert.Equal(9, ClockOf(w, "s1/server/aes#6"));
        Assert.Equal("s1/client/aes#3", w.Single(c => c.Event.EventId == "s1/server/aes#1").MatchedSendId);
        Assert.DoesNotContain(w, c => c.Unmatched);
    }

    [Fact]
    public void A_receive_before_its_send_holds_its_whole_stream_and_its_wire_until_the_send_arrives()
    {
        LogicalClock clock = new();
        Assert.Empty(clock.Admit(Ev("server/aes", "aes.message.received", "A")).Ready);
        Assert.Empty(clock.Admit(Ev("server/aes", "note")).Ready);
        Assert.Empty(clock.Admit(Ev("server/aes/wire", "wire.received")).Ready);
        Assert.Single(clock.Admit(Ev("client/aes", "note")).Ready);
        Assert.Single(clock.Admit(Ev("keys", "key.in-use")).Ready);
        List<Clocked> ready = clock.Admit(Ev("client/aes", "aes.message.sent", "A")).Ready.ToList();
        Assert.Equal(["s1/client/aes#2", "s1/server/aes#1", "s1/server/aes#2", "s1/server/aes/wire#1"], ready.Select(c => c.Event.EventId));
        Assert.Equal([2L, 3L, 4L, null], ready.Select(c => c.Clock));
    }

    [Fact]
    public void A_receive_with_no_send_is_written_unmatched_at_close_and_the_events_behind_it_follow()
    {
        LogicalClock clock = new();
        Assert.Equal(1, Assert.Single(clock.Admit(Ev("server/aes", "note")).Ready).Clock);
        Assert.Empty(clock.Admit(Ev("server/aes", "aes.message.received", "lost")).Ready);
        Assert.Empty(clock.Admit(Ev("server/aes", "note")).Ready);
        Assert.Single(clock.Admit(Ev("client/aes", "note")).Ready);
        List<Clocked> released = clock.Close().Ready.ToList();
        Assert.Equal(["s1/server/aes#2", "s1/server/aes#3"], released.Select(c => c.Event.EventId));
        Assert.Equal([2L, 3L], released.Select(c => c.Clock));
        Assert.Equal([true, false], released.Select(c => c.Unmatched));
    }

    [Fact]
    public void A_send_from_the_attacker_side_matches_a_receive_like_any_other_send()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("attacker/tls11", "note"), Ev("attacker/tls11", "note"), Ev("attacker/tls11", "tls11.message.sent", "Injected"),
            Ev("client/tls11", "note"), Ev("server/tls11", "tls11.message.received", "Injected"));
        Assert.Equal(4, ClockOf(w, "s1/server/tls11#1"));
        Assert.Equal("s1/attacker/tls11#3", w.Single(c => c.Event.EventId == "s1/server/tls11#1").MatchedSendId);
    }

    [Fact]
    public void Three_actors_that_send_or_receive_on_one_connection_give_one_ambiguity_and_no_guessed_match()
    {
        LogicalClock clock = new();
        Assert.Empty(clock.Admit(Ev("client/aes", "aes.message.sent", "A")).Ambiguous);
        Assert.Empty(clock.Admit(Ev("server/aes", "aes.message.received", "A")).Ambiguous);
        ClockStep third = clock.Admit(Ev("attacker/aes", "aes.message.sent", "X"));
        LinkAmbiguity a = Assert.Single(third.Ambiguous);
        Assert.Equal("aes", a.Connection);
        Assert.Equal(["attacker", "client", "server"], a.Actors);
        Assert.True(Assert.Single(third.Ready).Unmatched);
        ClockStep next = clock.Admit(Ev("server/aes", "aes.message.received", "X"));
        Assert.Empty(next.Ambiguous);
        Clocked receive = Assert.Single(next.Ready);
        Assert.True(receive.Unmatched);
        Assert.Null(receive.MatchedSendId);
        Assert.Equal(3, receive.Clock);
        Assert.Empty(clock.Admit(Ev("attacker/aes", "aes.message.sent", "Y")).Ambiguous);
    }

    [Fact]
    public void A_clockless_event_sorts_right_after_its_sides_last_engine_event_or_at_clock_0()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("keys", "key.in-use"), Ev("server/aes/wire", "wire.received"), Ev("client/aes", "note"), Ev("client/aes", "note"),
            Ev("client/aes/wire", "wire.sent"), Ev("server/aes", "note"), Ev("client/aes", "note"));
        Assert.Equal(
            ["s1/keys#1", "s1/server/aes/wire#1", "s1/client/aes#1", "s1/server/aes#1", "s1/client/aes#2", "s1/client/aes/wire#1", "s1/client/aes#3"],
            TraceOrder.Sort(w).Select(c => c.Event.EventId));
    }

    [Fact]
    public void The_catch_is_the_first_failed_check_that_names_a_cause_and_a_follow_on_check_with_a_lower_clock_is_never_it()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("client/aes", "check.result", failedCode: ErrorCodes.PeerClosedEarly),
            Ev("client/aes", "aes.message.sent", "A"), Ev("server/aes", "aes.message.received", "A"),
            Ev("server/aes", "check.result", failedCode: ErrorCodes.AesGcmTag), Ev("server/aes", "note"));
        CatchResult k = TraceCatch.Find(w);
        Assert.Equal("s1/server/aes#2", k.CatchEventId);
        Assert.Equal(["s1/server/aes#3"], k.AfterCatch);
    }

    [Fact]
    public void On_a_tie_in_clock_the_catch_goes_to_the_side_that_sorts_first()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("server/aes", "check.result", failedCode: ErrorCodes.AesGcmTag), Ev("client/aes", "check.result", failedCode: ErrorCodes.AesGcmTag));
        Assert.Equal("s1/client/aes#1", TraceCatch.Find(w).CatchEventId);
    }

    [Fact]
    public void The_backward_walk_reaches_the_catch_stream_and_each_matched_senders_events_up_to_the_send_and_no_others()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock,
            Ev("keys", "key.in-use"),
            Ev("client/aes", "note"), Ev("client/aes", "aes.message.sent", "M1"), Ev("client/aes/wire", "wire.sent"),
            Ev("server/aes", "aes.message.received", "M1"),
            Ev("client/aes", "aes.message.sent", "M2"), Ev("client/aes/wire", "wire.sent"), Ev("client/aes", "aes.message.sent", "M3"),
            Ev("server/aes", "check.result", failedCode: ErrorCodes.AesGcmTag),
            Ev("server/aes", "aes.message.received", "M2"));
        CatchResult k = TraceCatch.Find(w);
        Assert.Equal("s1/server/aes#2", k.CatchEventId);
        Assert.Equal(["s1/client/aes#3", "s1/client/aes/wire#2", "s1/client/aes#4", "s1/server/aes#3"], k.AfterCatch);
    }

    [Fact]
    public void A_run_with_no_failed_check_has_no_catch_and_an_empty_after_list()
    {
        LogicalClock clock = new();
        List<Clocked> w = All(clock, Ev("client/aes", "aes.message.sent", "A"), Ev("server/aes", "aes.message.received", "A"),
            Ev("client/aes", "check.result", failedCode: ErrorCodes.PeerClosedEarly));
        CatchResult k = TraceCatch.Find(w);
        Assert.Null(k.CatchEventId);
        Assert.Empty(k.AfterCatch);
    }
}
