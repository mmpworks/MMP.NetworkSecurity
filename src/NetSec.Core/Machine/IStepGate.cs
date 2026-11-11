using MMP.AsyncProxy;
using NetSec.Trace;

namespace NetSec.Machine
{
    /// <summary>Holds an event until the tour lets it pass. This one interface is the only AsyncProxy use in Machine.</summary>
    public interface IStepGate
    {
        IFuture Pass(TraceEvent e);
    }

    /// <summary>
    /// A gate that can say a learner holds an event. EnginePump restarts its read deadline while this is true, so a learner can read for an hour.
    /// With nothing held, a read that stays open is stuck for real, and the deadline ends it with a named error.
    /// </summary>
    public interface IGateState
    {
        bool IsHolding { get; }
    }

    /// <summary>
    /// A gate the pumps of one session share, so a read clock can count only while the whole session is quiet (issue #394). After a step releases
    /// an event, the gate holds nothing, but the released side may resume late on a busy pool. A pump that waits on its idle limit must not count
    /// while its peer is still passing events. Each pump joins with a test of its own work, and any pump's work keeps every clock at 0.
    /// </summary>
    public interface IGateActivity
    {
        void Join(GateWork busy);
        bool AnyBusy { get; }
    }

    /// <summary>True while one pump still has events to pass.</summary>
    public delegate bool GateWork();
}
