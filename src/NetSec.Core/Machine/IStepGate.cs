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
}
