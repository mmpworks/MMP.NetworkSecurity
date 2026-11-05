using MMP.AsyncProxy;
using NetSec.Trace;

namespace NetSec.Machine
{
    /// <summary>Holds an event until the tour lets it pass. This one interface is the only AsyncProxy use in Machine.</summary>
    public interface IStepGate
    {
        IFuture Pass(TraceEvent e);
    }
}
