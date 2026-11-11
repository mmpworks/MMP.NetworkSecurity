using System.Linq;

namespace NetSec.Bench;

/// <summary>One block case, measured as a pair: the frozen copy and the product on the same work, in alternating rounds.</summary>
sealed class CaseResult
{
    public CaseResult(BenchCase c, Pair pair) { Case = c; Pair = pair; }

    public BenchCase Case { get; }
    public Pair Pair { get; }

    public double OriginalNsPerUnit => Pair.Original.MedianNs / Case.UnitsPerOp;
    public double NewNsPerUnit => Pair.New.MedianNs / Case.UnitsPerOp;
    public double OriginalBytesPerUnit => Pair.Original.BytesPerCall / Case.UnitsPerOp;
    public double NewBytesPerUnit => Pair.New.BytesPerCall / Case.UnitsPerOp;
    public double NewMegabytesPerSecond => Case.BytesPerOp == 0 ? 0 : Case.BytesPerOp / Pair.New.MedianNs * 1e9 / (1024 * 1024);
    public double NewLowNsPerUnit => Pair.New.NsPerCall.Min() / Case.UnitsPerOp;
    public double NewHighNsPerUnit => Pair.New.NsPerCall.Max() / Case.UnitsPerOp;
}
