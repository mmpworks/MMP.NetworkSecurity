// CONTRACT STUB, Labs, Auth, Native, Platform folders. The design names these types and spells out only AttackDefinition,
// ILab, LabContext, TimingLab and TimingJudge. Every other member is ASSUMED and listed in CONTRACT.md.
#pragma warning disable CS0169, CS0649, CS8618
using System;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Platform
{
    public interface IClock { long NowMicros { get; } }
    public sealed class MonotonicClock : IClock { public MonotonicClock() { throw new NotImplementedException(); } public long NowMicros { get { throw new NotImplementedException(); } } }   // ASSUMED parameterless
}

namespace NetSec.Labs
{
    public enum AttackOutcome { Rejected, Accepted, NoCheck }                                           // ASSUMED members; NoCheck = "assert the absence of a failed check" (ECB, CBC flip)

    public sealed class TamperPlan { public string Kind; }                                              // design: data (kind, stream, streamSeq or message, offset, xor, replacement)
    public sealed class LabOption { public string Name; public string Value; }                          // ASSUMED shape

    public sealed class AttackDefinition
    {
        public string AttackId; public int Lesson; public string Kind; public TamperPlan Plan; public LabOption[] Options;
        public AttackOutcome Expect; public string ExpectCode, ExpectCheck;
    }

    /// <summary>ASSUMED: the one list of attacks (design 2.5: "AttackCatalog is the one list of attacks").</summary>
    public static class AttackCatalog { public static AttackDefinition[] All { get { throw new NotImplementedException(); } } }

    public sealed class LabContext
    {
        public int Seed; public ITransportFactory Transports; public IStepGate Gate; public ITraceSink Sink; public NetSec.Platform.IClock Clock;
        public IRandomSource Random; public AttackDefinition Attack;
    }

    /// <summary>ASSUMED shape: Completed is true when the lesson ran to its end. FailedCode and FailedCheck name the first failed check.</summary>
    public sealed class LabResult { public bool Completed; public string FailedCode; public string FailedCheck; }

    public interface ILab { string LabId { get; } IFuture<LabResult> Run(LabContext context); }

    /// <summary>ASSUMED: the lab for a lesson number 1 to 11.</summary>
    public static class LabCatalog { public static ILab Find(int lesson) { throw new NotImplementedException(); } }
}

namespace NetSec.Native
{
    public enum CompareKind { Leaky, ConstantTime }                                                     // ASSUMED members

    public sealed class TimingCase { public double[] TicksFirstByteDiff; }                              // shape not used by the suite

    public sealed class TimingVerdict { public double LeakyT, ConstantT, Threshold; public bool Separated; }                                          // ASSUMED shape: Welch t of the two cases, and whether |t| passes the stated threshold

    public static class NativeCompare
    {
        /// <summary>ASSUMED: P/Invoke wrappers over nsct_compare_leaky and nsct_compare_ct (design section 7).</summary>
        public static bool Leaky(byte[] a, byte[] b) { throw new NotImplementedException(); }
        public static bool ConstantTime(byte[] a, byte[] b) { throw new NotImplementedException(); }
        public static uint AbiVersion() { throw new NotImplementedException(); }
    }

    public static class TimingLab
    {
        public static TimingCase Sample(CompareKind kind, int bufferSize, int samples, int diffPosition) { throw new NotImplementedException(); }
    }

    public static class TimingJudge
    {
        /// <summary>ASSUMED: leaky pair then constant-time pair, each as (difference in the first byte, difference in the last byte).</summary>
        public static TimingVerdict Judge(TimingCase leakyFirst, TimingCase leakyLast, TimingCase constFirst, TimingCase constLast) { throw new NotImplementedException(); }
    }
}
