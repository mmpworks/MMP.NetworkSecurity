using System;
using System.Diagnostics;
using System.Security.Cryptography;
using NetSec.Crypto;

namespace NetSec.Platform
{
    public interface IClock
    {
        long NowMicros { get; }
    }

    public sealed class MonotonicClock : IClock
    {
        readonly Stopwatch _watch = new Stopwatch();

        public MonotonicClock() { _watch.Start(); }

        public long NowMicros
        {
            get { return (long)(_watch.ElapsedTicks * (1000000.0 / Stopwatch.Frequency)); }
        }
    }

    /// <summary>A clock that stays still, so two runs of a lab give the same bytes.</summary>
    public sealed class FixedClock : IClock
    {
        readonly long _micros;
        public FixedClock(long micros) { _micros = micros; }
        public long NowMicros { get { return _micros; } }
    }

    public sealed class OsRandom : IRandomSource
    {
        readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public void Fill(byte[] b, int off, int n)
        {
            byte[] drawn = new byte[n];
            lock (_rng) _rng.GetBytes(drawn);
            Buffer.BlockCopy(drawn, 0, b, off, n);
        }
    }
}
