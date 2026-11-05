using System;
using System.Collections.Generic;
using System.Diagnostics;
using NetSec.Errors;

namespace NetSec.Native
{
    /// <summary>The ticks of one compare on one pair of buffers.</summary>
    public sealed class TimingCase
    {
        public readonly string Compare;
        public readonly int BufferSize;
        public readonly int DiffPosition;
        public readonly uint TickFrequency;
        public readonly double[] Ticks;

        public TimingCase(string compare, int bufferSize, int diffPosition, uint tickFrequency, double[] ticks)
        {
            Compare = compare; BufferSize = bufferSize; DiffPosition = diffPosition; TickFrequency = tickFrequency; Ticks = ticks;
        }
    }

    /// <summary>T is the Welch t of two cases. Separates says |T| passes TimingJudge.MinT.</summary>
    public sealed class TimingVerdict
    {
        public readonly double T;
        public readonly bool Separates;

        public TimingVerdict(double t, bool separates) { T = t; Separates = separates; }
    }

    /// <summary>
    /// The measuring side. The buffers come from fixed bytes, so a case differs from another case only by DiffPosition. Sample takes one whole
    /// case at a time, so two cases taken in a row also differ by any drift of the machine, such as a move to a slower core. Interleaved takes
    /// short turns between its two cases, so drift lands on both. A verdict on "no leak" needs Interleaved.
    /// </summary>
    public static class TimingLab
    {
        public const string LeakyName = "leaky";
        public const string ConstantTimeName = "constant-time";
        public const string ManagedName = "managed";

        const int BufferSeed = 12345;
        const int TurnSamples = 100;

        public static TimingCase Sample(CompareKind kind, int bufferSize, int samples, int diffPosition)
        {
            byte[] a = Buffer(bufferSize);
            return Time(kind, a, Flipped(a, diffPosition), samples, diffPosition);
        }

        /// <summary>Times one native compare on the caller's two buffers.</summary>
        public static TimingCase Time(CompareKind kind, byte[] a, byte[] b, int samples, int diffPosition)
        {
            if (a == null) throw new ArgumentNullException("a");
            if (b == null) throw new ArgumentNullException("b");
            if (a.Length != b.Length) throw new ArgumentException("the buffers must have one length");
            if (samples < 2) throw new ArgumentOutOfRangeException("samples");
            uint[] ticks = new uint[samples];
            uint frequency = 0;
            int code = NativeLoad.Run<int>(delegate
            {
                return NetSecCtNative.nsct_sample(kind == CompareKind.Leaky ? 0 : 1, a, b, (uint)a.Length, ticks, (uint)samples, out frequency);
            });
            if (code != NetSecCtNative.Ok) throw new NetSecException(NetSecError.Of(ErrorCodes.NativeSampleFailed, "nsct_sample returned " + code));
            double[] values = new double[samples];
            for (int i = 0; i < samples; i++) values[i] = ticks[i];
            return new TimingCase(kind == CompareKind.Leaky ? LeakyName : ConstantTimeName, a.Length, diffPosition, frequency, values);
        }

        /// <summary>Two cases, in short turns. Returns the case for firstPosition, then the case for secondPosition.</summary>
        public static TimingCase[] Interleaved(CompareKind kind, int bufferSize, int samples, int firstPosition, int secondPosition)
        {
            byte[] a = Buffer(bufferSize);
            return Turns(a, samples, firstPosition, secondPosition, delegate(byte[] b, int count, int position) { return Time(kind, a, b, count, position); });
        }

        /// <summary>The managed compare, in short turns. Each sample carries the clock call and any JIT or collector pause. Managed code has no constant-time guarantee.</summary>
        public static TimingCase[] InterleavedManaged(int bufferSize, int samples, int firstPosition, int secondPosition)
        {
            byte[] a = Buffer(bufferSize);
            return Turns(a, samples, firstPosition, secondPosition, delegate(byte[] b, int count, int position) { return TimeManaged(a, b, count, position); });
        }

        static TimingCase TimeManaged(byte[] a, byte[] b, int samples, int diffPosition)
        {
            double[] values = new double[samples];
            bool sink = false;
            for (int i = 0; i < samples; i++)
            {
                long start = Stopwatch.GetTimestamp();
                sink ^= ManagedCompare.FixedShape(a, b);
                values[i] = Stopwatch.GetTimestamp() - start;
            }
            GC.KeepAlive(sink);
            return new TimingCase(ManagedName, a.Length, diffPosition, (uint)Stopwatch.Frequency, values);
        }

        static TimingCase[] Turns(byte[] a, int samples, int firstPosition, int secondPosition, Func<byte[], int, int, TimingCase> time)
        {
            if (samples < 2) throw new ArgumentOutOfRangeException("samples");
            byte[] first = Flipped(a, firstPosition), second = Flipped(a, secondPosition);
            double[] firstTicks = new double[samples], secondTicks = new double[samples];
            uint frequency = 0;
            string compare = null;
            for (int done = 0; done < samples; done += TurnSamples)
            {
                int count = Math.Min(TurnSamples, samples - done);
                TimingCase one = time(first, count, firstPosition), two = time(second, count, secondPosition);
                one.Ticks.CopyTo(firstTicks, done);
                two.Ticks.CopyTo(secondTicks, done);
                frequency = one.TickFrequency;
                compare = one.Compare;
            }
            return new TimingCase[]
            {
                new TimingCase(compare, a.Length, firstPosition, frequency, firstTicks),
                new TimingCase(compare, a.Length, secondPosition, frequency, secondTicks),
            };
        }

        static byte[] Buffer(int size)
        {
            if (size < 1) throw new ArgumentOutOfRangeException("size");
            return LabBytes.Fill(size, BufferSeed);
        }

        static byte[] Flipped(byte[] a, int position)
        {
            if (position < 0 || position >= a.Length) throw new ArgumentOutOfRangeException("position");
            byte[] b = (byte[])a.Clone();
            b[position] ^= 0x01;
            return b;
        }
    }

    /// <summary>Teaching bytes from a seed, so two runs with one seed agree. This is no source of secrets.</summary>
    public static class LabBytes
    {
        public static byte[] Fill(int size, int seed)
        {
            byte[] bytes = new byte[size];
            uint state = (uint)seed;
            for (int i = 0; i < size; i++)
            {
                state = unchecked(state * 1103515245u + 12345u);
                bytes[i] = (byte)(state >> 16);
            }
            return bytes;
        }
    }

    /// <summary>The pure judge. It reads ticks and returns a verdict, and it touches no clock.</summary>
    public static class TimingJudge
    {
        /// <summary>The stated threshold (program-design.md section 7): the leaky compare passes at |t| above MinT and above Factor times the constant-time |t|.</summary>
        public const double MinT = 4.5;
        public const double Factor = 3.0;

        const double CropPercentile = 0.99;

        public static TimingVerdict Judge(TimingCase firstByteDiff, TimingCase lastByteDiff)
        {
            if (firstByteDiff == null) throw new ArgumentNullException("firstByteDiff");
            if (lastByteDiff == null) throw new ArgumentNullException("lastByteDiff");
            double t = Welch(firstByteDiff.Ticks, lastByteDiff.Ticks);
            return new TimingVerdict(t, Math.Abs(t) > MinT);
        }

        public static bool Separated(TimingVerdict leaky, TimingVerdict constantTime)
        {
            return leaky.Separates && Math.Abs(leaky.T) > Factor * Math.Abs(constantTime.T);
        }

        /// <summary>Welch t. Both sets lose every sample above the 99th percentile of the two sets together, because scheduler pauses would rule the raw number.</summary>
        public static double Welch(double[] x, double[] y)
        {
            if (x.Length < 2 || y.Length < 2) throw new ArgumentException("Welch t needs two samples per set");
            double[] all = new double[x.Length + y.Length];
            x.CopyTo(all, 0);
            y.CopyTo(all, x.Length);
            Array.Sort(all);
            double cut = all[(int)(all.Length * CropPercentile)];
            double[] keptX = AtOrBelow(x, cut), keptY = AtOrBelow(y, cut);
            double meanX = Mean(keptX), meanY = Mean(keptY);
            double error = Math.Sqrt(Variance(keptX, meanX) / keptX.Length + Variance(keptY, meanY) / keptY.Length);
            if (error == 0) return meanX == meanY ? 0 : double.PositiveInfinity;
            return (meanX - meanY) / error;
        }

        public static double Mean(double[] values)
        {
            double sum = 0;
            for (int i = 0; i < values.Length; i++) sum += values[i];
            return sum / values.Length;
        }

        static double Variance(double[] values, double mean)
        {
            if (values.Length < 2) return 0;
            double sum = 0;
            for (int i = 0; i < values.Length; i++)
            {
                double d = values[i] - mean;
                sum += d * d;
            }
            return sum / (values.Length - 1);
        }

        static double[] AtOrBelow(double[] values, double cut)
        {
            List<double> kept = new List<double>(values.Length);
            for (int i = 0; i < values.Length; i++) if (values[i] <= cut) kept.Add(values[i]);
            return kept.ToArray();
        }
    }

    /// <summary>What one guess loop found. Recovered holds the attacker's best guess for each secret byte.</summary>
    public sealed class GuessResult
    {
        public readonly string Compare;
        public readonly byte[] Recovered;
        public readonly double[] Margins;
        public readonly uint TickFrequency;
        public readonly int CorrectBytes;

        public GuessResult(string compare, byte[] recovered, double[] margins, uint tickFrequency, int correctBytes)
        {
            Compare = compare; Recovered = recovered; Margins = margins; TickFrequency = tickFrequency; CorrectBytes = correctBytes;
        }

        public bool RecoveredAll { get { return CorrectBytes == Recovered.Length; } }
    }

    /// <summary>
    /// The attacker's loop. One loop pass per byte is too small for a 100 ns clock, so the lab stretches each secret byte to BlockBytes
    /// bytes. One right guess then moves the time by several ticks. This stretch is a teaching aid. A real attacker pays with more samples.
    /// Each round tries every candidate once, so drift of the machine lands on all candidates.
    /// </summary>
    public static class TimingGuess
    {
        public const int BlockBytes = 1024;
        public const int Rounds = 50;
        public const int SamplesPerRound = 10;
        public const int SamplesPerGuess = Rounds * SamplesPerRound;

        /// <summary>The target's buffer: each secret byte repeated BlockBytes times.</summary>
        public static byte[] Stretch(byte[] secret)
        {
            byte[] target = new byte[secret.Length * BlockBytes];
            for (int i = 0; i < target.Length; i++) target[i] = secret[i / BlockBytes];
            return target;
        }

        /// <summary>Recovers the secret one byte at a time. The attacker reads only the time of each compare. The target buffer stays the compare's other operand.</summary>
        public static GuessResult Recover(CompareKind kind, byte[] secret)
        {
            byte[] target = Stretch(secret);
            byte[] guess = new byte[target.Length];
            byte[] recovered = new byte[secret.Length];
            double[] margins = new double[secret.Length];
            uint frequency = 0;
            int correct = 0;
            for (int position = 0; position < secret.Length; position++)
            {
                double[][] ticks = new double[256][];
                for (int candidate = 0; candidate < 256; candidate++) ticks[candidate] = new double[SamplesPerGuess];
                for (int round = 0; round < Rounds; round++)
                {
                    for (int candidate = 0; candidate < 256; candidate++)
                    {
                        SetBlock(guess, position, (byte)candidate);
                        TimingCase timed = TimingLab.Time(kind, target, guess, SamplesPerRound, position * BlockBytes);
                        frequency = timed.TickFrequency;
                        timed.Ticks.CopyTo(ticks[candidate], round * SamplesPerRound);
                    }
                }
                double[] scores = new double[256];
                for (int candidate = 0; candidate < 256; candidate++) scores[candidate] = Score(ticks[candidate]);
                int best = BestGuess(scores);
                recovered[position] = (byte)best;
                margins[position] = Margin(scores, best);
                SetBlock(guess, position, (byte)best);
                if (recovered[position] == secret[position]) correct++;
            }
            return new GuessResult(kind == CompareKind.Leaky ? TimingLab.LeakyName : TimingLab.ConstantTimeName, recovered, margins, frequency, correct);
        }

        static void SetBlock(byte[] guess, int position, byte value)
        {
            for (int i = 0; i < BlockBytes; i++) guess[position * BlockBytes + i] = value;
        }

        /// <summary>The mean of the fastest 90 percent. A scheduler pause only adds time, so the slow tail holds no signal.</summary>
        public static double Score(double[] ticks)
        {
            double[] sorted = (double[])ticks.Clone();
            Array.Sort(sorted);
            int keep = Math.Max(1, sorted.Length * 9 / 10);
            double sum = 0;
            for (int i = 0; i < keep; i++) sum += sorted[i];
            return sum / keep;
        }

        /// <summary>The slowest guess went furthest through the early-return loop. The lowest index wins a tie.</summary>
        public static int BestGuess(double[] scores)
        {
            int best = 0;
            for (int i = 1; i < scores.Length; i++) if (scores[i] > scores[best]) best = i;
            return best;
        }

        static double Margin(double[] scores, int best)
        {
            double second = double.NegativeInfinity;
            for (int i = 0; i < scores.Length; i++) if (i != best && scores[i] > second) second = scores[i];
            return scores[best] - second;
        }
    }
}
