using System;
using System.Globalization;
using System.Text;

namespace NetSec.Native
{
    /// <summary>Writes the numbers the two histograms show as JSON text. A timing event carries this text in Plain, because a timing event has no wire bytes.</summary>
    public static class TimingReport
    {
        public static string Case(TimingCase c)
        {
            double[] sorted = (double[])c.Ticks.Clone();
            Array.Sort(sorted);
            double p99 = sorted[(int)(sorted.Length * 0.99)];
            StringBuilder s = new StringBuilder("{");
            s.Append("\"compare\":\"").Append(c.Compare).Append('"');
            s.Append(",\"bufferSize\":").Append(c.BufferSize);
            s.Append(",\"diffPosition\":").Append(c.DiffPosition);
            s.Append(",\"samples\":").Append(c.Ticks.Length);
            s.Append(",\"tickFrequency\":").Append(c.TickFrequency);
            s.Append(",\"meanNs\":").Append(Number(Nanos(TimingJudge.Mean(c.Ticks), c.TickFrequency)));
            s.Append(",\"medianNs\":").Append(Number(Nanos(sorted[sorted.Length / 2], c.TickFrequency)));
            s.Append(",\"p99Ns\":").Append(Number(Nanos(p99, c.TickFrequency)));
            s.Append(",\"histogram\":[");
            int above = AppendBins(s, sorted, p99, c.TickFrequency);
            s.Append("],\"aboveP99\":").Append(above);
            return s.Append('}').ToString();
        }

        /// <summary>One bin for each tick value up to the 99th percentile. Returns the count of slower samples, so a scheduler pause cannot stretch the chart.</summary>
        static int AppendBins(StringBuilder s, double[] sorted, double p99, uint frequency)
        {
            int i = 0, bins = 0;
            while (i < sorted.Length && sorted[i] <= p99)
            {
                int start = i;
                while (i < sorted.Length && sorted[i] == sorted[start]) i++;
                if (bins++ > 0) s.Append(',');
                s.Append("{\"ns\":").Append(Number(Nanos(sorted[start], frequency))).Append(",\"count\":").Append(i - start).Append('}');
            }
            return sorted.Length - i;
        }

        /// <summary>controlT is the constant-time compare against itself: two cases with one difference position. Its |t| is this machine's noise floor for one run.</summary>
        public static string Verdict(TimingVerdict verdict, double controlT, double managedT)
        {
            StringBuilder s = new StringBuilder("{");
            s.Append("\"leakyT\":").Append(Number(verdict.LeakyT));
            s.Append(",\"constantTimeT\":").Append(Number(verdict.ConstantT));
            s.Append(",\"controlT\":").Append(Number(controlT));
            s.Append(",\"managedT\":").Append(Number(managedT));
            s.Append(",\"minT\":").Append(Number(verdict.Threshold));
            s.Append(",\"factor\":").Append(Number(TimingJudge.Factor));
            s.Append(",\"constantTimeOverMinT\":").Append(Math.Abs(verdict.ConstantT) > verdict.Threshold ? "true" : "false");
            s.Append(",\"separated\":").Append(verdict.Separated ? "true" : "false");
            return s.Append('}').ToString();
        }

        public static string Guess(GuessResult g)
        {
            StringBuilder s = new StringBuilder("{");
            s.Append("\"compare\":\"").Append(g.Compare).Append('"');
            s.Append(",\"correctBytes\":").Append(g.CorrectBytes);
            s.Append(",\"totalBytes\":").Append(g.Recovered.Length);
            s.Append(",\"blockBytes\":").Append(TimingGuess.BlockBytes);
            s.Append(",\"samplesPerGuess\":").Append(TimingGuess.SamplesPerGuess);
            s.Append(",\"bytes\":[");
            for (int i = 0; i < g.Recovered.Length; i++)
            {
                if (i > 0) s.Append(',');
                s.Append("{\"value\":").Append(g.Recovered[i]).Append(",\"marginNs\":").Append(Number(Nanos(g.Margins[i], g.TickFrequency))).Append('}');
            }
            return s.Append("]}").ToString();
        }

        /// <summary>The run's machine, which the lab must show beside its numbers. It holds no name of a person or a host.</summary>
        public static string Machine()
        {
            StringBuilder s = new StringBuilder("{");
            s.Append("\"clr\":\"").Append(Environment.Version.ToString()).Append('"');
            s.Append(",\"pointerBytes\":").Append(IntPtr.Size);
            return s.Append('}').ToString();
        }

        static double Nanos(double ticks, uint frequency)
        {
            return frequency == 0 ? 0 : ticks * 1000000000.0 / frequency;
        }

        static string Number(double value)
        {
            if (double.IsInfinity(value) || double.IsNaN(value)) return "null";
            return value.ToString("0.###", CultureInfo.InvariantCulture);
        }
    }
}
