using System;
using System.Runtime.InteropServices;

namespace NetSec.Bench;

/// <summary>
/// Picks the logical processor the paired rounds run on. On a hybrid CPU (for example a 12th-generation Intel Core with P-cores and
/// E-cores) the processors differ in speed, and the highest numbers are often the slow efficiency cores. So the pick reads the CPU sets
/// of Windows (GetSystemCpuSetInformation) and takes the first logical processor of the last core in the highest efficiency class
/// (Windows: a higher class is a faster core). The report names the processor, its core and its class.
/// </summary>
static class CoreMap
{
    public sealed class Pick
    {
        public int LogicalProcessor, Core, EfficiencyClass, HighestClass, LowestClass;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetSystemCpuSetInformation(IntPtr information, uint bufferLength, out uint returnedLength, IntPtr process, uint flags);

    /// <summary>The fastest logical processor, or null when Windows gives no CPU set information.</summary>
    public static Pick Fastest()
    {
        Pick best = null;
        int lowest = int.MaxValue;
        foreach (Pick set in Read())
        {
            lowest = Math.Min(lowest, set.EfficiencyClass);
            bool faster = best == null || set.EfficiencyClass > best.EfficiencyClass;
            bool laterCore = best != null && set.EfficiencyClass == best.EfficiencyClass && set.Core > best.Core;
            if (faster || laterCore) best = set;
        }
        if (best != null) { best.HighestClass = best.EfficiencyClass; best.LowestClass = lowest; }
        return best;
    }

    /// <summary>Every logical processor on the same physical core as <paramref name="logicalProcessor"/> (itself and its hyper-thread
    /// sibling), or just itself when Windows gives no CPU set information.</summary>
    public static int[] CorePair(int logicalProcessor)
    {
        System.Collections.Generic.List<Pick> sets = Read();
        Pick own = sets.Find(s => s.LogicalProcessor == logicalProcessor);
        if (own == null) return new[] { logicalProcessor };
        return sets.FindAll(s => s.Core == own.Core).ConvertAll(s => s.LogicalProcessor).ToArray();
    }

    static System.Collections.Generic.List<Pick> Read()
    {
        System.Collections.Generic.List<Pick> sets = new System.Collections.Generic.List<Pick>();
        GetSystemCpuSetInformation(IntPtr.Zero, 0, out uint length, IntPtr.Zero, 0);
        if (length == 0) return sets;
        IntPtr buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            if (!GetSystemCpuSetInformation(buffer, length, out length, IntPtr.Zero, 0)) return sets;
            for (int offset = 0; offset < length;)
            {
                // SYSTEM_CPU_SET_INFORMATION: Size (DWORD) at 0, LogicalProcessorIndex at 14, CoreIndex at 15, EfficiencyClass at 18.
                int size = Marshal.ReadInt32(buffer, offset);
                sets.Add(new Pick { LogicalProcessor = Marshal.ReadByte(buffer, offset + 14), Core = Marshal.ReadByte(buffer, offset + 15), EfficiencyClass = Marshal.ReadByte(buffer, offset + 18) });
                offset += size;
            }
            return sets;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
