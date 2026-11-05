using System;
using NetSec.Io;

namespace NetSec.Bridge
{
    /// <summary>What a device may do, as data. CeProfile holds the budget of ce-budget.md and Steve's CE fact: SSH and TLS 1.1 only.</summary>
    public sealed class DeviceProfile
    {
        public static readonly DeviceProfile Ce = new DeviceProfile("CeProfile", 25, 64 * 1024 * 1024, 2, new WireProtocol[] { WireProtocol.Ssh, WireProtocol.Tls11 });
        public static readonly DeviceProfile Modern = new DeviceProfile("ModernProfile", 0, 0, 0, new WireProtocol[] { WireProtocol.Tls13, WireProtocol.Tls11, WireProtocol.Ssh });

        public readonly string Name;
        public readonly int PoolThreads;
        public readonly long RamBytes;
        public readonly int DedicatedThreads;
        readonly WireProtocol[] _transports;

        DeviceProfile(string name, int poolThreads, long ramBytes, int dedicatedThreads, WireProtocol[] transports)
        {
            Name = name; PoolThreads = poolThreads; RamBytes = ramBytes; DedicatedThreads = dedicatedThreads; _transports = transports;
        }

        public bool Allows(WireProtocol protocol)
        {
            return Array.IndexOf(_transports, protocol) >= 0;
        }
    }
}
