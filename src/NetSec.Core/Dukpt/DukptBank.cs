using System;
using System.Collections.Generic;
using NetSec.Bytes;

namespace NetSec.Dukpt
{
    /// <summary>
    /// The bank side. It keeps no per-reader key: it holds the base key and derives every key again from the KSN.
    /// So its work for one sale grows with the number of 1 bits in the counter and stays small for every sale.
    /// </summary>
    public static class DukptBank
    {
        public static byte[] DeriveInitialKey(byte[] bdk, byte[] initialKeyId)
        {
            DukptDerivation.RequireInitialKeyId(initialKeyId);
            return DukptDerivation.InitialKey(bdk, initialKeyId);
        }

        public static byte[] DeriveWorkingKey(byte[] bdk, byte[] ksn, DukptKeyUsage u, DukptKeyType t)
        {
            if (ksn == null) throw new ArgumentNullException("ksn");
            if (ksn.Length != DukptDerivation.KsnSize) throw new ArgumentException("A KSN holds 12 bytes.", "ksn");
            byte[] initialKeyId = new byte[DukptDerivation.InitialKeyIdSize];
            Buffer.BlockCopy(ksn, 0, initialKeyId, 0, initialKeyId.Length);
            uint counter = ((uint)ksn[8] << 24) | ((uint)ksn[9] << 16) | ((uint)ksn[10] << 8) | ksn[11];

            byte[] initial = DukptDerivation.InitialKey(bdk, initialKeyId);
            byte[] derivationKey = DukptDerivation.WalkDown(initial, initialKeyId, counter, 32);
            return DukptDerivation.Working(derivationKey, initialKeyId, counter, u, t);
        }
    }

    /// <summary>The KSNs a bank has seen. A repeat means a replayed sale.</summary>
    public sealed class KsnLedger
    {
        readonly Dictionary<string, bool> _seen = new Dictionary<string, bool>();

        /// <summary>True when this KSN is new. False when it was seen before.</summary>
        public bool TryRecord(byte[] ksn)
        {
            string key = Hex.Encode(ksn);
            if (_seen.ContainsKey(key)) return false;
            _seen.Add(key, true);
            return true;
        }
    }
}
