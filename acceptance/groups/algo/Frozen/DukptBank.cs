// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Dukpt/DukptBank.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 d155c0f47d7c4c6d12d662ad589ec94b70ebabb8e66de6ab8e4715ec46da4254). Do not edit.
using System;
using System.Collections.Generic;
using Acceptance.Frozen.Bytes;
using Acceptance.Frozen.Errors;

namespace Acceptance.Frozen.Dukpt
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
            uint counter = DukptDerivation.CounterOf(ksn);

            byte[] initial = DukptDerivation.InitialKey(bdk, initialKeyId);
            byte[] derivationKey = DukptDerivation.WalkDown(initial, initialKeyId, counter, 32);
            return DukptDerivation.Working(derivationKey, initialKeyId, counter, u, t);
        }

        /// <summary>Makes the bank's checks on one PIN sale and changes nothing, so a trace can show the outcome before the rule acts.</summary>
        public static PinSale CheckPinSale(byte[] bdk, KsnLedger ledger, byte[] ksn, byte[] block, string pan, DukptKeyType t)
        {
            PinSale sale = new PinSale();
            sale.Counter = DukptDerivation.CounterOf(ksn);
            if (ledger.Contains(ksn))
            {
                sale.Code = ErrorCodes.DukptKsnReplay;
                return sale;
            }
            sale.Key = DeriveWorkingKey(bdk, ksn, DukptKeyUsage.PinEncryption, t);
            if (!PinBlock.TryDecryptFormat4(sale.Key, block, pan, out sale.Pin)) sale.Code = ErrorCodes.DukptPinBlockFormat;
            return sale;
        }

        /// <summary>
        /// Checks one PIN sale and records its KSN only if the sale passes. A forged block under the next KSN then leaves that KSN free for the real sale.
        /// A caller with more checks, such as a MAC, makes them before this call.
        /// </summary>
        public static PinSale OpenPinSale(byte[] bdk, KsnLedger ledger, byte[] ksn, byte[] block, string pan, DukptKeyType t)
        {
            PinSale sale = CheckPinSale(bdk, ledger, ksn, block, pan, t);
            if (sale.Code == null) ledger.Record(ksn);
            return sale;
        }
    }

    /// <summary>The outcome of the bank's checks on one PIN sale. Code is null when the sale passed.</summary>
    public sealed class PinSale
    {
        public string Code;
        public uint Counter;
        public byte[] Key;
        public string Pin;
    }

    /// <summary>The KSNs of the sales a bank has accepted. A repeat means a replayed sale.</summary>
    public sealed class KsnLedger
    {
        readonly Dictionary<string, bool> _seen = new Dictionary<string, bool>();

        public bool Contains(byte[] ksn) { return _seen.ContainsKey(Hex.Encode(ksn)); }

        public void Record(byte[] ksn) { _seen[Hex.Encode(ksn)] = true; }
    }
}
