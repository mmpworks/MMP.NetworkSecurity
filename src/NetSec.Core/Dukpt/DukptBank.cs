using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Errors;

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
            uint counter = DukptDerivation.CounterOf(ksn);

            byte[] initial = DukptDerivation.InitialKey(bdk, initialKeyId);
            byte[] derivationKey = DukptDerivation.WalkDown(initial, initialKeyId, counter, 32);
            return DukptDerivation.Working(derivationKey, initialKeyId, counter, u, t);
        }

        /// <summary>
        /// Makes the bank's checks on one PIN sale and changes nothing, so a trace can show the outcome before the rule acts.
        /// The PIN block is opened first and the ledger asked second. A block that fails gets the format code whether or not the
        /// bank has seen its KSN, so a forged block cannot ask which KSNs the bank holds. A refused sale carries no PIN and no key.
        /// </summary>
        public static PinSale CheckPinSale(byte[] bdk, KsnLedger ledger, byte[] ksn, byte[] block, string pan, DukptKeyType t)
        {
            PinSale sale = new PinSale();
            sale.Counter = DukptDerivation.CounterOf(ksn);
            byte[] key = DeriveWorkingKey(bdk, ksn, DukptKeyUsage.PinEncryption, t);
            string pin;
            if (!PinBlock.TryDecryptFormat4(key, block, pan, out pin)) sale.Code = ErrorCodes.DukptPinBlockFormat;
            else sale.Code = ledger.RefusalFor(ksn);
            if (sale.Code != null)
            {
                Array.Clear(key, 0, key.Length);
                return sale;
            }
            sale.Key = key;
            sale.Pin = pin;
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

    /// <summary>
    /// The KSNs of the sales a bank has accepted, and a high-water mark per device. A KSN names its device by its first 8 bytes
    /// (the initial key ID) and its counter by the last 4. A reader never reuses a counter and only counts up, so the bank refuses
    /// an exact repeat (a replayed sale) and also any counter at or below the highest one it accepted from that device, seen or
    /// not (a recorded sale held back and sent late). A gap ahead is accepted: a sale that never reached the bank leaves one.
    /// Record only a sale that passed every check, so a forged message cannot raise the mark.
    /// </summary>
    public sealed class KsnLedger
    {
        const int InitialKeyIdSize = 8;
        readonly Dictionary<string, bool> _seen = new Dictionary<string, bool>();
        readonly Dictionary<string, uint> _highest = new Dictionary<string, uint>();

        /// <summary>True for a KSN this ledger recorded. The exact-repeat test only; <see cref="RefusalFor"/> also applies the mark.</summary>
        public bool Contains(byte[] ksn) { return _seen.ContainsKey(Hex.Encode(ksn)); }

        /// <summary>Null when the bank may accept this KSN. DUKPT_KSN_REPLAY for an exact repeat. DUKPT_KSN_STALE for a counter at or below the device's mark.</summary>
        public string RefusalFor(byte[] ksn)
        {
            if (Contains(ksn)) return ErrorCodes.DukptKsnReplay;
            uint top;
            if (_highest.TryGetValue(DeviceOf(ksn), out top) && DukptDerivation.CounterOf(ksn) <= top) return ErrorCodes.DukptKsnStale;
            return null;
        }

        public void Record(byte[] ksn)
        {
            uint counter = DukptDerivation.CounterOf(ksn);
            _seen[Hex.Encode(ksn)] = true;
            string device = DeviceOf(ksn);
            uint top;
            if (!_highest.TryGetValue(device, out top) || counter > top) _highest[device] = counter;
        }

        /// <summary>True once the ledger accepted a KSN from the device with this 8-byte initial key ID.</summary>
        public bool HasMark(byte[] initialKeyId) { return _highest.ContainsKey(KeyIdHex(initialKeyId)); }

        /// <summary>The highest counter accepted from the device. Zero when <see cref="HasMark"/> is false.</summary>
        public uint HighestCounter(byte[] initialKeyId)
        {
            uint top;
            return _highest.TryGetValue(KeyIdHex(initialKeyId), out top) ? top : 0;
        }

        static string DeviceOf(byte[] ksn)
        {
            byte[] id = new byte[InitialKeyIdSize];
            Buffer.BlockCopy(ksn, 0, id, 0, InitialKeyIdSize);
            return Hex.Encode(id);
        }

        static string KeyIdHex(byte[] initialKeyId)
        {
            DukptDerivation.RequireInitialKeyId(initialKeyId);
            return Hex.Encode(initialKeyId);
        }
    }
}
