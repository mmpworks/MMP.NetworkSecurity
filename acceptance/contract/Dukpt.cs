// CONTRACT STUB, Dukpt folder. The design names DukptPinPad, DukptBank and PinBlock (program-design.md section 1)
// and gives no members. Every member below is ASSUMED. CONTRACT.md lists them with the clause that needs each one.
#pragma warning disable CS0169, CS0649, CS8618
using System;

namespace NetSec.Dukpt
{
    /// <summary>Key usage codes of ANSI X9.24-3-2017 (values print in the derivation data of the test vectors).</summary>
    public enum DukptKeyUse : ushort
    {
        KeyEncryption = 0x0002,
        PinEncryption = 0x1000,
        MacGeneration = 0x2000,
        MacVerification = 0x2001,
        MacBothWays = 0x2002,
        DataEncrypt = 0x3000,
        DataDecrypt = 0x3001,
        DataBothWays = 0x3002,
        DerivationKey = 0x8000,
        InitialKey = 0x8001
    }

    /// <summary>Bank side (host algorithm). Holds the base derivation key and can derive any transaction's keys.</summary>
    public sealed class DukptBank
    {
        public DukptBank(byte[] bdk) { throw new NotImplementedException(); }                                       // ASSUMED: 16 or 32 bytes
        public byte[] InitialKey(byte[] initialKeyId) { throw new NotImplementedException(); }                        // ASSUMED: 8-byte id -> 16 or 32 bytes
        public byte[] DerivationKey(byte[] initialKeyId, uint counter) { throw new NotImplementedException(); }       // ASSUMED: the "Derivation Key" line of the vectors
        public byte[] WorkingKey(byte[] initialKeyId, uint counter, DukptKeyUse use, int keyBytes) { throw new NotImplementedException(); }   // ASSUMED
    }

    /// <summary>PIN-pad side (terminal algorithm). Loads the initial key, then keeps only future-key registers.</summary>
    public sealed class DukptPinPad
    {
        public DukptPinPad(byte[] initialKey, byte[] initialKeyId) { throw new NotImplementedException(); }          // ASSUMED: erases initialKey's copy after loading
        public uint Counter { get { throw new NotImplementedException(); } }                                           // ASSUMED
        public uint NextTransaction() { throw new NotImplementedException(); }                                         // ASSUMED: advances, returns the new counter
        public byte[] WorkingKey(DukptKeyUse use, int keyBytes) { throw new NotImplementedException(); }              // ASSUMED: for the current transaction
        public byte[][] StateRegisters() { throw new NotImplementedException(); }                                      // ASSUMED: every key register held now (erasure check)
    }

    public static class PinBlock
    {
        /// <summary>ISO 9564 format 4, AES. pinKey is the PIN encryption working key. random8 fills the second half of the PIN field.</summary>
        public static byte[] EncryptFormat4(byte[] pinKey, string pin, string pan, byte[] random8) { throw new NotImplementedException(); }    // ASSUMED
        public static bool TryDecryptFormat4(byte[] pinKey, byte[] block, string pan, out string pin) { throw new NotImplementedException(); } // ASSUMED
    }
}
