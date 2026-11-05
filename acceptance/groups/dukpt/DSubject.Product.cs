using System;
using System.Collections.Generic;
using NetSec.Dukpt;

namespace Acceptance
{
    sealed class ProductPad : PadSession
    {
        readonly DukptPinPad _pad;
        public ProductPad(DukptPinPad pad) { _pad = pad; }

        public override PadUse Next(int use, int keyBytes)
        {
            DukptUse u = _pad.Next((DukptKeyUsage)use, DSubject.TypeOf(keyBytes));
            byte[] ksn = u.Ksn;
            uint counter = ksn == null || ksn.Length != 12 ? 0 : (uint)((ksn[8] << 24) | (ksn[9] << 16) | (ksn[10] << 8) | ksn[11]);
            return new PadUse { Counter = counter, Ksn = ksn, Key = u.Key };
        }

        public override byte[][] State() { return _pad.HeldKeys(); }
    }

    /// <summary>Product mapping for A3 (design section 11, "DUKPT": DukptPinPad, DukptBank). ASSUMED names are listed in CONTRACT.md.</summary>
    static class DSubject
    {
        public const string Name = "NetSec.Core";

        public static DukptKeyType TypeOf(int keyBytes) { return keyBytes == 16 ? DukptKeyType.Aes128 : keyBytes == 24 ? DukptKeyType.Aes192 : DukptKeyType.Aes256; }

        public static byte[] Ksn(byte[] ikid, uint counter)
        {
            byte[] k = new byte[12];
            Array.Copy(ikid, 0, k, 0, 8);
            k[8] = (byte)(counter >> 24); k[9] = (byte)(counter >> 16); k[10] = (byte)(counter >> 8); k[11] = (byte)counter;
            return k;
        }

        public static byte[] InitialKey(byte[] bdk, byte[] ikid) { return DukptBank.DeriveInitialKey(bdk, ikid); }

        /// <summary>Section 11 exposes no derivation-key seam. The working-key checks cover the same path, so this returns null and the clause skips it.</summary>
        public static byte[] DerivationKey(byte[] bdk, byte[] ikid, uint counter) { return null; }

        public static byte[] WorkingKey(byte[] bdk, byte[] ikid, uint counter, int use, int keyBytes)
        {
            return DukptBank.DeriveWorkingKey(bdk, Ksn(ikid, counter), (DukptKeyUsage)use, TypeOf(keyBytes));
        }

        public static PadSession NewPad(byte[] bdk, byte[] ikid)
        {
            return new ProductPad(new DukptPinPad(DukptBank.DeriveInitialKey(bdk, ikid), ikid));
        }

        public static byte[] PinBlockEncrypt(byte[] pinKey, string pin, string pan, byte[] random8) { return PinBlock.EncryptFormat4(pinKey, pin, pan, random8); }

        public static string PinBlockDecrypt(byte[] pinKey, byte[] block, string pan)
        {
            string pin;
            if (!PinBlock.TryDecryptFormat4(pinKey, block, pan, out pin)) return null;
            return pin;
        }
    }
}
