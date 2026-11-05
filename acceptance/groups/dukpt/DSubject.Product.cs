using System;
using System.Collections.Generic;
using NetSec.Dukpt;

namespace Acceptance
{
    sealed class ProductPad : PadSession
    {
        readonly DukptPinPad _pad;
        public ProductPad(DukptPinPad pad) { _pad = pad; }
        public override uint Counter { get { return _pad.Counter; } }
        public override uint Next() { return _pad.NextTransaction(); }
        public override byte[] WorkingKey(int use, int keyBytes) { return _pad.WorkingKey((DukptKeyUse)use, keyBytes); }
        public override byte[][] State() { return _pad.StateRegisters(); }
    }

    /// <summary>Product mapping for A3 (program-design sections 2 and 6, Dukpt folder). ASSUMED names are listed in CONTRACT.md.</summary>
    static class DSubject
    {
        public const string Name = "NetSec.Core";

        public static byte[] InitialKey(byte[] bdk, byte[] ikid) { return new DukptBank(bdk).InitialKey(ikid); }
        public static byte[] DerivationKey(byte[] bdk, byte[] ikid, uint counter) { return new DukptBank(bdk).DerivationKey(ikid, counter); }
        public static byte[] WorkingKey(byte[] bdk, byte[] ikid, uint counter, int use, int keyBytes)
        {
            return new DukptBank(bdk).WorkingKey(ikid, counter, (DukptKeyUse)use, keyBytes);
        }

        public static PadSession NewPad(byte[] bdk, byte[] ikid)
        {
            DukptBank bank = new DukptBank(bdk);
            return new ProductPad(new DukptPinPad(bank.InitialKey(ikid), ikid));
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
