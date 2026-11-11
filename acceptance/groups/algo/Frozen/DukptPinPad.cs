// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Dukpt/DukptPinPad.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 119b872210bbb371c695966b9d9310f047fd3e8cca2a50198579f39bfd898676). Do not edit.
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Acceptance.Frozen.Errors;

[assembly: InternalsVisibleTo("NetSec.Tests")]

namespace Acceptance.Frozen.Dukpt
{
    public sealed class DukptUse
    {
        public byte[] Ksn;
        public byte[] Key;
    }

    /// <summary>
    /// The reader side of AES DUKPT. It holds one register per counter bit and never holds a key it has used.
    ///
    /// How the registers work. Register b holds the derivation key for one counter value: the value whose lowest 1 bit is b. A counter's
    /// key comes from the register of its lowest 1 bit. Before that register is erased, it fills every lower register with a child key,
    /// each child adding one lower bit to the counter. A child key cannot give its parent, so an erased key cannot come back from the
    /// registers that remain. The bank needs no registers: it walks the counter's 1 bits down from the base key.
    ///
    /// Erasing clears the register's array in place. A managed heap can keep copies: the collector can move an array and leave the old bytes
    /// behind, and each AesKey holds a key schedule nobody clears. So erasing a register does not prove the bytes are gone from memory.
    /// The registers are mutable on purpose, because erasing them is the point. Not thread safe: one reader, one caller.
    /// </summary>
    public sealed class DukptPinPad
    {
        const int RegisterCount = 32;

        /// <summary>The limit on 1 bits in a counter this pad issues, which caps the bank's work for a reader built on this class. Counters past it are skipped. The bank itself derives for any KSN. The value 16 is recalled from X9.24-3, which is paid. The free vectors do not state it.</summary>
        const int MaxOneBits = 16;

        readonly byte[] _initialKeyId;
        readonly byte[][] _registers = new byte[RegisterCount][];
        readonly uint[] _registerCounters = new uint[RegisterCount];
        ulong _nextCounter = 1;

        /// <summary>Loads the initial key into the registers. The pad keeps no copy of it. The caller erases its own array.</summary>
        public DukptPinPad(byte[] initialKey, byte[] initialKeyId)
        {
            DukptDerivation.TypeOf(initialKey);
            DukptDerivation.RequireInitialKeyId(initialKeyId);
            _initialKeyId = (byte[])initialKeyId.Clone();
            FillRegistersBelow(RegisterCount, initialKey, 0);
        }

        /// <summary>A pad part way through its life: one register, for the given counter. The end of the counter range takes about 2^31 sales to reach, so a test starts here.</summary>
        internal DukptPinPad(byte[] derivationKey, byte[] initialKeyId, uint counter)
        {
            DukptDerivation.TypeOf(derivationKey);
            DukptDerivation.RequireInitialKeyId(initialKeyId);
            _initialKeyId = (byte[])initialKeyId.Clone();
            int bit = LowestOneBit(counter);
            _registers[bit] = (byte[])derivationKey.Clone();
            _registerCounters[bit] = counter;
            _nextCounter = counter;
        }

        /// <summary>The counter value the next key request uses.</summary>
        public ulong NextCounter { get { return _nextCounter; } }

        /// <summary>The number of key registers held now. It copies no key.</summary>
        public int HeldCount
        {
            get
            {
                int held = 0;
                for (int i = 0; i < RegisterCount; i++)
                    if (_registers[i] != null) held++;
                return held;
            }
        }

        /// <summary>Gives the working key for the next counter, then erases the derivation key it came from. Each call uses a new counter.</summary>
        public DukptUse Next(DukptKeyUsage u, DukptKeyType t)
        {
            return NextTogether(new DukptKeyUsage[] { u }, t)[0];
        }

        /// <summary>Gives one working key per usage, all from the next counter, then erases the derivation key they came from. One sale needs a PIN key and a MAC key under one KSN.</summary>
        public DukptUse[] NextTogether(DukptKeyUsage[] usages, DukptKeyType t)
        {
            if (usages == null) throw new ArgumentNullException("usages");
            if (_nextCounter > uint.MaxValue)
                throw new NetSecException(NetSecError.Of(ErrorCodes.DukptCounterExhausted, "This reader has used every counter value. It must get a new initial key."));

            uint counter = (uint)_nextCounter;
            int lowestBit = LowestOneBit(counter);
            byte[] derivationKey = _registers[lowestBit];

            DukptUse[] uses = new DukptUse[usages.Length];
            for (int i = 0; i < usages.Length; i++)
            {
                uses[i] = new DukptUse();
                uses[i].Ksn = DukptDerivation.Ksn(_initialKeyId, counter);
                uses[i].Key = DukptDerivation.Working(derivationKey, _initialKeyId, counter, usages[i], t);
            }

            bool mayAddBit = OneBits(counter) < MaxOneBits;
            if (mayAddBit) FillRegistersBelow(lowestBit, derivationKey, counter);
            Erase(lowestBit);
            _nextCounter = counter + (mayAddBit ? 1UL : 1UL << lowestBit);
            return uses;
        }

        /// <summary>Copies of every key register held now.</summary>
        public byte[][] HeldKeys()
        {
            List<byte[]> held = new List<byte[]>();
            for (int i = 0; i < RegisterCount; i++)
                if (_registers[i] != null) held.Add((byte[])_registers[i].Clone());
            return held.ToArray();
        }

        /// <summary>
        /// Tries to build the working key for any counter from the registers held now. It works for a later counter, because a register above
        /// it can derive down to it. It fails for a used counter: every register that led to that counter is gone.
        /// </summary>
        public bool TryDeriveFromHeldKeys(uint counter, DukptKeyUsage u, DukptKeyType t, out byte[] key)
        {
            key = null;
            for (int bit = 0; bit < RegisterCount; bit++)
            {
                if (_registers[bit] == null || !LeadsTo(_registerCounters[bit], bit, counter)) continue;
                byte[] derivationKey = DukptDerivation.WalkDown(_registers[bit], _initialKeyId, counter, bit);
                key = DukptDerivation.Working(derivationKey, _initialKeyId, counter, u, t);
                return true;
            }
            return false;
        }

        /// <summary>A register for value v at bit b leads to every counter that matches v in bits b and up.</summary>
        static bool LeadsTo(uint registerCounter, int bit, uint counter)
        {
            return registerCounter >> bit == counter >> bit;
        }

        void FillRegistersBelow(int topBit, byte[] parent, uint parentCounter)
        {
            for (int bit = topBit - 1; bit >= 0; bit--)
            {
                uint counter = parentCounter | (1u << bit);
                _registers[bit] = DukptDerivation.Intermediate(parent, _initialKeyId, counter);
                _registerCounters[bit] = counter;
            }
        }

        void Erase(int bit)
        {
            Array.Clear(_registers[bit], 0, _registers[bit].Length);
            _registers[bit] = null;
        }

        static int LowestOneBit(uint value)
        {
            int bit = 0;
            while ((value & (1u << bit)) == 0) bit++;
            return bit;
        }

        static int OneBits(uint value)
        {
            int count = 0;
            for (; value != 0; value &= value - 1) count++;
            return count;
        }
    }
}
