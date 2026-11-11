// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Sha3Hash.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 c419e6a21905293054677846050a972c90ba25cf7fdb5a87bea3609e1178d0af). Do not edit.
using System;

namespace Acceptance.Frozen.Crypto
{
    /// <summary>SHA3-256 and SHA3-512, FIPS 202 section 6.1. The rate is 200 minus twice the digest size.</summary>
    sealed class Sha3Hash : IHash
    {
        readonly int _digestSize;
        readonly Keccak _sponge;
        bool _finished;

        public Sha3Hash(int digestSize) : this(digestSize, new Keccak(200 - 2 * digestSize, 0x06)) { }

        Sha3Hash(int digestSize, Keccak sponge)
        {
            _digestSize = digestSize;
            _sponge = sponge;
        }

        public int DigestSize { get { return _digestSize; } }
        public int BlockSize { get { return 200 - 2 * _digestSize; } }

        public void Update(byte[] b, int off, int n)
        {
            RefuseAfterFinish();
            _sponge.Absorb(b, off, n);
        }

        public byte[] Finish()
        {
            RefuseAfterFinish();
            _finished = true;
            byte[] digest = new byte[_digestSize];
            _sponge.Squeeze(digest, 0, _digestSize);
            return digest;
        }

        public IHash Clone()
        {
            Sha3Hash copy = new Sha3Hash(_digestSize, _sponge.Clone());
            copy._finished = _finished;
            return copy;
        }

        void RefuseAfterFinish()
        {
            if (_finished) throw new InvalidOperationException("this hash has finished; Clone before Finish to keep going");
        }
    }
}
