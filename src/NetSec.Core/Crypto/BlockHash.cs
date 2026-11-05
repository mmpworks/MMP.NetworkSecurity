using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// The Merkle-Damgard frame that MD5, SHA-1 and SHA-2 share: fill a block, compress it into the state,
    /// and at the end pad with 0x80, zeros, and the message length in bits.
    /// A subclass holds the state and supplies Compress and Digest.
    /// </summary>
    abstract class BlockHash : IHash
    {
        readonly int _digestSize, _blockSize, _lengthBytes;
        readonly bool _lengthLittleEndian;
        byte[] _buffer;
        int _buffered;
        ulong _totalBytes;
        bool _finished;

        protected BlockHash(int digestSize, int blockSize, int lengthBytes, bool lengthLittleEndian)
        {
            _digestSize = digestSize;
            _blockSize = blockSize;
            _lengthBytes = lengthBytes;
            _lengthLittleEndian = lengthLittleEndian;
            _buffer = new byte[blockSize];
        }

        public int DigestSize { get { return _digestSize; } }
        public int BlockSize { get { return _blockSize; } }

        protected abstract void Compress(byte[] block, int off);
        protected abstract byte[] Digest();

        /// <summary>Called on a new clone. The clone replaces its state arrays with copies.</summary>
        protected abstract void DetachState();

        public void Update(byte[] b, int off, int n)
        {
            Arg.Range(b, off, n);
            RefuseAfterFinish();
            _totalBytes += (ulong)n;
            if (_buffered > 0)
            {
                int take = Math.Min(n, _blockSize - _buffered);
                Buffer.BlockCopy(b, off, _buffer, _buffered, take);
                _buffered += take;
                off += take;
                n -= take;
                if (_buffered < _blockSize) return;
                Compress(_buffer, 0);
                _buffered = 0;
            }
            while (n >= _blockSize)
            {
                Compress(b, off);
                off += _blockSize;
                n -= _blockSize;
            }
            Buffer.BlockCopy(b, off, _buffer, 0, n);
            _buffered = n;
        }

        public byte[] Finish()
        {
            RefuseAfterFinish();
            _finished = true;
            _buffer[_buffered++] = 0x80;
            if (_buffered > _blockSize - _lengthBytes)
            {
                Array.Clear(_buffer, _buffered, _blockSize - _buffered);
                Compress(_buffer, 0);
                _buffered = 0;
            }
            Array.Clear(_buffer, _buffered, _blockSize - _buffered);
            WriteBitLength();
            Compress(_buffer, 0);
            return Digest();
        }

        public IHash Clone()
        {
            BlockHash copy = (BlockHash)MemberwiseClone();
            copy._buffer = (byte[])_buffer.Clone();
            copy.DetachState();
            return copy;
        }

        void WriteBitLength()
        {
            ulong lowBits = _totalBytes << 3;
            if (_lengthLittleEndian)
            {
                Endian.StoreLe64(lowBits, _buffer, _blockSize - 8);
                return;
            }
            Endian.StoreBe64(lowBits, _buffer, _blockSize - 8);
            if (_lengthBytes == 16) Endian.StoreBe64(_totalBytes >> 61, _buffer, _blockSize - 16);
        }

        void RefuseAfterFinish()
        {
            if (_finished) throw new InvalidOperationException("this hash has finished; Clone before Finish to keep going");
        }
    }
}
