using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// The running chain of a streamed CBC message (PRD 7.3 item 15): the last ciphertext block, which the next call xors in. A new object
    /// is empty. Init starts a message with its iv and is legal in every state; Clear ends it. One object serves one message at a time and
    /// one thread; used again across messages it allocates nothing. A class and not a struct, because a mutable struct passed by value
    /// would silently drop the chain in C# 3.
    /// </summary>
    public sealed class CbcChain
    {
        internal uint W0, W1, W2, W3;
        bool _ready;

        public CbcChain() { }

        /// <summary>Takes 16 bytes at offset as the iv. A refused Init (null, or fewer than 16 bytes from offset) leaves the object as it was.</summary>
        public void Init(byte[] b, int offset)
        {
            Arg.Range(b, offset, 16);
            W0 = Endian.LoadBe32(b, offset); W1 = Endian.LoadBe32(b, offset + 4); W2 = Endian.LoadBe32(b, offset + 8); W3 = Endian.LoadBe32(b, offset + 12);
            _ready = true;
        }

        /// <summary>Ends the message: the object is empty again, and the chain words are set to 0.</summary>
        public void Clear()
        {
            W0 = W1 = W2 = W3 = 0;
            _ready = false;
        }

        internal void RequireReady()
        {
            if (!_ready) throw new InvalidOperationException("this CbcChain is empty: call Init with the iv first");
        }
    }

    /// <summary>
    /// The running counter of a streamed CTR message (PRD 7.3 item 15): one 128-bit big-endian number. States: empty (new, or after Clear),
    /// ready (after Init), and ended (after a call that ended in a partial block, so no key stream is left over to reuse). Init is legal in
    /// every state and starts a new message.
    /// </summary>
    public sealed class CtrCounter
    {
        internal uint W0, W1, W2, W3;
        int _state;   // 0 empty, 1 ready, 2 ended

        public CtrCounter() { }

        /// <summary>Takes 16 bytes at offset as the first counter block. A refused Init leaves the object as it was.</summary>
        public void Init(byte[] b, int offset)
        {
            Arg.Range(b, offset, 16);
            W0 = Endian.LoadBe32(b, offset); W1 = Endian.LoadBe32(b, offset + 4); W2 = Endian.LoadBe32(b, offset + 8); W3 = Endian.LoadBe32(b, offset + 12);
            _state = 1;
        }

        /// <summary>Ends the message: the object is empty again, and the counter words are set to 0.</summary>
        public void Clear()
        {
            W0 = W1 = W2 = W3 = 0;
            _state = 0;
        }

        internal void RequireReady()
        {
            if (_state == 0) throw new InvalidOperationException("this CtrCounter is empty: call Init with the first counter block");
            if (_state == 2) throw new InvalidOperationException("this CtrCounter ended with a partial block: call Init for the next message");
        }

        internal void End() { _state = 2; }
    }
}
