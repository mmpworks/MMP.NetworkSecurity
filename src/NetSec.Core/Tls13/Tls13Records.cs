using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Tls13
{
    public static class ContentType
    {
        public const int ChangeCipherSpec = 20;
        public const int Alert = 21;
        public const int Handshake = 22;
        public const int ApplicationData = 23;
    }

    /// <summary>
    /// One direction's AEAD state. The nonce is the IV xor the record count (RFC 8446 section 5.3), so the count must advance once per record.
    /// It holds one GcmKey for all its records (PRD 7.3 item 12) and one 12-byte nonce buffer that every record uses again.
    /// Contract: one direction, one thread at a time. Two calls that overlap would share the nonce buffer and the count, so a second call
    /// while one runs throws InvalidOperationException (a test holds this). Calls from different threads one after another are fine.
    /// </summary>
    public sealed class RecordProtection
    {
        public const int MaxPlain = 16384;
        const int TagSize = 16;
        const int HeaderSize = 5;

        readonly GcmKey _gcm;
        readonly byte[] _iv;
        readonly byte[] _nonce;
        long _count;
        int _inUse;

        public RecordProtection(byte[] key, byte[] iv)
        {
            _gcm = new GcmKey(new AesKey(key));
            _iv = (byte[])iv.Clone();
            _nonce = new byte[_iv.Length];
        }

        /// <summary>Takes the one-call-at-a-time guard; throws when another call holds it. Internal so a test can hold it.</summary>
        internal void Enter()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _inUse, 1, 0) != 0)
                throw new InvalidOperationException("one RecordProtection serves one direction on one thread at a time, and two calls overlapped");
        }

        internal void Exit() { System.Threading.Interlocked.Exchange(ref _inUse, 0); }

        public long Count { get { return _count; } }

        /// <summary>TLSInnerPlaintext = content + 1-byte real type. The outer type always reads application_data.</summary>
        public byte[] Seal(int contentType, byte[] content, int off, int n)
        {
            Enter();
            try
            {
                byte[] inner = new byte[n + 1];
                Buffer.BlockCopy(content, off, inner, 0, n);
                inner[n] = (byte)contentType;
                byte[] header = new ByteWriter().U8(ContentType.ApplicationData).U16(0x0303).U16(inner.Length + TagSize).ToArray();
                byte[] sealedBytes = _gcm.Seal(NextNonce(), header, inner);
                return new ByteWriter().Put(header).Put(sealedBytes).ToArray();
            }
            finally { Exit(); }
        }

        /// <summary>Opens one record. False means the tag failed. On success, zero padding is gone and the real type is out.</summary>
        public bool TryOpen(byte[] header, byte[] payload, out int contentType, out byte[] content)
        {
            contentType = 0;
            content = null;
            byte[] inner;
            Enter();
            try
            {
                if (!_gcm.TryOpen(NextNonce(), header, payload, out inner)) return false;
            }
            finally { Exit(); }
            int end = inner.Length - 1;
            while (end >= 0 && inner[end] == 0) end--;
            if (end < 0) throw new ParseFailure(ErrorCodes.UnexpectedMessage, "a protected record holds only padding");
            if (end > MaxPlain) throw new ParseFailure(Tls13Codes.RecordOverflow, "a sealed record holds " + end + " bytes, and the limit is " + MaxPlain);
            contentType = inner[end];
            content = new byte[end];
            Buffer.BlockCopy(inner, 0, content, 0, end);
            return true;
        }

        /// <summary>The next record's nonce, in the one buffer this direction owns (safe under the one-call-at-a-time contract).</summary>
        byte[] NextNonce()
        {
            Buffer.BlockCopy(_iv, 0, _nonce, 0, _iv.Length);
            long count = _count++;
            for (int i = 0; i < 8; i++) _nonce[_nonce.Length - 1 - i] ^= (byte)(count >> (8 * i));
            return _nonce;
        }

        public static byte[] PlainRecord(int contentType, int version, byte[] content, int off, int n)
        {
            byte[] part = new byte[n];
            Buffer.BlockCopy(content, off, part, 0, n);
            return new ByteWriter().U8(contentType).U16(version).U16(n).Put(part).ToArray();
        }
    }

    public sealed class RawRecord
    {
        public readonly int Type;
        public readonly byte[] Header, Payload;
        public RawRecord(int type, byte[] header, byte[] payload) { Type = type; Header = header; Payload = payload; }
    }

    /// <summary>Joins bytes from TCP into whole records. A length that promises more than RFC 8446 allows fails now and never waits.</summary>
    public sealed class RecordBuffer
    {
        const int HeaderSize = 5;
        const int MaxPayload = RecordProtection.MaxPlain + 256;

        byte[] _pending = new byte[0];

        public void Append(byte[] b, int off, int n)
        {
            byte[] joined = new byte[_pending.Length + n];
            Buffer.BlockCopy(_pending, 0, joined, 0, _pending.Length);
            Buffer.BlockCopy(b, off, joined, _pending.Length, n);
            _pending = joined;
        }

        /// <summary>True while bytes of a record that is not whole yet wait here (issue #309).</summary>
        public bool HoldsPartial { get { return _pending.Length > 0; } }

        /// <summary>The next whole record, or null when more bytes must come.</summary>
        public RawRecord Next()
        {
            if (_pending.Length < HeaderSize) return null;
            int length = (_pending[3] << 8) | _pending[4];
            int limit = _pending[0] == ContentType.ApplicationData ? MaxPayload : RecordProtection.MaxPlain;
            if (length > limit) throw new ParseFailure(Tls13Codes.RecordOverflow, "a record claims " + length + " bytes, and the limit is " + limit);
            if (_pending.Length < HeaderSize + length) return null;

            byte[] header = new byte[HeaderSize];
            byte[] payload = new byte[length];
            byte[] rest = new byte[_pending.Length - HeaderSize - length];
            Buffer.BlockCopy(_pending, 0, header, 0, HeaderSize);
            Buffer.BlockCopy(_pending, HeaderSize, payload, 0, length);
            Buffer.BlockCopy(_pending, HeaderSize + length, rest, 0, rest.Length);
            _pending = rest;
            return new RawRecord(header[0], header, payload);
        }
    }

    /// <summary>Joins record contents into whole handshake messages. One record can hold many messages, and one message can span many records.</summary>
    public sealed class HandshakeBuffer
    {
        const int HeaderSize = 4;
        /// <summary>No message this engine reads comes near this. A length past it fails now and never waits for bytes.</summary>
        const int MaxMessage = 65536;
        byte[] _pending = new byte[0];

        public bool IsEmpty { get { return _pending.Length == 0; } }

        public void Append(byte[] content)
        {
            byte[] joined = new byte[_pending.Length + content.Length];
            Buffer.BlockCopy(_pending, 0, joined, 0, _pending.Length);
            Buffer.BlockCopy(content, 0, joined, _pending.Length, content.Length);
            _pending = joined;
        }

        /// <summary>The next whole message with its 4-byte header, or null when more bytes must come.</summary>
        public byte[] Next()
        {
            if (_pending.Length < HeaderSize) return null;
            int length = (_pending[1] << 16) | (_pending[2] << 8) | _pending[3];
            if (length > MaxMessage) throw new ParseFailure(Tls13Codes.MessageTooLong, "a handshake message claims " + length + " bytes, and the limit is " + MaxMessage);
            if (_pending.Length < HeaderSize + length) return null;
            byte[] message = new byte[HeaderSize + length];
            byte[] rest = new byte[_pending.Length - message.Length];
            Buffer.BlockCopy(_pending, 0, message, 0, message.Length);
            Buffer.BlockCopy(_pending, message.Length, rest, 0, rest.Length);
            _pending = rest;
            return message;
        }
    }
}
