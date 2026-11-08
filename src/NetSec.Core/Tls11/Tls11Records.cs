using System;
using NetSec.Bytes;
using NetSec.Crypto;

namespace NetSec.Tls11
{
    public static class Tls11Content
    {
        public const int ChangeCipherSpec = 20, Alert = 21, Handshake = 22, ApplicationData = 23;
    }

    /// <summary>
    /// One direction of an AES-128-CBC, HMAC-SHA1 record layer (RFC 4346 section 6.2.3.2). It runs MAC then encrypt: the MAC covers the clear content,
    /// and CBC then locks content, MAC and padding. Each record carries a fresh clear IV, which stops the BEAST attack on TLS 1.0.
    /// What stays weak: the receiver must decrypt before it can check anything, so padding checks run on unauthenticated bytes. That opens padding oracles such as Lucky13.
    /// TryOpen computes the MAC on bad padding too and reports one result for both faults, as RFC 4346 asks. It does not equalize time, and managed code gives no timing guarantee.
    /// Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Tls11RecordCipher
    {
        public const int HeaderSize = 5;
        public const int IvSize = 16;
        public const int MaxContent = 16384;
        const int BlockSize = 16;
        const int MacSize = Tls11KeyBlock.MacSize;

        readonly AesKey _key;
        readonly byte[] _macKey;
        readonly IRandomSource _random;
        long _sequence;

        public Tls11RecordCipher(byte[] key, byte[] macKey, IRandomSource random)
        {
            _key = new AesKey(key);
            _macKey = (byte[])macKey.Clone();
            _random = random;
        }

        /// <summary>The whole record. The sequence number is implicit: both sides count records, and the MAC covers the count.</summary>
        public byte[] Seal(int contentType, byte[] content)
        {
            byte[] mac = Mac(_sequence++, contentType, Tls11Messages.Version, content, content.Length);
            int paddingLength = BlockSize - 1 - (content.Length + MacSize) % BlockSize;
            ByteWriter inner = new ByteWriter().Put(content).Put(mac);
            for (int i = 0; i <= paddingLength; i++) inner.U8(paddingLength);
            byte[] iv = new byte[IvSize];
            _random.Fill(iv, 0, IvSize);
            byte[] cipher = Modes.CbcEncrypt(_key, iv, inner.ToArray());
            return new ByteWriter().U8(contentType).U16(Tls11Messages.Version).U16(IvSize + cipher.Length).Put(iv).Put(cipher).ToArray();
        }

        /// <summary>False means the MAC or the padding failed. The caller reports one code for both, so a peer cannot tell which one.</summary>
        public bool TryOpen(int contentType, int version, byte[] payload, out byte[] content)
        {
            content = null;
            long sequence = _sequence++;
            int cipherLength = payload.Length - IvSize;
            if (cipherLength < MacSize + 1 || cipherLength % BlockSize != 0) return false;

            byte[] iv = new byte[IvSize], cipher = new byte[cipherLength];
            Buffer.BlockCopy(payload, 0, iv, 0, IvSize);
            Buffer.BlockCopy(payload, IvSize, cipher, 0, cipherLength);
            byte[] inner = Modes.CbcDecrypt(_key, iv, cipher);

            bool paddingGood;
            int contentLength = ContentLength(inner, out paddingGood);
            byte[] expected = Mac(sequence, contentType, version, inner, contentLength);
            bool macGood = ConstantTime.Equal(expected, 0, inner, contentLength, MacSize);
            if (!paddingGood || !macGood) return false;
            content = new byte[contentLength];
            Buffer.BlockCopy(inner, 0, content, 0, contentLength);
            return true;
        }

        /// <summary>On bad padding the length treats the padding as absent, so the MAC work still runs (RFC 4346 section 6.2.3.2).</summary>
        static int ContentLength(byte[] inner, out bool paddingGood)
        {
            int paddingLength = inner[inner.Length - 1];
            paddingGood = paddingLength + 1 + MacSize <= inner.Length;
            for (int i = 0; paddingGood && i <= paddingLength; i++)
                paddingGood = inner[inner.Length - 1 - i] == paddingLength;
            return paddingGood ? inner.Length - paddingLength - 1 - MacSize : inner.Length - 1 - MacSize;
        }

        byte[] Mac(long sequence, int contentType, int version, byte[] content, int contentLength)
        {
            byte[] part = new byte[contentLength];
            Buffer.BlockCopy(content, 0, part, 0, contentLength);
            byte[] signed = new ByteWriter().U32(sequence >> 32).U32(sequence & 0xFFFFFFFFL).U8(contentType).U16(version).U16(contentLength).Put(part).ToArray();
            return Hmac.Compute(Hashes.Sha1, _macKey, signed);
        }

        /// <summary>The size of the cipher field for this much content, for the trace fields of a send.</summary>
        public static int CipherSize(int contentLength)
        {
            return (contentLength + MacSize) / BlockSize * BlockSize + BlockSize;
        }

        public static byte[] PlainRecord(int contentType, byte[] content)
        {
            return new ByteWriter().U8(contentType).U16(Tls11Messages.Version).U16(content.Length).Put(content).ToArray();
        }
    }

    public sealed class Tls11RawRecord
    {
        public readonly int Type, Version;
        public readonly byte[] Payload;
        public Tls11RawRecord(int type, int version, byte[] payload) { Type = type; Version = version; Payload = payload; }
    }

    /// <summary>Joins bytes from TCP into whole records. A length above the RFC 4346 limit fails now, because waiting for those bytes could never end.</summary>
    public sealed class Tls11RecordReader
    {
        const int MaxPayload = Tls11RecordCipher.MaxContent + 2048;
        const int TlsMajor = 3;
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
        public Tls11RawRecord Next()
        {
            if (_pending.Length < Tls11RecordCipher.HeaderSize) return null;
            if (_pending[1] != TlsMajor) throw new ParseFailure(Tls11Codes.RecordHeader, "a record header has major version " + _pending[1]);
            int length = (_pending[3] << 8) | _pending[4];
            if (length > MaxPayload) throw new ParseFailure(Tls11Codes.RecordOverflow, "a record claims " + length + " bytes, and the limit is " + MaxPayload);
            int size = Tls11RecordCipher.HeaderSize + length;
            if (_pending.Length < size) return null;

            byte[] payload = new byte[length];
            byte[] rest = new byte[_pending.Length - size];
            Buffer.BlockCopy(_pending, Tls11RecordCipher.HeaderSize, payload, 0, length);
            Buffer.BlockCopy(_pending, size, rest, 0, rest.Length);
            Tls11RawRecord record = new Tls11RawRecord(_pending[0], (_pending[1] << 8) | _pending[2], payload);
            _pending = rest;
            return record;
        }
    }

    /// <summary>Joins record contents into whole handshake messages. One record can hold many messages, and one message can span many records.</summary>
    public sealed class Tls11HandshakeReader
    {
        const int HeaderSize = 4;
        const int MaxMessage = 1 << 17;
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
            if (length > MaxMessage) throw new ParseFailure(Tls11Codes.RecordOverflow, "a handshake message claims " + length + " bytes, and the limit is " + MaxMessage);
            int size = HeaderSize + length;
            if (_pending.Length < size) return null;
            byte[] message = new byte[size];
            byte[] rest = new byte[_pending.Length - size];
            Buffer.BlockCopy(_pending, 0, message, 0, size);
            Buffer.BlockCopy(_pending, size, rest, 0, rest.Length);
            _pending = rest;
            return message;
        }
    }
}
