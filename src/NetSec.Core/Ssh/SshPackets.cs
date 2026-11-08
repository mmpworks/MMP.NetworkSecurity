using System;
using NetSec.Bytes;
using NetSec.Crypto;

namespace NetSec.Ssh
{
    /// <summary>A cipher with memory between packets. SSH runs one counter or one chain through the whole session.</summary>
    public interface ISshCipher
    {
        /// <summary>Changes count bytes in place. Count is a whole number of 16-byte blocks.</summary>
        void Transform(byte[] bytes, int offset, int count);
    }

    /// <summary>aes128-ctr (RFC 4344 section 4). Encrypt and decrypt are one operation.</summary>
    public sealed class AesCtrStream : ISshCipher
    {
        readonly AesKey _key;
        readonly byte[] _counter;
        readonly byte[] _pad = new byte[Block];
        const int Block = 16;

        public AesCtrStream(byte[] key, byte[] iv)
        {
            _key = new AesKey(key);
            _counter = (byte[])iv.Clone();
        }

        public void Transform(byte[] bytes, int offset, int count)
        {
            for (int at = 0; at < count; at += Block)
            {
                _key.EncryptBlock(_counter, 0, _pad, 0);
                for (int i = 0; i < Block; i++) bytes[offset + at + i] ^= _pad[i];
                for (int i = Block - 1; i >= 0 && ++_counter[i] == 0; i--) { }
            }
        }
    }

    /// <summary>aes128-cbc (RFC 4253 section 6.3). The chain runs across packets, so the IV of each packet is the last cipher block before it.</summary>
    public sealed class AesCbcStream : ISshCipher
    {
        readonly AesKey _key;
        readonly byte[] _chain;
        readonly bool _encrypt;
        const int Block = 16;

        public AesCbcStream(byte[] key, byte[] iv, bool encrypt)
        {
            _key = new AesKey(key);
            _chain = (byte[])iv.Clone();
            _encrypt = encrypt;
        }

        public void Transform(byte[] bytes, int offset, int count)
        {
            for (int at = offset; at < offset + count; at += Block)
            {
                if (_encrypt) EncryptOne(bytes, at);
                else DecryptOne(bytes, at);
            }
        }

        void EncryptOne(byte[] bytes, int at)
        {
            for (int i = 0; i < Block; i++) bytes[at + i] ^= _chain[i];
            _key.EncryptBlock(bytes, at, bytes, at);
            Buffer.BlockCopy(bytes, at, _chain, 0, Block);
        }

        void DecryptOne(byte[] bytes, int at)
        {
            byte[] cipher = new byte[Block];
            Buffer.BlockCopy(bytes, at, cipher, 0, Block);
            _key.DecryptBlock(cipher, 0, bytes, at);
            for (int i = 0; i < Block; i++) bytes[at + i] ^= _chain[i];
            Buffer.BlockCopy(cipher, 0, _chain, 0, Block);
        }
    }

    /// <summary>The binary packet of RFC 4253 section 6, in one place: its sizes, and the MAC over the sequence number and the plain packet.</summary>
    public static class SshPacketForm
    {
        public const int ClearBlock = 8;
        public const int CipherBlock = 16;
        public const int MinimumPadding = 4;
        public const int HeaderSize = 5;
        public const int MaximumPacket = 35000;

        /// <summary>
        /// RFC 4253 section 6.4 lets the sequence number wrap at 2^32. RFC 4344 section 3.1 says not to send 2^32 packets under one key, because a
        /// repeated number makes a MAC collision useful. This engine has no rekey, so it stops by name at the last number.
        /// </summary>
        public const long LastSequence = uint.MaxValue;

        public static void CheckSequence(long sequence)
        {
            if (sequence > LastSequence) throw new ParseFailure(SshCodes.SequenceExhausted, "this session used all 2^32 sequence numbers, and this lab has no rekey");
        }

        public static int PaddingFor(int payloadLength, int block)
        {
            int padding = block - ((HeaderSize + payloadLength) % block);
            return padding < MinimumPadding ? padding + block : padding;
        }

        /// <summary>RFC 4253 section 6.4: the MAC covers the sequence number and the whole plain packet. This suite computes it over the plain text.</summary>
        public static byte[] MacInput(uint sequence, byte[] plainPacket, int length)
        {
            byte[] input = new byte[4 + length];
            input[0] = (byte)(sequence >> 24);
            input[1] = (byte)(sequence >> 16);
            input[2] = (byte)(sequence >> 8);
            input[3] = (byte)sequence;
            Buffer.BlockCopy(plainPacket, 0, input, 4, length);
            return input;
        }

        public static ISshCipher CipherFor(string name, byte[] key, byte[] iv, bool encrypt)
        {
            if (name == SshAlgorithms.CipherCbc) return new AesCbcStream(key, iv, encrypt);
            return new AesCtrStream(key, iv);
        }
    }

    /// <summary>Builds outbound packets. The sequence number counts every packet from the first one, clear ones too.</summary>
    public sealed class SshPacketWriter
    {
        ISshCipher _cipher;
        byte[] _macKey;
        Func<IHash> _macHash;
        long _sequence;

        public SshPacketWriter() { }

        public SshPacketWriter(uint firstSequence) { _sequence = firstSequence; }

        public void Arm(ISshCipher cipher, byte[] macKey, Func<IHash> macHash)
        {
            _cipher = cipher; _macKey = macKey; _macHash = macHash;
        }

        /// <summary>Strict KEX only: the number restarts right after NewKeys, so a packet dropped before NewKeys cannot shift it.</summary>
        public void ResetSequence() { _sequence = 0; }

        public byte[] Seal(byte[] payload, IRandomSource random)
        {
            SshPacketForm.CheckSequence(_sequence);
            int block = _cipher == null ? SshPacketForm.ClearBlock : SshPacketForm.CipherBlock;
            int padding = SshPacketForm.PaddingFor(payload.Length, block);
            byte[] noise = new byte[padding];
            random.Fill(noise, 0, padding);
            byte[] packet = new ByteWriter().U32(1 + payload.Length + padding).U8(padding).Put(payload).Put(noise).ToArray();
            uint sequence = (uint)_sequence++;
            if (_cipher == null) return packet;

            byte[] mac = Hmac.Compute(_macHash, _macKey, SshPacketForm.MacInput(sequence, packet, packet.Length));
            _cipher.Transform(packet, 0, packet.Length);
            return new ByteWriter().Put(packet).Put(mac).ToArray();
        }
    }

    public sealed class SshPacket
    {
        public byte[] Wire, Payload;
        public int PaddingLength;
    }

    /// <summary>
    /// Takes bytes as TCP gives them and returns whole packets. SSH encrypts the length too, so the reader must decrypt the first block
    /// before it knows how many bytes to wait for. It keeps that block, because the cipher moves on and cannot run over it twice.
    /// A flipped length byte that still looks sensible makes the reader wait for bytes that never come. The pump's read deadline ends that wait.
    /// </summary>
    public sealed class SshPacketReader
    {
        const int MaximumLine = 255;
        const int MaximumLeadingBytes = 8192;

        byte[] _pending = new byte[0];
        byte[] _firstBlock;
        ISshCipher _cipher;
        byte[] _macKey;
        Func<IHash> _macHash;
        int _macSize;
        long _sequence;

        public SshPacketReader() { }

        public SshPacketReader(uint firstSequence) { _sequence = firstSequence; }

        public void Append(byte[] b, int off, int n)
        {
            byte[] joined = new byte[_pending.Length + n];
            Buffer.BlockCopy(_pending, 0, joined, 0, _pending.Length);
            Buffer.BlockCopy(b, off, joined, _pending.Length, n);
            _pending = joined;
        }

        /// <summary>
        /// True while this reader holds input it has not turned into a line or a packet: bytes of an identification line with no CRLF yet, bytes
        /// of a packet whose length is not known yet, or a decrypted first block whose rest has not come (issue #309).
        /// </summary>
        public bool HoldsPartial { get { return _pending.Length > 0 || _firstBlock != null; } }

        /// <summary>How many packets this reader has taken since the last reset. Strict KEX reads this to prove KexInit came first.</summary>
        public long Sequence { get { return _sequence; } }

        public void ResetSequence() { _sequence = 0; }

        public void Arm(ISshCipher cipher, byte[] macKey, Func<IHash> macHash, int macSize)
        {
            _cipher = cipher; _macKey = macKey; _macHash = macHash; _macSize = macSize;
        }

        /// <summary>The next line without its line ending, or null when no whole line has come. RFC 4253 section 4.2.</summary>
        public byte[] TryLine()
        {
            for (int i = 0; i < _pending.Length; i++)
            {
                if (_pending[i] != 10) continue;
                int length = i > 0 && _pending[i - 1] == 13 ? i - 1 : i;
                if (length > MaximumLine) throw new ParseFailure(SshCodes.Version, "a line before the first packet holds " + length + " bytes");
                byte[] line = new byte[length];
                Buffer.BlockCopy(_pending, 0, line, 0, length);
                Drop(i + 1);
                return line;
            }
            if (_pending.Length > MaximumLeadingBytes) throw new ParseFailure(SshCodes.Version, "the peer sent " + _pending.Length + " bytes and no line ending");
            return null;
        }

        /// <summary>The next whole packet, or null until enough bytes have come. Each bad packet throws ParseFailure with a named code.</summary>
        public SshPacket TryNext()
        {
            SshPacketForm.CheckSequence(_sequence);
            int block = _cipher == null ? SshPacketForm.ClearBlock : SshPacketForm.CipherBlock;
            if (_firstBlock == null)
            {
                if (_pending.Length < block) return null;
                _firstBlock = new byte[block];
                Buffer.BlockCopy(_pending, 0, _firstBlock, 0, block);
                if (_cipher != null) _cipher.Transform(_firstBlock, 0, block);
            }
            int packetLength = CheckedLength(block);
            int plainSize = 4 + packetLength;
            int wireSize = plainSize + (_cipher == null ? 0 : _macSize);
            if (_pending.Length < wireSize) return null;
            return Finish(block, plainSize, wireSize);
        }

        int CheckedLength(int block)
        {
            long length = ((long)_firstBlock[0] << 24) | ((long)_firstBlock[1] << 16) | ((long)_firstBlock[2] << 8) | _firstBlock[3];
            if (length > SshPacketForm.MaximumPacket || length < block - 4 || (length + 4) % block != 0)
                throw new ParseFailure(SshCodes.PacketLength, "the packet length reads " + length + ", which no packet may hold");
            return (int)length;
        }

        SshPacket Finish(int block, int plainSize, int wireSize)
        {
            byte[] plain = new byte[plainSize];
            Buffer.BlockCopy(_firstBlock, 0, plain, 0, block);
            Buffer.BlockCopy(_pending, block, plain, block, plainSize - block);
            if (_cipher != null)
            {
                _cipher.Transform(plain, block, plainSize - block);
                CheckMac(plain, plainSize);
            }
            _sequence++;
            int padding = plain[4];
            int payloadLength = plainSize - SshPacketForm.HeaderSize - padding;
            if (padding < SshPacketForm.MinimumPadding || payloadLength < 1)
                throw new ParseFailure(SshCodes.PacketLength, "the padding length reads " + padding + " in a packet of " + plainSize + " bytes");

            SshPacket packet = new SshPacket();
            packet.PaddingLength = padding;
            packet.Payload = new byte[payloadLength];
            Buffer.BlockCopy(plain, SshPacketForm.HeaderSize, packet.Payload, 0, payloadLength);
            packet.Wire = new byte[wireSize];
            Buffer.BlockCopy(_pending, 0, packet.Wire, 0, wireSize);
            Drop(wireSize);
            _firstBlock = null;
            return packet;
        }

        void CheckMac(byte[] plain, int plainSize)
        {
            byte[] tag = new byte[_macSize];
            Buffer.BlockCopy(_pending, plainSize, tag, 0, _macSize);
            if (!Hmac.Verify(_macHash, _macKey, SshPacketForm.MacInput((uint)_sequence, plain, plainSize), tag)) throw new ParseFailure(SshCodes.PacketMac, "packet " + _sequence + " fails its MAC, so it changed on the way or the keys differ");
        }

        void Drop(int count)
        {
            byte[] rest = new byte[_pending.Length - count];
            Buffer.BlockCopy(_pending, count, rest, 0, rest.Length);
            _pending = rest;
        }
    }
}
