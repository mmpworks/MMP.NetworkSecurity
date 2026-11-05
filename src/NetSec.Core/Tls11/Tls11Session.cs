using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Trace;

namespace NetSec.Tls11
{
    /// <summary>What one engine needs. Option classes use public fields, for object initializers.</summary>
    public sealed class Tls11Options
    {
        public Tls11CipherSuite Suite;
        public IRandomSource Random;
        public TraceStream Stream;
        public ITamperHook Tamper;

        // Client role.
        public string PeerName;
        public Certificate[] Anchors;
        public DateTime Now;

        // Server role.
        public byte[][] Chain;
        public RsaPrivate ServerKey;
        public bool WriteDowngradeTail;
    }

    /// <summary>
    /// What the rules read. A rule changes nothing here: the transcript grows through Absorb, secrets through Remember, and keys through InstallKeys,
    /// and the interpreter calls those. One side effect stays: Draw reads the random stream in rule order.
    /// A rule finds the randoms and the server key by reading the transcript again, so the session holds no second copy of them.
    /// </summary>
    public sealed class Tls11Session : IMachineSession
    {
        public const string Premaster = "tls11.premaster", Master = "tls11.master", EcdhePrivate = "tls11.ecdhe.private",
            ClientWriteMac = "tls11.client_write_mac", ServerWriteMac = "tls11.server_write_mac",
            ClientWriteKey = "tls11.client_write_key", ServerWriteKey = "tls11.server_write_key";

        readonly Dictionary<string, byte[]> _secrets = new Dictionary<string, byte[]>();
        readonly List<byte[]> _transcript = new List<byte[]>();
        Tls11RecordCipher _outbound;

        public readonly Tls11Options Options;
        public Tls11RecordCipher Inbound { get; private set; }

        public Tls11Session(Tls11Options options) { Options = options; }

        public string SentType { get { return "tls11.message.sent"; } }
        public string ReceivedType { get { return "tls11.message.received"; } }

        public void Absorb(byte[] message) { _transcript.Add(message); }
        public void Remember(string name, byte[] value) { _secrets[name] = value; }
        public byte[] PlainOf(InboundMessage message) { return message.Bytes; }

        /// <param name="iv">The MAC key. TLS 1.1 sends each IV on the wire, so this slot of the effect holds the second key of the direction.</param>
        public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv)
        {
            Tls11RecordCipher cipher = new Tls11RecordCipher(key, iv, Options.Random);
            if (direction == Direction.Outbound) _outbound = cipher;
            else Inbound = cipher;
        }

        public byte[] Protect(string message, byte[] body)
        {
            int type = Tls11Messages.ContentTypeOf(message);
            return _outbound == null ? Tls11RecordCipher.PlainRecord(type, body) : _outbound.Seal(type, body);
        }

        public byte[] Secret(string name) { return _secrets[name]; }
        public bool Holds(string name) { return _secrets.ContainsKey(name); }

        public byte[] Draw(int count)
        {
            byte[] bytes = new byte[count];
            Options.Random.Fill(bytes, 0, count);
            return bytes;
        }

        /// <summary>The handshake message of this type in the transcript, or null.</summary>
        public byte[] Message(int type)
        {
            for (int i = 0; i < _transcript.Count; i++)
                if (_transcript[i][0] == type) return _transcript[i];
            return null;
        }

        public byte[] ClientRandom { get { return Tls11Messages.ReadClientHello(ReaderOf(Tls11Messages.ClientHello)).Random; } }
        public byte[] ServerRandom { get { return Tls11Messages.ReadServerHello(ReaderOf(Tls11Messages.ServerHello)).Random; } }

        public ByteReader ReaderOf(int type)
        {
            byte[] message = Message(type);
            return new ByteReader(message, 0, message.Length, true);
        }

        /// <summary>MD5 and SHA-1 of the transcript with these messages added. It returns a digest and leaves the transcript as it was.</summary>
        public byte[] TranscriptDigest(params byte[][] extra)
        {
            ByteWriter all = new ByteWriter();
            for (int i = 0; i < _transcript.Count; i++) all.Put(_transcript[i]);
            for (int i = 0; i < extra.Length; i++) all.Put(extra[i]);
            return Tls11Prf.Md5Sha1(all.ToArray());
        }
    }
}
