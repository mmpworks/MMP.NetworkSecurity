using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Trace;

namespace NetSec.Tls13
{
    /// <summary>What a caller chooses for one engine. A server sets the chain and the seed. A client sets the anchors and the name.</summary>
    public sealed class Tls13Options
    {
        public TraceStream Stream;
        public string Peer;
        public IRandomSource Random;
        public ITamperHook Tamper;
        public Tls13Group Group;
        public string ServerName;
        public byte[][] TrustAnchors;
        public DateTime Now;
        public bool OfferOnlyTls11;
        public byte[][] CertificateChain;
        public byte[] SigningSeed;
    }

    /// <summary>
    /// The state rules read. Rules never write it. They return Store effects, and the interpreter runs those.
    /// Protect and InstallKeys are the only record-layer calls, so a key change happens where the table says it does.
    /// </summary>
    public sealed class Tls13Session : IMachineSession
    {
        const string HandshakeSent = "tls.handshake.sent";
        public const string AlertMessage = "Alert";
        public const string ApplicationMessage = "ApplicationData";

        public readonly Tls13Options Options;
        public byte[] Transcript = new byte[0];
        public KeyShareOffer Offer;
        public byte[] ClientRandom, SessionId, Shared, HelloHash;
        public Tls13Suite Suite;
        public Tls13Secrets Secrets;
        public Certificate Leaf;
        public bool ClientCertificateAsked;
        public readonly List<string> KeyLogLines = new List<string>();

        RecordProtection _outbound;
        bool _helloSent;

        public Tls13Session(Tls13Options options) { Options = options; }

        public RecordProtection Inbound { get; private set; }
        public bool OutboundProtected { get { return _outbound != null; } }
        public string Holder { get { return Options.Stream.Actor; } }

        public string SentType { get { return HandshakeSent; } }
        public string ReceivedType { get { return "tls.handshake.received"; } }

        public void Absorb(byte[] message)
        {
            byte[] joined = new byte[Transcript.Length + message.Length];
            Buffer.BlockCopy(Transcript, 0, joined, 0, Transcript.Length);
            Buffer.BlockCopy(message, 0, joined, Transcript.Length, message.Length);
            Transcript = joined;
        }

        /// <summary>Rules read secrets from Secrets, which a Store effect sets, so a remembered name adds nothing here.</summary>
        public void Remember(string name, byte[] value) { }

        public byte[] PlainOf(InboundMessage message) { return message.Bytes; }

        public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv)
        {
            RecordProtection protection = new RecordProtection(key, iv);
            if (direction == Direction.Inbound) Inbound = protection;
            else _outbound = protection;
        }

        /// <summary>Splits at the record limit, and seals once outbound keys exist. The very first record says TLS 1.0, as RFC 8446 section 5.1 allows for middlebox reasons.</summary>
        public byte[] Protect(string message, byte[] body)
        {
            int contentType = message == AlertMessage ? ContentType.Alert : message == ApplicationMessage ? ContentType.ApplicationData : ContentType.Handshake;
            ByteWriter wire = new ByteWriter();
            int off = 0;
            do
            {
                int n = Math.Min(body.Length - off, RecordProtection.MaxPlain);
                wire.Put(_outbound != null ? _outbound.Seal(contentType, body, off, n) : RecordProtection.PlainRecord(contentType, _helloSent ? 0x0303 : 0x0301, body, off, n));
                _helloSent = true;
                off += n;
            }
            while (off < body.Length);
            return wire.ToArray();
        }

        public byte[] HashWith(params byte[][] more)
        {
            ByteWriter all = new ByteWriter().Put(Transcript);
            for (int i = 0; i < more.Length; i++) all.Put(more[i]);
            return Tls13KeySchedule.HashOf(Suite.Hash, all.ToArray());
        }

        public byte[] Draw(int n)
        {
            byte[] bytes = new byte[n];
            Options.Random.Fill(bytes, 0, n);
            return bytes;
        }
    }
}
