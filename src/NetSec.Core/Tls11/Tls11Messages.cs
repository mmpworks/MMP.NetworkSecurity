using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Trace;

namespace NetSec.Tls11
{
    public enum Tls11KeyExchange { Rsa, Ecdhe }

    /// <summary>A named suite. Both use AES-128-CBC and HMAC-SHA1. They differ only in how the two sides agree on the premaster secret.</summary>
    public sealed class Tls11CipherSuite
    {
        public readonly int Code;
        public readonly string Name;
        public readonly Tls11KeyExchange KeyExchange;

        Tls11CipherSuite(int code, string name, Tls11KeyExchange keyExchange) { Code = code; Name = name; KeyExchange = keyExchange; }

        /// <summary>RSA key transport has no forward secrecy: an attacker can record now and decrypt after a key theft.</summary>
        public static readonly Tls11CipherSuite RsaAes128CbcSha = new Tls11CipherSuite(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", Tls11KeyExchange.Rsa);
        public static readonly Tls11CipherSuite EcdheRsaAes128CbcSha = new Tls11CipherSuite(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Tls11KeyExchange.Ecdhe);

        /// <summary>The suite with this IANA name, or null.</summary>
        public static Tls11CipherSuite Find(string name)
        {
            if (name == RsaAes128CbcSha.Name) return RsaAes128CbcSha;
            if (name == EcdheRsaAes128CbcSha.Name) return EcdheRsaAes128CbcSha;
            return null;
        }
    }

    public sealed class Tls11Hello
    {
        public int Version;
        public byte[] Random;
        public int[] Suites;
        public byte[] Compression;

        /// <summary>The client sent the signalling suite or an empty renegotiation_info. The server then owes an empty one back (RFC 5746 section 3.6).</summary>
        public bool SignalsSecureRenegotiation;
    }

    public sealed class Tls11ServerKeyExchange
    {
        public int CurveType, Curve;
        public byte[] PublicKey, Signature;

        /// <summary>The bytes the signature covers after the two randoms.</summary>
        public byte[] Params { get { return new ByteWriter().U8(CurveType).U16(Curve).U8(PublicKey.Length).Put(PublicKey).ToArray(); } }
    }

    /// <summary>
    /// Builds and reads the handshake messages of RFC 4346 section 7.4. Each reader goes through ByteReader, so one piece of code parses a message
    /// and names its trace fields. A builder makes bytes only, and the same reader then names the fields of a send.
    /// </summary>
    public static class Tls11Messages
    {
        public const int Version = 0x0302;
        public const int RandomSize = 32;
        public const int ClientHello = 1, ServerHello = 2, Certificate = 11, ServerKeyExchange = 12, ServerHelloDone = 14, ClientKeyExchange = 16, Finished = 20;

        /// <summary>Table keys for what is not a handshake message. Each sits above every handshake type.</summary>
        public const int ChangeCipherSpecKey = 1000 + Tls11Content.ChangeCipherSpec, AlertKey = 1000 + Tls11Content.Alert, ApplicationDataKey = 1000 + Tls11Content.ApplicationData;

        public const string ClientHelloName = "ClientHello", ServerHelloName = "ServerHello", CertificateName = "Certificate", ServerKeyExchangeName = "ServerKeyExchange",
            ServerHelloDoneName = "ServerHelloDone", ClientKeyExchangeName = "ClientKeyExchange", FinishedName = "Finished",
            ChangeCipherSpecName = "ChangeCipherSpec", AlertName = "Alert", ApplicationDataName = "ApplicationData";

        const int NamedCurveType = 3;
        public const int X25519Curve = 29;
        const int SupportedGroupsExtension = 10, EcPointFormatsExtension = 11, RenegotiationInfoExtension = 0xFF01;
        const int RenegotiationSignallingSuite = 0x00FF;
        public const int FatalLevel = 2, WarningLevel = 1;
        public const int CloseNotify = 0, ProtocolVersionAlert = 70;

        static readonly byte[] DowngradeTail = Hex.Decode("444f574e47524400");

        public static string NameOf(int key)
        {
            switch (key)
            {
                case ClientHello: return ClientHelloName;
                case ServerHello: return ServerHelloName;
                case Certificate: return CertificateName;
                case ServerKeyExchange: return ServerKeyExchangeName;
                case ServerHelloDone: return ServerHelloDoneName;
                case ClientKeyExchange: return ClientKeyExchangeName;
                case Finished: return FinishedName;
                case ChangeCipherSpecKey: return ChangeCipherSpecName;
                case AlertKey: return AlertName;
                case ApplicationDataKey: return ApplicationDataName;
                default: return "Unknown";
            }
        }

        public static int ContentTypeOf(string message)
        {
            switch (message)
            {
                case ChangeCipherSpecName: return Tls11Content.ChangeCipherSpec;
                case AlertName: return Tls11Content.Alert;
                case ApplicationDataName: return Tls11Content.ApplicationData;
                default: return Tls11Content.Handshake;
            }
        }

        // ---------------------------------------------------------------- builders

        /// <summary>
        /// One suite only: the lab forces its choice, because a default run picks the best case. The X25519 extensions go only with an ECDHE suite.
        /// The signalling value beside it is no suite. It tells the server this client knows RFC 5746. This engine has no row for a second handshake, so it does not read the answer.
        /// </summary>
        public static byte[] BuildClientHello(byte[] random, Tls11CipherSuite suite)
        {
            ByteWriter body = new ByteWriter().U16(Version).Put(random).U8(0).U16(4).U16(suite.Code).U16(RenegotiationSignallingSuite).U8(1).U8(0);
            if (suite.KeyExchange == Tls11KeyExchange.Ecdhe)
            {
                body.U16(14);
                body.U16(SupportedGroupsExtension).U16(4).U16(2).U16(X25519Curve);
                body.U16(EcPointFormatsExtension).U16(2).U8(1).U8(0);
            }
            return Handshake(ClientHello, body.ToArray());
        }

        /// <param name="answerRenegotiationInfo">Adds the empty extension, ff 01 00 01 00 (RFC 5746 section 3.2). OpenSSL's default client refuses a server with no such answer.</param>
        public static byte[] BuildServerHello(byte[] random, Tls11CipherSuite suite, bool answerRenegotiationInfo)
        {
            ByteWriter body = new ByteWriter().U16(Version).Put(random).U8(0).U16(suite.Code).U8(0);
            if (answerRenegotiationInfo) body.U16(5).U16(RenegotiationInfoExtension).U16(1).U8(0);
            return Handshake(ServerHello, body.ToArray());
        }

        public static byte[] BuildCertificate(byte[][] chain)
        {
            ByteWriter list = new ByteWriter();
            for (int i = 0; i < chain.Length; i++) list.U24(chain[i].Length).Put(chain[i]);
            return Handshake(Certificate, new ByteWriter().U24(list.Count).Put(list.ToArray()).ToArray());
        }

        public static byte[] X25519Params(byte[] publicKey)
        {
            return new ByteWriter().U8(NamedCurveType).U16(X25519Curve).U8(publicKey.Length).Put(publicKey).ToArray();
        }

        public static byte[] BuildServerKeyExchange(byte[] parameters, byte[] signature)
        {
            return Handshake(ServerKeyExchange, new ByteWriter().Put(parameters).U16(signature.Length).Put(signature).ToArray());
        }

        public static byte[] BuildServerHelloDone() { return Handshake(ServerHelloDone, new byte[0]); }

        public static byte[] BuildRsaClientKeyExchange(byte[] encrypted)
        {
            return Handshake(ClientKeyExchange, new ByteWriter().U16(encrypted.Length).Put(encrypted).ToArray());
        }

        public static byte[] BuildEcdheClientKeyExchange(byte[] publicKey)
        {
            return Handshake(ClientKeyExchange, new ByteWriter().U8(publicKey.Length).Put(publicKey).ToArray());
        }

        public static byte[] BuildFinished(byte[] verifyData) { return Handshake(Finished, verifyData); }

        public static byte[] BuildAlert(int level, int description) { return new byte[] { (byte)level, (byte)description }; }

        public static byte[] BuildChangeCipherSpec() { return new byte[] { 1 }; }

        /// <summary>RFC 8446 section 4.1.3: a server able to speak TLS 1.3 that agrees to TLS 1.1 or below ends its random with DOWNGRD 00.</summary>
        public static void WriteDowngradeTail(byte[] serverRandom)
        {
            Buffer.BlockCopy(DowngradeTail, 0, serverRandom, serverRandom.Length - DowngradeTail.Length, DowngradeTail.Length);
        }

        static byte[] Handshake(int type, byte[] body)
        {
            return new ByteWriter().U8(type).U24(body.Length).Put(body).ToArray();
        }

        // ---------------------------------------------------------------- readers

        static void ReadHeader(ByteReader r)
        {
            r.U8("handshakeType", "header");
            r.U24("handshakeLength", "length");
        }

        public static Tls11Hello ReadClientHello(ByteReader r)
        {
            ReadHeader(r);
            Tls11Hello hello = new Tls11Hello();
            hello.Version = r.U16("clientVersion", "version");
            hello.Random = r.Take("random", "nonce", RandomSize);
            r.Take("sessionId", "id", r.U8("sessionIdLength", "length"));
            int suitesLength = r.U16("suitesLength", "length");
            byte[] suites = r.Take("suites", "data", suitesLength);
            hello.Suites = new int[suites.Length / 2];
            for (int i = 0; i < hello.Suites.Length; i++) hello.Suites[i] = (suites[2 * i] << 8) | suites[2 * i + 1];
            hello.Compression = r.Take("compression", "data", r.U8("compressionLength", "length"));
            hello.SignalsSecureRenegotiation = Array.IndexOf(hello.Suites, RenegotiationSignallingSuite) >= 0 | ExtensionsHoldRenegotiationInfo(r.Take("extensions", "data", r.Remaining));
            return hello;
        }

        /// <summary>A hello may stop before the extension block. A first handshake must carry an empty renegotiation_info, so any other body fails (RFC 5746 section 3.6).</summary>
        static bool ExtensionsHoldRenegotiationInfo(byte[] block)
        {
            if (block.Length == 0) return false;
            ByteReader r = new ByteReader(block, 0, block.Length, true);
            r.U16("extensionsLength", "length");
            bool found = false;
            while (r.Remaining > 0)
            {
                int type = r.U16("extensionType", "data");
                byte[] data = r.Take("extensionData", "data", r.U16("extensionLength", "length"));
                if (type != RenegotiationInfoExtension) continue;
                if (data.Length != 1 || data[0] != 0) throw new ParseFailure(Tls11Codes.RenegotiationInfo, "a first handshake carries a renegotiation_info that is not empty");
                found = true;
            }
            return found;
        }

        public static Tls11Hello ReadServerHello(ByteReader r)
        {
            ReadHeader(r);
            Tls11Hello hello = new Tls11Hello();
            hello.Version = r.U16("serverVersion", "version");
            hello.Random = r.Take("random", "nonce", RandomSize);
            r.Take("sessionId", "id", r.U8("sessionIdLength", "length"));
            hello.Suites = new int[] { r.U16("suite", "data") };
            hello.Compression = new byte[] { (byte)r.U8("compression", "data") };
            r.Take("extensions", "data", r.Remaining);
            return hello;
        }

        public static byte[][] ReadCertificates(ByteReader r)
        {
            ReadHeader(r);
            r.U24("certificatesLength", "length");
            List<byte[]> chain = new List<byte[]>();
            while (r.Remaining > 0)
            {
                int length = r.U24("certificateLength." + chain.Count, "length");
                chain.Add(r.Take("certificate." + chain.Count, "data", length));
            }
            return chain.ToArray();
        }

        public static Tls11ServerKeyExchange ReadServerKeyExchange(ByteReader r)
        {
            ReadHeader(r);
            Tls11ServerKeyExchange ske = new Tls11ServerKeyExchange();
            ske.CurveType = r.U8("curveType", "data");
            ske.Curve = r.U16("namedCurve", "data");
            ske.PublicKey = r.Take("publicKey", "key", r.U8("publicKeyLength", "length"));
            ske.Signature = r.Take("signature", "mac", r.U16("signatureLength", "length"));
            return ske;
        }

        /// <summary>The encrypted premaster on an RSA suite, or the client's public key on an ECDHE suite.</summary>
        public static byte[] ReadClientKeyExchange(ByteReader r, Tls11CipherSuite suite)
        {
            ReadHeader(r);
            if (suite.KeyExchange == Tls11KeyExchange.Rsa) return r.Take("encryptedPremaster", "cipher", r.U16("encryptedPremasterLength", "length"));
            return r.Take("publicKey", "key", r.U8("publicKeyLength", "length"));
        }

        public static byte[] ReadFinished(ByteReader r)
        {
            ReadHeader(r);
            return r.Take("verifyData", "mac", r.Remaining);
        }

        /// <summary>Reads a body for its marks alone. A message with no reader of its own shows as one data span.</summary>
        static void MarkBody(int key, ByteReader r, Tls11CipherSuite suite)
        {
            switch (key)
            {
                case ClientHello: ReadClientHello(r); return;
                case ServerHello: ReadServerHello(r); return;
                case Certificate: ReadCertificates(r); return;
                case ServerKeyExchange: ReadServerKeyExchange(r); return;
                case ServerHelloDone: ReadHeader(r); return;
                case ClientKeyExchange: ReadClientKeyExchange(r, suite); return;
                case Finished: ReadFinished(r); return;
                case ChangeCipherSpecKey: r.U8("change", "data"); return;
                case AlertKey: r.U8("alertLevel", "data"); r.U8("alertDescription", "data"); return;
                default: r.Take("data", "data", r.Remaining); return;
            }
        }

        // ---------------------------------------------------------------- trace fields

        /// <summary>The fields of a received message. The offsets index the message bytes that the received event shows as plain.</summary>
        public static TraceField[] InboundFields(int key, byte[] message, bool visibleToWire, Tls11CipherSuite suite)
        {
            ByteReader r = new ByteReader(message, 0, message.Length, visibleToWire);
            MarkBody(key, r, suite);
            return TraceField.From(r.Marks);
        }

        /// <summary>The fields of a clear record as it goes on the wire: the 5-byte header, then the message.</summary>
        public static TraceField[] ClearFields(int key, byte[] message, Tls11CipherSuite suite)
        {
            byte[] wire = Tls11RecordCipher.PlainRecord(ContentTypeOf(NameOf(key)), message);
            ByteReader r = new ByteReader(wire, 0, wire.Length, true);
            ReadRecordHeader(r);
            MarkBody(key, r, suite);
            return TraceField.From(r.Marks);
        }

        /// <summary>The fields of a protected record. The MAC and the padding sit inside the cipher field, and nothing on the wire shows where they start.</summary>
        public static TraceField[] ProtectedFields(int contentLength)
        {
            int cipherSize = Tls11RecordCipher.CipherSize(contentLength);
            int payload = Tls11RecordCipher.IvSize + cipherSize;
            byte[] header = new ByteWriter().U8(0).U16(0).U16(payload).ToArray();
            ByteReader clear = new ByteReader(header, 0, header.Length, true);
            ReadRecordHeader(clear);
            List<FieldMark> marks = new List<FieldMark>(clear.Marks);
            marks.Add(new FieldMark("iv", Tls11RecordCipher.HeaderSize, Tls11RecordCipher.IvSize, "nonce", true, "iv"));
            marks.Add(new FieldMark("cipher", Tls11RecordCipher.HeaderSize + Tls11RecordCipher.IvSize, cipherSize, "cipher", false, "cipher"));
            return TraceField.From(marks.ToArray());
        }

        static void ReadRecordHeader(ByteReader r)
        {
            r.U8("type", "header");
            r.U16("version", "version");
            r.U16("length", "length");
        }
    }
}
