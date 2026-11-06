using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Pki;
using NetSec.Trace;

namespace NetSec.Tls13
{
    public static class HandshakeType
    {
        public const int ClientHello = 1;
        public const int ServerHello = 2;
        public const int NewSessionTicket = 4;
        public const int EncryptedExtensions = 8;
        public const int Certificate = 11;
        public const int CertificateRequest = 13;
        public const int CertificateVerify = 15;
        public const int Finished = 20;
        public const int KeyUpdate = 24;
        /// <summary>Not a handshake type. The table gives application data a row like any other message.</summary>
        public const int ApplicationData = 1000;

        public static string Name(int type)
        {
            switch (type)
            {
                case ClientHello: return "ClientHello";
                case ServerHello: return "ServerHello";
                case NewSessionTicket: return "NewSessionTicket";
                case EncryptedExtensions: return "EncryptedExtensions";
                case Certificate: return "Certificate";
                case CertificateRequest: return "CertificateRequest";
                case CertificateVerify: return "CertificateVerify";
                case Finished: return "Finished";
                case KeyUpdate: return "KeyUpdate";
                case ApplicationData: return "ApplicationData";
                default: return "Unknown";
            }
        }
    }

    public sealed class ClientHelloInfo
    {
        public int LegacyVersion;
        public byte[] Random, SessionId, Compression;
        public int[] Suites = new int[0];
        public int[] Versions = new int[0];
        public int[] Groups = new int[0];
        public int[] SignatureSchemes = new int[0];
        public bool HasSignatureAlgorithms, HasSupportedGroups, HasKeyShare;
        public readonly List<int> ExtensionTypes = new List<int>();
        public string ServerName;
        public readonly Dictionary<int, byte[]> KeyShares = new Dictionary<int, byte[]>();
        public FieldMark[] Marks;
    }

    public sealed class ServerHelloInfo
    {
        public int LegacyVersion, Suite, Compression, SelectedVersion, Group;
        public byte[] Random, SessionId, KeyShare;
        public bool HasSupportedVersions;
        public readonly List<int> ExtensionTypes = new List<int>();
        public FieldMark[] Marks;

        public bool IsHelloRetry { get { return Tls13Messages.SameBytes(Random, Tls13Messages.HelloRetryRandom); } }

        /// <summary>RFC 8446 section 4.1.3: a TLS 1.3 server that falls back ends its random with DOWNGRD and 0 or 1.</summary>
        public bool HasDowngradeSentinel
        {
            get
            {
                for (int i = 0; i < 7; i++)
                    if (Random[24 + i] != Tls13Messages.Downgrade[i]) return false;
                return Random[31] == 0 || Random[31] == 1;
            }
        }
    }

    public sealed class CertificateInfo
    {
        public byte[][] Chain;
        public FieldMark[] Marks;
    }

    public sealed class CertificateVerifyInfo
    {
        public int Scheme;
        public byte[] Signature;
        public FieldMark[] Marks;
    }

    /// <summary>
    /// Builds and reads the handshake messages. A sent message goes through the same reader as a received one to get its fields,
    /// so the decoder the learner sees and the parser the engine runs are one piece of code.
    /// </summary>
    public static class Tls13Messages
    {
        public const int Tls13Version = 0x0304;
        public const int Ed25519Scheme = 0x0807;

        const int ExtServerName = 0, ExtSupportedGroups = 10, ExtSignatureAlgorithms = 13, ExtSupportedVersions = 43, ExtKeyShare = 51;
        static readonly int[] Tls11Suites = { 0x002F, 0xC013 };

        // What ClientHello below sends, and the section 4.2 table for the two server messages that answer it.
        static readonly int[] RequestedByClient = { ExtServerName, ExtSupportedGroups, ExtSignatureAlgorithms, ExtSupportedVersions, ExtKeyShare };
        static readonly int[] AllowedInServerHello = { ExtSupportedVersions, ExtKeyShare };
        static readonly int[] AllowedInEncryptedExtensions = { ExtServerName, ExtSupportedGroups };

        /// <summary>RFC 8446 section 4.1.3: SHA-256 of the text "HelloRetryRequest".</summary>
        public static readonly byte[] HelloRetryRandom = Hex.Decode("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");
        public static readonly byte[] Downgrade = Encoding.UTF8.GetBytes("DOWNGRD");

        public static byte[] ClientHello(byte[] random, string serverName, Tls13Group group, byte[] share)
        {
            ByteWriter ext = new ByteWriter();
            WriteServerName(ext, serverName);
            ext.U16(ExtSupportedVersions).U16(3).U8(2).U16(Tls13Version);
            ext.U16(ExtSupportedGroups).U16(4).U16(2).U16(Tls13GroupInfo.Code(group));
            ext.U16(ExtSignatureAlgorithms).U16(4).U16(2).U16(Ed25519Scheme);
            ext.U16(ExtKeyShare).U16(share.Length + 6).U16(share.Length + 4).U16(Tls13GroupInfo.Code(group)).U16(share.Length).Put(share);

            ByteWriter suites = new ByteWriter();
            for (int i = 0; i < Tls13Suite.All.Length; i++) suites.U16(Tls13Suite.All[i].Code);
            return HelloBody(0x0303, random, suites.ToArray(), ext.ToArray());
        }

        /// <summary>The downgrade lesson: a hello as a TLS 1.1 client writes it, with no supported_versions, so a TLS 1.3 server falls back.</summary>
        public static byte[] LegacyClientHello(byte[] random, string serverName)
        {
            ByteWriter ext = new ByteWriter();
            WriteServerName(ext, serverName);
            ByteWriter suites = new ByteWriter();
            for (int i = 0; i < Tls11Suites.Length; i++) suites.U16(Tls11Suites[i]);
            return HelloBody(0x0302, random, suites.ToArray(), ext.ToArray());
        }

        static byte[] HelloBody(int version, byte[] random, byte[] suites, byte[] extensions)
        {
            ByteWriter body = new ByteWriter().U16(version).Put(random).U8(0).U16(suites.Length).Put(suites).U8(1).U8(0).U16(extensions.Length).Put(extensions);
            return Message(HandshakeType.ClientHello, body.ToArray());
        }

        static void WriteServerName(ByteWriter ext, string serverName)
        {
            byte[] name = Encoding.UTF8.GetBytes(serverName);
            ext.U16(ExtServerName).U16(name.Length + 5).U16(name.Length + 3).U8(0).U16(name.Length).Put(name);
        }

        public static byte[] ServerHello(byte[] random, byte[] sessionId, Tls13Suite suite, Tls13Group group, byte[] share)
        {
            ByteWriter ext = new ByteWriter();
            ext.U16(ExtSupportedVersions).U16(2).U16(Tls13Version);
            ext.U16(ExtKeyShare).U16(share.Length + 4).U16(Tls13GroupInfo.Code(group)).U16(share.Length).Put(share);
            ByteWriter body = new ByteWriter().U16(0x0303).Put(random).U8(sessionId.Length).Put(sessionId).U16(suite.Code).U8(0).U16(ext.Count).Put(ext.ToArray());
            return Message(HandshakeType.ServerHello, body.ToArray());
        }

        public static byte[] EncryptedExtensions()
        {
            return Message(HandshakeType.EncryptedExtensions, new byte[] { 0, 0 });
        }

        /// <summary>RFC 8446 section 4.3.2: an empty context, and the signature_algorithms extension the section requires.</summary>
        public static byte[] CertificateRequest()
        {
            ByteWriter schemes = new ByteWriter().U16(2).U16(Ed25519Scheme);
            ByteWriter extensions = new ByteWriter().U16(ExtSignatureAlgorithms).U16(schemes.Count).Put(schemes.ToArray());
            return Message(HandshakeType.CertificateRequest, new ByteWriter().U8(0).U16(extensions.Count).Put(extensions.ToArray()).ToArray());
        }

        public static byte[] CertificateMessage(byte[][] chain)
        {
            ByteWriter list = new ByteWriter();
            for (int i = 0; i < chain.Length; i++) list.U24(chain[i].Length).Put(chain[i]).U16(0);
            return Message(HandshakeType.Certificate, new ByteWriter().U8(0).U24(list.Count).Put(list.ToArray()).ToArray());
        }

        public static byte[] CertificateVerify(byte[] signature)
        {
            return Message(HandshakeType.CertificateVerify, new ByteWriter().U16(Ed25519Scheme).U16(signature.Length).Put(signature).ToArray());
        }

        public static byte[] Finished(byte[] verifyData)
        {
            return Message(HandshakeType.Finished, verifyData);
        }

        static byte[] Message(int type, byte[] body)
        {
            return new ByteWriter().U8(type).U24(body.Length).Put(body).ToArray();
        }

        /// <summary>RFC 8446 section 4.4.3: 64 spaces, a context string, one zero byte, the transcript hash.</summary>
        public static byte[] SignedContent(string context, byte[] transcriptHash)
        {
            ByteWriter w = new ByteWriter();
            for (int i = 0; i < 64; i++) w.U8(32);
            return w.Put(Encoding.UTF8.GetBytes(context)).U8(0).Put(transcriptHash).ToArray();
        }

        public const string ServerVerifyContext = "TLS 1.3, server CertificateVerify";
        public const string ClientVerifyContext = "TLS 1.3, client CertificateVerify";

        // ---------------------------------------------------------------- readers

        public static ClientHelloInfo ReadClientHello(byte[] message)
        {
            ByteReader r = Open(message, true);
            ClientHelloInfo info = new ClientHelloInfo();
            info.LegacyVersion = r.U16("legacy_version", "header");
            info.Random = r.Take("random", "random", 32);
            info.SessionId = r.Take("session_id", "id", r.U8("session_id.length", "length"));
            info.Suites = ReadU16List(r, "cipher_suites", r.U16("cipher_suites.length", "length"));
            info.Compression = r.Take("compression", "header", r.U8("compression.length", "length"));
            int extensions = r.Remaining > 0 ? r.U16("extensions.length", "length") : 0;
            int end = r.Remaining - extensions;
            while (r.Remaining > end) ReadClientExtension(r, info);
            info.Marks = r.Marks;
            return info;
        }

        static void ReadClientExtension(ByteReader r, ClientHelloInfo info)
        {
            int type = r.U16("extension.type", "header");
            int length = r.U16("extension.length", "length");
            int end = r.Remaining - length;
            info.ExtensionTypes.Add(type);
            switch (type)
            {
                case ExtServerName:
                    r.U16("server_name.list_length", "length");
                    r.U8("server_name.type", "header");
                    byte[] name = r.Take("server_name", "data", r.U16("server_name.length", "length"));
                    info.ServerName = Encoding.UTF8.GetString(name, 0, name.Length);
                    break;
                case ExtSupportedVersions:
                    info.Versions = ReadU16List(r, "supported_versions", r.U8("supported_versions.length", "length"));
                    break;
                case ExtSupportedGroups:
                    info.HasSupportedGroups = true;
                    info.Groups = ReadU16List(r, "supported_groups", r.U16("supported_groups.length", "length"));
                    break;
                case ExtSignatureAlgorithms:
                    info.HasSignatureAlgorithms = true;
                    info.SignatureSchemes = ReadU16List(r, "signature_algorithms", r.U16("signature_algorithms.length", "length"));
                    break;
                case ExtKeyShare:
                    info.HasKeyShare = true;
                    r.U16("key_share.list_length", "length");
                    while (r.Remaining > end)
                    {
                        int group = r.U16("key_share.group", "header");
                        info.KeyShares[group] = ReadShare(r, group, r.U16("key_share.length", "length"));
                    }
                    break;
                default:
                    r.Take("extension.other", "data", length);
                    break;
            }
            CheckEnd(r, end, "extension " + type);
        }

        /// <summary>Marks the two parts of a hybrid share apart, because the lesson shows each one.</summary>
        static byte[] ReadShare(ByteReader r, int group, int length)
        {
            if (group != Tls13GroupInfo.HybridCode || (length != 1216 && length != 1120))
                return r.Take("key_share.x25519", "key", length);
            byte[] first = r.Take(length == 1216 ? "key_share.mlkem_ek" : "key_share.mlkem_ciphertext", "key", length - 32);
            byte[] second = r.Take("key_share.x25519", "key", 32);
            return new ByteWriter().Put(first).Put(second).ToArray();
        }

        public static ServerHelloInfo ReadServerHello(byte[] message)
        {
            ByteReader r = Open(message, true);
            ServerHelloInfo info = new ServerHelloInfo();
            info.LegacyVersion = r.U16("legacy_version", "header");
            info.Random = r.Take("random", "random", 32);
            info.SessionId = r.Take("session_id", "id", r.U8("session_id.length", "length"));
            info.Suite = r.U16("cipher_suite", "header");
            info.Compression = r.U8("compression", "header");
            int extensions = r.Remaining > 0 ? r.U16("extensions.length", "length") : 0;
            int end = r.Remaining - extensions;
            while (r.Remaining > end) ReadServerExtension(r, info);
            info.Marks = r.Marks;
            return info;
        }

        static void ReadServerExtension(ByteReader r, ServerHelloInfo info)
        {
            int type = r.U16("extension.type", "header");
            int length = r.U16("extension.length", "length");
            int end = r.Remaining - length;
            info.ExtensionTypes.Add(type);
            if (type == ExtSupportedVersions) info.HasSupportedVersions = true;
            if (type == ExtSupportedVersions && length == 2)
                info.SelectedVersion = r.U16("supported_versions", "header");
            else if (type == ExtKeyShare && length >= 4)
            {
                info.Group = r.U16("key_share.group", "header");
                info.KeyShare = ReadShare(r, info.Group, r.U16("key_share.length", "length"));
            }
            else
                r.Take("extension.other", "data", length);
            CheckEnd(r, end, "extension " + type);
        }

        public static CertificateInfo ReadCertificate(byte[] message, bool visible)
        {
            ByteReader r = Open(message, visible);
            r.Take("request_context", "id", r.U8("request_context.length", "length"));
            int list = r.U24("certificate_list.length", "length");
            int end = r.Remaining - list;
            List<byte[]> chain = new List<byte[]>();
            while (r.Remaining > end)
            {
                chain.Add(r.Take("certificate[" + chain.Count + "]", "data", r.U24("certificate.length", "length")));
                r.Take("certificate.extensions", "data", r.U16("certificate.extensions.length", "length"));
            }
            CertificateInfo info = new CertificateInfo();
            info.Chain = chain.ToArray();
            info.Marks = WithCertificateFields(r.Marks, info.Chain, visible);
            return info;
        }

        /// <summary>Swaps each whole-certificate field for the X.509 fields inside it. A certificate that does not parse keeps the whole field, and the rule reports it.</summary>
        static FieldMark[] WithCertificateFields(FieldMark[] marks, byte[][] chain, bool visible)
        {
            List<FieldMark> all = new List<FieldMark>();
            int seen = 0;
            for (int i = 0; i < marks.Length; i++)
            {
                FieldMark[] inner = marks[i].Name.StartsWith("certificate[") ? InnerFields(chain[seen++], marks[i].Offset, visible) : null;
                if (inner == null) all.Add(marks[i]);
                else all.AddRange(inner);
            }
            return all.ToArray();
        }

        static FieldMark[] InnerFields(byte[] der, int offset, bool visible)
        {
            try { return Certificate.Parse(der).Marks(offset, visible); }
            catch (ParseFailure) { return null; }
        }

        public static CertificateVerifyInfo ReadCertificateVerify(byte[] message, bool visible)
        {
            ByteReader r = Open(message, visible);
            CertificateVerifyInfo info = new CertificateVerifyInfo();
            info.Scheme = r.U16("signature_scheme", "header");
            info.Signature = r.Take("signature", "mac", r.U16("signature.length", "length"));
            info.Marks = r.Marks;
            return info;
        }

        /// <summary>The fields of a message by type, for the trace. Any type this engine does not read in depth shows as one body field.</summary>
        public static TraceField[] FieldsOf(int type, byte[] message, bool visible)
        {
            switch (type)
            {
                case HandshakeType.ClientHello: return TraceField.From(ReadClientHello(message).Marks);
                case HandshakeType.ServerHello: return TraceField.From(ReadServerHello(message).Marks);
                case HandshakeType.Certificate: return TraceField.From(ReadCertificate(message, visible).Marks);
                case HandshakeType.CertificateVerify: return TraceField.From(ReadCertificateVerify(message, visible).Marks);
            }
            ByteReader r = Open(message, visible);
            r.Take(type == HandshakeType.Finished ? "verify_data" : "body", type == HandshakeType.Finished ? "mac" : "data", r.Remaining);
            return TraceField.From(r.Marks);
        }

        static ByteReader Open(byte[] message, bool visible)
        {
            ByteReader r = new ByteReader(message, 0, message.Length, visible);
            r.U8("msg_type", "header");
            r.U24("length", "length");
            return r;
        }

        static int[] ReadU16List(ByteReader r, string name, int byteLength)
        {
            if (byteLength % 2 != 0) throw new ParseFailure(ErrorCodes.ParseTruncated, name + " has an odd length");
            int[] items = new int[byteLength / 2];
            for (int i = 0; i < items.Length; i++) items[i] = r.U16(name, "header");
            return items;
        }

        /// <summary>The extension types in an EncryptedExtensions message, in order.</summary>
        public static List<int> ReadEncryptedExtensionTypes(byte[] message)
        {
            ByteReader r = Open(message, false);
            int end = r.Remaining - r.U16("extensions.length", "length") - 2;
            List<int> types = new List<int>();
            while (r.Remaining > end)
            {
                types.Add(r.U16("extension.type", "header"));
                r.Take("extension.data", "data", r.U16("extension.length", "length"));
            }
            CheckEnd(r, end, "encrypted_extensions");
            if (r.Remaining != 0) throw new ParseFailure(ErrorCodes.ParseTruncated, "encrypted_extensions has " + r.Remaining + " bytes after its block");
            return types;
        }

        /// <summary>
        /// RFC 8446 section 4.2. Null when every type is allowed. A type this client never asked for is ExtensionNotRequested. A type it asked for,
        /// in a message the section 4.2 table does not list it in, is ExtensionWrongMessage. A repeat of any type is ExtensionRepeated. Type gives the first one at fault.
        /// </summary>
        public static string ServerHelloExtensionFault(List<int> types, out int type) { return ExtensionFault(types, AllowedInServerHello, out type); }

        public static string EncryptedExtensionsFault(List<int> types, out int type) { return ExtensionFault(types, AllowedInEncryptedExtensions, out type); }

        /// <summary>RFC 8446 section 4.2: one extension of each type in a block, known or not. True gives the first repeat.</summary>
        public static bool HasRepeat(List<int> types, out int type)
        {
            for (int i = 0; i < types.Count; i++)
            {
                type = types[i];
                if (types.IndexOf(type) != i) return true;
            }
            type = -1;
            return false;
        }

        static string ExtensionFault(List<int> types, int[] allowed, out int type)
        {
            if (HasRepeat(types, out type)) return Tls13Codes.ExtensionRepeated;
            for (int i = 0; i < types.Count; i++)
            {
                type = types[i];
                if (Array.IndexOf(RequestedByClient, type) < 0) return Tls13Codes.ExtensionNotRequested;
                if (Array.IndexOf(allowed, type) < 0) return Tls13Codes.ExtensionWrongMessage;
            }
            type = -1;
            return null;
        }

        static void CheckEnd(ByteReader r, int end, string what)
        {
            if (r.Remaining != end) throw new ParseFailure(ErrorCodes.ParseTruncated, what + " has a length that does not match its content");
        }

        public static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
