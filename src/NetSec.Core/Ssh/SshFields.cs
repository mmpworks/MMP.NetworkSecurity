using System.Collections.Generic;
using System.Text;
using NetSec.Bytes;
using NetSec.Trace;

namespace NetSec.Ssh
{
    /// <summary>
    /// The name and the fields of each message. One parser serves the sent and the received event, so the two cannot drift.
    /// Offsets index the wire bytes. A protected packet shows only its cipher and its MAC, because the length is encrypted too.
    /// </summary>
    public static class SshFields
    {
        public static TraceField[] Clear(byte[] payload, int paddingLength, bool legacy)
        {
            List<FieldMark> marks = new List<FieldMark>();
            marks.Add(new FieldMark("packetLength", 0, 4, "length", true, "packetLength"));
            marks.Add(new FieldMark("paddingLength", 4, 1, "length", true, "paddingLength"));
            FieldMark[] body = BodyMarks(payload, legacy);
            for (int i = 0; i < body.Length; i++)
                marks.Add(new FieldMark(body[i].Name, body[i].Offset + SshPacketForm.HeaderSize, body[i].Length, body[i].Kind, true, body[i].Gloss));
            marks.Add(new FieldMark("padding", SshPacketForm.HeaderSize + payload.Length, paddingLength, "random", true, "padding"));
            return TraceField.From(marks.ToArray());
        }

        /// <summary>The fields of a protected packet not yet sealed. The padding size follows from the payload size.</summary>
        public static TraceField[] Protected(int payloadLength, int macSize)
        {
            int padding = SshPacketForm.PaddingFor(payloadLength, SshPacketForm.CipherBlock);
            return OfCipher(SshPacketForm.HeaderSize + payloadLength + padding, macSize);
        }

        public static TraceField[] OfCipher(int cipherSize, int macSize)
        {
            return TraceField.From(new FieldMark[]
            {
                new FieldMark("encryptedPacket", 0, cipherSize, "cipher", false, "encryptedPacket"),
                new FieldMark("mac", cipherSize, macSize, "mac", true, "mac"),
            });
        }

        public static TraceField[] VersionLine(int length)
        {
            return TraceField.From(new FieldMark[] { new FieldMark("versionLine", 0, length, "data", true, "versionLine") });
        }

        static FieldMark[] BodyMarks(byte[] payload, bool legacy)
        {
            ByteReader r = new ByteReader(payload, 0, payload.Length, true);
            try
            {
                int type = r.U8("messageType", "header");
                if (type == SshMsg.KexInit) KexInitMarks(r);
                else if (type == SshMsg.KexClientShare) r.Prefixed(legacy ? "dhE" : "clientShare", "key");
                else if (type == SshMsg.KexReply) KexReplyMarks(r, legacy);
            }
            catch (ParseFailure)
            {
                // A bad body still shows its known fields. The rule that reads this message names the failure.
            }
            return r.Marks;
        }

        static void KexInitMarks(ByteReader r)
        {
            r.Take("cookie", "random", 16);
            string[] lists =
            {
                "kexAlgorithms", "hostKeyAlgorithms", "ciphersC2S", "ciphersS2C", "macsC2S", "macsS2C",
                "compressionC2S", "compressionS2C", "languagesC2S", "languagesS2C",
            };
            for (int i = 0; i < lists.Length; i++) r.Prefixed(lists[i], "data");
            r.U8("firstKexPacketFollows", "data");
            r.U32("reserved", "data");
        }

        static void KexReplyMarks(ByteReader r, bool legacy)
        {
            r.Prefixed("hostKey", "key");
            r.Prefixed(legacy ? "dhF" : "serverShare", "key");
            r.Prefixed("exchangeSignature", "mac");
        }

        /// <summary>The name of a packet. Some numbers carry two names, so a tour can tell a query from a signed request.</summary>
        public static string NameOf(byte[] payload, bool legacy)
        {
            switch (payload[0])
            {
                case SshMsg.Disconnect: return SshNames.Disconnect;
                case SshMsg.Ignore: return SshNames.Ignore;
                case SshMsg.Unimplemented: return SshNames.Unimplemented;
                case SshMsg.Debug: return SshNames.Debug;
                case SshMsg.ExtInfo: return SshNames.ExtInfo;
                case SshMsg.ServiceRequest: return SshNames.ServiceRequest;
                case SshMsg.ServiceAccept: return SshNames.ServiceAccept;
                case SshMsg.KexInit: return SshNames.KexInit;
                case SshMsg.NewKeys: return SshNames.NewKeys;
                case SshMsg.KexClientShare: return legacy ? SshNames.KexdhInit : SshNames.KexEcdhInit;
                case SshMsg.KexReply: return legacy ? SshNames.KexdhReply : SshNames.KexEcdhReply;
                case SshMsg.UserauthRequest: return UserauthName(payload);
                case SshMsg.UserauthFailure: return SshNames.UserauthFailure;
                case SshMsg.UserauthSuccess: return SshNames.UserauthSuccess;
                case SshMsg.UserauthBanner: return SshNames.UserauthBanner;
                case SshMsg.UserauthPkOk: return SshNames.UserauthPkOk;
                case SshMsg.GlobalRequest: return SshNames.GlobalRequest;
                case SshMsg.RequestSuccess: return SshNames.RequestSuccess;
                case SshMsg.RequestFailure: return SshNames.RequestFailure;
                case SshMsg.ChannelOpen: return ChannelOpenName(payload);
                case SshMsg.ChannelConfirmation: return SshNames.ChannelOpenConfirmation;
                case SshMsg.ChannelOpenFailure: return SshNames.ChannelOpenFailure;
                case SshMsg.ChannelWindowAdjust: return SshNames.ChannelWindowAdjust;
                case SshMsg.ChannelData: return SshNames.ChannelData;
                case SshMsg.ChannelExtendedData: return SshNames.ChannelExtendedData;
                case SshMsg.ChannelEof: return SshNames.ChannelEof;
                case SshMsg.ChannelClose: return SshNames.ChannelClose;
                case SshMsg.ChannelRequest: return ChannelRequestName(payload);
                case SshMsg.ChannelSuccess: return SshNames.ChannelSuccess;
                case SshMsg.ChannelFailure: return SshNames.ChannelFailure;
                default: return SshNames.Unknown;
            }
        }

        static string UserauthName(byte[] payload)
        {
            try
            {
                ByteReader r = new ByteReader(payload, 1, payload.Length - 1, true);
                r.Prefixed("user", "id");
                r.Prefixed("service", "id");
                if (Text(r.Prefixed("method", "id")) != "publickey") return SshNames.UserauthOther;
                return r.U8("signed", "data") == 0 ? SshNames.UserauthQuery : SshNames.UserauthSigned;
            }
            catch (ParseFailure) { return SshNames.UserauthOther; }
        }

        static string ChannelOpenName(byte[] payload)
        {
            try
            {
                string kind = Text(new ByteReader(payload, 1, payload.Length - 1, true).Prefixed("type", "id"));
                if (kind == "session") return SshNames.ChannelOpenSession;
                return kind == "direct-tcpip" ? SshNames.ChannelOpenTunnel : SshNames.ChannelOpenOther;
            }
            catch (ParseFailure) { return SshNames.ChannelOpenOther; }
        }

        static string ChannelRequestName(byte[] payload)
        {
            try
            {
                ByteReader r = new ByteReader(payload, 1, payload.Length - 1, true);
                r.U32("recipient", "id");
                string kind = Text(r.Prefixed("request", "id"));
                if (kind == "exec") return SshNames.ChannelRequestExec;
                return kind == "exit-status" ? SshNames.ChannelRequestExitStatus : SshNames.ChannelRequestOther;
            }
            catch (ParseFailure) { return SshNames.ChannelRequestOther; }
        }

        public static string Text(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
        }
    }
}
