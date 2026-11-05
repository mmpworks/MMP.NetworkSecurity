using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Trace;

namespace NetSec.Bridge
{
    /// <summary>
    /// What travels from PIN pad to bank (D13). The CE and the gateway relay it and hold no key that opens it. Its card number shows in clear,
    /// so the gateway sees everything except the PIN block. A CMAC under the sale's MAC key covers every byte before it.
    /// </summary>
    public sealed class PinEnvelope
    {
        const int Version = 1;
        const int KsnSize = 12;
        const int BlockSize = 16;
        const int MacSize = 16;

        public readonly string TraceId, Pan;
        public readonly byte[] Ksn, LockedBlock, Mac;
        public readonly byte[] Bytes;

        PinEnvelope(string traceId, string pan, byte[] ksn, byte[] lockedBlock, byte[] mac, byte[] bytes)
        {
            TraceId = traceId; Pan = pan; Ksn = ksn; LockedBlock = lockedBlock; Mac = mac; Bytes = bytes;
        }

        /// <summary>The bytes the MAC covers. Bytes minus its last 16.</summary>
        public byte[] Covered
        {
            get
            {
                byte[] covered = new byte[Bytes.Length - MacSize];
                Buffer.BlockCopy(Bytes, 0, covered, 0, covered.Length);
                return covered;
            }
        }

        public static PinEnvelope Build(string traceId, string pan, byte[] ksn, byte[] lockedBlock, byte[] macKey)
        {
            byte[] trace = Encoding.UTF8.GetBytes(traceId), card = Encoding.UTF8.GetBytes(pan);
            byte[] covered = new ByteWriter().U8(Version).U8(trace.Length).Put(trace).U8(card.Length).Put(card).Put(ksn).Put(lockedBlock).ToArray();
            byte[] mac = Cmac.Compute(new AesKey(macKey), covered);
            return new PinEnvelope(traceId, pan, ksn, lockedBlock, mac, new ByteWriter().Put(covered).Put(mac).ToArray());
        }

        /// <summary>Reads the shape and checks nothing else. Throws ParseFailure on a shape it cannot read.</summary>
        public static PinEnvelope Parse(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            ByteReader r = new ByteReader(bytes, 0, bytes.Length, true);
            int version = r.U8("version", "header");
            if (version != Version) throw new ParseFailure(ErrorCodes.EnvelopeMalformed, "this envelope has version " + version);
            byte[] trace = r.Take("traceId", "id", r.U8("traceIdLength", "length"));
            byte[] card = r.Take("pan", "data", r.U8("panLength", "length"));
            byte[] ksn = r.Take("ksn", "id", KsnSize);
            byte[] block = r.Take("lockedPinBlock", "cipher", BlockSize);
            byte[] mac = r.Take("mac", "mac", MacSize);
            if (r.Remaining != 0) throw new ParseFailure(ErrorCodes.EnvelopeMalformed, "bytes follow the MAC");
            return new PinEnvelope(Encoding.UTF8.GetString(trace, 0, trace.Length), Encoding.UTF8.GetString(card, 0, card.Length), ksn, block, mac, (byte[])bytes.Clone());
        }
    }

    /// <summary>One sale at the PIN pad. The clear field stays in the pad's process. Only the locked block leaves it.</summary>
    public sealed class PadSale
    {
        public PinEnvelope Envelope;
        public byte[] ClearField;
    }

    public static class PinPadCore
    {
        const int RandomSize = 8;

        /// <summary>Locks one PIN under the next counter's keys. The pad erases the derivation key inside NextTogether.</summary>
        public static PadSale Sell(DukptPinPad pad, string traceId, string pin, string pan, IRandomSource random)
        {
            byte[] fill = new byte[RandomSize];
            random.Fill(fill, 0, fill.Length);
            DukptUse[] keys = pad.NextTogether(new DukptKeyUsage[] { DukptKeyUsage.PinEncryption, DukptKeyUsage.MacGeneration }, DukptKeyType.Aes128);
            byte[] locked = PinBlock.EncryptFormat4(keys[0].Key, pin, pan, fill);
            PadSale sale = new PadSale();
            sale.Envelope = PinEnvelope.Build(traceId, pan, keys[0].Ksn, locked, keys[1].Key);
            sale.ClearField = PinBlock.ClearFieldFormat4(pin, fill);
            return sale;
        }
    }

    /// <summary>The bank's answer to one envelope. A rule's result: the bank process does the printing and the tracing.</summary>
    public sealed class BankDecision
    {
        public bool Ok;
        public string Code, Check, Detail;
        public string TraceId;
        public byte[] ClearField, PinKey;
    }

    public static class BankHsmCore
    {
        public const string MacCheck = "PIN block MAC at bank";
        public const string ReplayCheck = "KSN already seen";
        public const string FormatCheck = "PIN block format check";

        /// <summary>MAC first, so a changed envelope stops before the KSN enters the ledger. Then the KSN, then the PIN block's shape.</summary>
        public static BankDecision Decide(byte[] bdk, KsnLedger ledger, byte[] envelopeBytes)
        {
            PinEnvelope envelope;
            try { envelope = PinEnvelope.Parse(envelopeBytes); }
            catch (ParseFailure failure) { return Refuse(null, ErrorCodes.EnvelopeMalformed, MacCheck, failure.Message); }

            byte[] macKey;
            try { macKey = DukptBank.DeriveWorkingKey(bdk, envelope.Ksn, DukptKeyUsage.MacGeneration, DukptKeyType.Aes128); }
            catch (ArgumentException failure) { return Refuse(envelope.TraceId, ErrorCodes.DukptMacMismatch, MacCheck, failure.Message); }
            catch (NetSecException failure) { return Refuse(envelope.TraceId, ErrorCodes.DukptMacMismatch, MacCheck, failure.Error.Message); }
            if (!Cmac.Verify(new AesKey(macKey), envelope.Covered, envelope.Mac))
                return Refuse(envelope.TraceId, ErrorCodes.DukptMacMismatch, MacCheck, "the MAC does not fit this envelope");
            if (!ledger.TryRecord(envelope.Ksn))
                return Refuse(envelope.TraceId, ErrorCodes.DukptKsnReplay, ReplayCheck, "the bank has seen this KSN before");

            byte[] pinKey = DukptBank.DeriveWorkingKey(bdk, envelope.Ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128);
            byte[] field;
            if (!PinBlock.TryOpenFieldFormat4(pinKey, envelope.LockedBlock, envelope.Pan, out field))
                return Refuse(envelope.TraceId, ErrorCodes.DukptPinBlockFormat, FormatCheck, "the opened PIN block has the wrong shape");

            BankDecision ok = new BankDecision();
            ok.Ok = true;
            ok.TraceId = envelope.TraceId;
            ok.ClearField = field;
            ok.PinKey = pinKey;
            return ok;
        }

        static BankDecision Refuse(string traceId, string code, string check, string detail)
        {
            BankDecision refused = new BankDecision();
            refused.TraceId = traceId;
            refused.Code = code;
            refused.Check = check;
            refused.Detail = detail;
            return refused;
        }
    }

    /// <summary>A plain link's framing: a 4-byte big-endian length, then that many bytes. It is the same on every plain hop, and an SSH channel or a TLS stream carries it unchanged.</summary>
    public static class FrameIo
    {
        public const int MaxFrame = 1 << 20;

        public static IFuture WriteFrame(IByteLink link, byte[] frame)
        {
            byte[] all = new ByteWriter().U32(frame.Length).Put(frame).ToArray();
            return link.Write(all, 0, all.Length);
        }

        /// <summary>The next frame, or null when the peer closed at a frame boundary. A close inside a frame faults the future.</summary>
        public static IFuture<byte[]> ReadFrame(IByteLink link)
        {
            return AsyncProxy.Run<byte[]>(delegate(Return<byte[]> ret) { return ReadBody(link, ret); });
        }

        static IEnumerable<IFuture> ReadBody(IByteLink link, Return<byte[]> ret)
        {
            byte[] header = new byte[4];
            IFuture<int> got = ReadFull(link, header);
            yield return got;
            if (got.Result == 0) yield break;
            if (got.Result < header.Length) throw new ParseFailure(ErrorCodes.ParseTruncated, "the link closed inside a frame header");
            long length = (long)((uint)header[0] << 24 | (uint)header[1] << 16 | (uint)header[2] << 8 | header[3]);
            if (length > MaxFrame) throw new ParseFailure(ErrorCodes.ParseTruncated, "a frame says it holds " + length + " bytes");
            byte[] body = new byte[(int)length];
            got = ReadFull(link, body);
            yield return got;
            if (got.Result < body.Length) throw new ParseFailure(ErrorCodes.ParseTruncated, "the link closed inside a frame");
            ret.Value = body;
        }

        static IFuture<int> ReadFull(IByteLink link, byte[] into)
        {
            return AsyncProxy.Run<int>(delegate(Return<int> ret) { return FullBody(link, into, ret); });
        }

        static IEnumerable<IFuture> FullBody(IByteLink link, byte[] into, Return<int> ret)
        {
            int have = 0;
            while (have < into.Length)
            {
                IFuture<int> read = link.Read(into, have, into.Length - have);
                yield return read;
                if (read.Result == 0) break;
                have += read.Result;
            }
            ret.Value = have;
        }
    }

    /// <summary>The bank's reply to one envelope, sent back along the same path: one byte for the result, then the code as text.</summary>
    public static class BankReply
    {
        public static byte[] Build(BankDecision decision)
        {
            return new ByteWriter().U8(decision.Ok ? 1 : 0).Put(Encoding.UTF8.GetBytes(decision.Code ?? "")).ToArray();
        }

        public static bool Read(byte[] reply, out string code)
        {
            code = reply.Length > 1 ? Encoding.UTF8.GetString(reply, 1, reply.Length - 1) : "";
            return reply.Length > 0 && reply[0] == 1;
        }
    }
}
