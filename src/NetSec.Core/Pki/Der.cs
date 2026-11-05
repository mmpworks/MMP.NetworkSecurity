using System;
using System.Text;
using NetSec.Bytes;

namespace NetSec.Pki
{
    /// <summary>The small part of DER that X.509 needs. Each writer returns one whole tag, length, value. Parts join by plain concatenation.</summary>
    public static class Der
    {
        public const int TagBoolean = 0x01, TagInteger = 0x02, TagBitString = 0x03, TagOctetString = 0x04, TagOid = 0x06, TagUtf8 = 0x0C,
            TagUtcTime = 0x17, TagGeneralizedTime = 0x18, TagSequence = 0x30, TagSet = 0x31;

        public static byte[] Tlv(int tag, byte[] value)
        {
            ByteWriter w = new ByteWriter().U8(tag);
            int n = value.Length;
            if (n < 128) w.U8(n);
            else if (n < 256) w.U8(0x81).U8(n);
            else if (n < 65536) w.U8(0x82).U16(n);
            else w.U8(0x83).U24(n);
            return w.Put(value).ToArray();
        }

        public static byte[] Join(params byte[][] parts)
        {
            ByteWriter w = new ByteWriter();
            for (int i = 0; i < parts.Length; i++) w.Put(parts[i]);
            return w.ToArray();
        }

        public static byte[] Sequence(params byte[][] parts) { return Tlv(TagSequence, Join(parts)); }
        public static byte[] Set(params byte[][] parts) { return Tlv(TagSet, Join(parts)); }
        public static byte[] Utf8(string text) { return Tlv(TagUtf8, Encoding.UTF8.GetBytes(text)); }
        public static byte[] OctetString(byte[] value) { return Tlv(TagOctetString, value); }
        public static byte[] Boolean(bool value) { return Tlv(TagBoolean, new byte[] { (byte)(value ? 0xFF : 0) }); }
        public static byte[] Oid(string hex) { return Tlv(TagOid, Hex.Decode(hex)); }

        /// <summary>No unused bits. A key or a signature always fills whole bytes.</summary>
        public static byte[] BitString(byte[] value) { return Tlv(TagBitString, Join(new byte[] { 0 }, value)); }

        /// <summary>A small unsigned value. A leading zero keeps the top bit clear, because a DER integer has a sign.</summary>
        public static byte[] Integer(byte[] unsignedBigEndian)
        {
            byte[] body = (unsignedBigEndian[0] & 0x80) != 0 ? Join(new byte[] { 0 }, unsignedBigEndian) : unsignedBigEndian;
            return Tlv(TagInteger, body);
        }

        /// <summary>RFC 5280 section 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050.</summary>
        public static byte[] Time(DateTime utc)
        {
            string stamp = Two(utc.Month) + Two(utc.Day) + Two(utc.Hour) + Two(utc.Minute) + Two(utc.Second) + "Z";
            if (utc.Year < 2050) return Tlv(TagUtcTime, Encoding.UTF8.GetBytes(Two(utc.Year % 100) + stamp));
            return Tlv(TagGeneralizedTime, Encoding.UTF8.GetBytes(utc.Year.ToString() + stamp));
        }

        static string Two(int value) { return value < 10 ? "0" + value : value.ToString(); }
    }

    /// <summary>Reads tag, length, value items and remembers each item's place, so a certificate can name its fields by offset.</summary>
    public sealed class DerReader
    {
        public const string ParseCode = "CERT_PARSE";

        readonly byte[] _bytes;
        readonly int _end;
        int _at;

        public DerReader(byte[] bytes, int offset, int count)
        {
            _bytes = bytes; _at = offset; _end = offset + count;
        }

        public bool HasMore { get { return _at < _end; } }
        public int PeekTag { get { return HasMore ? _bytes[_at] : -1; } }

        public DerItem Read()
        {
            if (_end - _at < 2) throw Bad("an item is cut short");
            int start = _at;
            int tag = _bytes[_at++];
            int length = _bytes[_at++];
            if (length >= 128)
            {
                int count = length - 128;
                if (count < 1 || count > 3 || _end - _at < count) throw Bad("a length field is out of range");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | _bytes[_at++];
            }
            if (_end - _at < length) throw Bad("an item runs past its parent");
            DerItem item = new DerItem(_bytes, tag, start, _at, length);
            _at += length;
            return item;
        }

        public DerItem Read(int expectedTag)
        {
            DerItem item = Read();
            if (item.Tag != expectedTag) throw Bad("found tag " + item.Tag + " where tag " + expectedTag + " belongs");
            return item;
        }

        static ParseFailure Bad(string detail) { return new ParseFailure(ParseCode, detail); }
    }

    public sealed class DerItem
    {
        readonly byte[] _bytes;
        public readonly int Tag, Start, ValueStart, ValueLength;

        public DerItem(byte[] bytes, int tag, int start, int valueStart, int valueLength)
        {
            _bytes = bytes; Tag = tag; Start = start; ValueStart = valueStart; ValueLength = valueLength;
        }

        public int TotalLength { get { return ValueStart - Start + ValueLength; } }
        public DerReader Inner { get { return new DerReader(_bytes, ValueStart, ValueLength); } }

        public byte[] Value { get { return Slice(ValueStart, ValueLength); } }
        public byte[] Whole { get { return Slice(Start, TotalLength); } }

        byte[] Slice(int off, int n)
        {
            byte[] part = new byte[n];
            Buffer.BlockCopy(_bytes, off, part, 0, n);
            return part;
        }
    }
}
