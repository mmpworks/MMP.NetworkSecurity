using System;
using System.Collections.Generic;
using System.Text;

namespace NetSec.Bytes
{
    public static class Hex
    {
        const string Digits = "0123456789abcdef";

        public static string Encode(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            StringBuilder text = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                text.Append(Digits[bytes[i] >> 4]);
                text.Append(Digits[bytes[i] & 15]);
            }
            return text.ToString();
        }

        public static byte[] Decode(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            if (text.Length % 2 != 0) throw new FormatException("hex text has an odd length");
            byte[] bytes = new byte[text.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = (byte)((Nibble(text[i * 2]) << 4) | Nibble(text[i * 2 + 1]));
            return bytes;
        }

        static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new FormatException("not a hex digit: " + c);
        }
    }

    /// <summary>Thrown by ByteReader inside an engine. The engine turns it into a named error at its boundary.</summary>
    public sealed class ParseFailure : Exception
    {
        public readonly string Code;
        public ParseFailure(string code, string message) : base(message) { Code = code; }
    }

    /// <summary>One parsed span of a message. The Trace folder turns it into a TraceField.</summary>
    public sealed class FieldMark
    {
        public readonly string Name, Kind, Gloss;
        public readonly int Offset, Length;
        public readonly bool VisibleToWire;

        public FieldMark(string name, int offset, int length, string kind, bool visibleToWire, string gloss)
        {
            Name = name; Offset = offset; Length = length; Kind = kind; VisibleToWire = visibleToWire; Gloss = gloss;
        }
    }

    /// <summary>Reads big-endian fields and records each one, so the parser and the trace decoder are one piece of code.</summary>
    public sealed class ByteReader
    {
        readonly byte[] _bytes;
        readonly int _end;
        readonly bool _visibleToWire;
        readonly List<FieldMark> _marks = new List<FieldMark>();
        int _at;

        public ByteReader(byte[] bytes, int offset, int count, bool visibleToWire)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            _bytes = bytes; _at = offset; _end = offset + count; _visibleToWire = visibleToWire;
        }

        public int Remaining { get { return _end - _at; } }
        public FieldMark[] Marks { get { return _marks.ToArray(); } }

        public int U8(string name, string kind) { return (int)Number(name, kind, 1); }
        public int U16(string name, string kind) { return (int)Number(name, kind, 2); }
        public int U24(string name, string kind) { return (int)Number(name, kind, 3); }
        public long U32(string name, string kind) { return Number(name, kind, 4); }

        public byte[] Take(string name, string kind, int count)
        {
            Need(name, count);
            byte[] taken = new byte[count];
            Buffer.BlockCopy(_bytes, _at, taken, 0, count);
            Mark(name, kind, count);
            return taken;
        }

        long Number(string name, string kind, int size)
        {
            Need(name, size);
            long value = 0;
            for (int i = 0; i < size; i++) value = (value << 8) | _bytes[_at + i];
            Mark(name, kind, size);
            return value;
        }

        void Need(string name, int count)
        {
            if (count < 0 || count > Remaining)
                throw new ParseFailure("PARSE_TRUNCATED", name + " needs " + count + " bytes and " + Remaining + " remain");
        }

        void Mark(string name, string kind, int count)
        {
            _marks.Add(new FieldMark(name, _at, count, kind, _visibleToWire, name));
            _at += count;
        }
    }

    public sealed class ByteWriter
    {
        byte[] _bytes = new byte[64];
        int _count;

        public int Count { get { return _count; } }

        public ByteWriter U8(int value) { Room(1); _bytes[_count++] = (byte)value; return this; }
        public ByteWriter U16(int value) { U8(value >> 8); return U8(value); }
        public ByteWriter U24(int value) { U8(value >> 16); return U16(value); }
        public ByteWriter U32(long value) { U16((int)((value >> 16) & 0xFFFF)); return U16((int)(value & 0xFFFF)); }

        public ByteWriter Put(byte[] bytes)
        {
            Room(bytes.Length);
            Buffer.BlockCopy(bytes, 0, _bytes, _count, bytes.Length);
            _count += bytes.Length;
            return this;
        }

        public byte[] ToArray()
        {
            byte[] copy = new byte[_count];
            Buffer.BlockCopy(_bytes, 0, copy, 0, _count);
            return copy;
        }

        void Room(int extra)
        {
            if (_count + extra <= _bytes.Length) return;
            byte[] larger = new byte[Math.Max(_bytes.Length * 2, _count + extra)];
            Buffer.BlockCopy(_bytes, 0, larger, 0, _count);
            _bytes = larger;
        }
    }

    /// <summary>JSON writing helpers. One rule for both builds, because CF has no JSON library.</summary>
    public static class MiniJson
    {
        const string HexDigits = "0123456789abcdef";

        public static string Quote(string value)
        {
            StringBuilder text = new StringBuilder(value.Length + 2);
            text.Append('"');
            for (int i = 0; i < value.Length; i++) AppendEscaped(text, value[i]);
            text.Append('"');
            return text.ToString();
        }

        static void AppendEscaped(StringBuilder text, char c)
        {
            switch (c)
            {
                case '"': text.Append((char)92).Append('"'); return;
                case (char)92: text.Append((char)92).Append((char)92); return;
                case (char)10: text.Append((char)92).Append('n'); return;
                case (char)13: text.Append((char)92).Append('r'); return;
                case (char)9: text.Append((char)92).Append('t'); return;
            }
            if (c >= ' ') { text.Append(c); return; }
            text.Append((char)92).Append("u00").Append(HexDigits[c >> 4]).Append(HexDigits[c & 15]);
        }
    }
}
