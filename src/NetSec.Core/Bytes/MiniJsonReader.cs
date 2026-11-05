using System;
using System.Collections.Generic;
using System.Text;

namespace NetSec.Bytes
{
    /// <summary>
    /// Reads the JSON in tokens and proofs: objects, arrays, strings, whole numbers, true, false, null. CF has no JSON library.
    /// An object is a Dictionary, an array a List, a number a long. A fraction or an exponent is refused, because no claim here needs one.
    /// </summary>
    public sealed class MiniJsonReader
    {
        public const string Malformed = "JSON_MALFORMED";
        const int MaxDepth = 16;

        readonly string _text;
        int _at;

        MiniJsonReader(string text) { _text = text; }

        public static object Parse(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            MiniJsonReader reader = new MiniJsonReader(text);
            object value = reader.Value(0);
            reader.SkipSpace();
            if (reader._at != text.Length) throw reader.Bad("text follows the value");
            return value;
        }

        object Value(int depth)
        {
            if (depth > MaxDepth) throw Bad("nesting is deeper than " + MaxDepth);
            SkipSpace();
            if (_at >= _text.Length) throw Bad("the text ended early");
            char c = _text[_at];
            if (c == '{') return Object(depth);
            if (c == '[') return Array(depth);
            if (c == '"') return String();
            if (c == '-' || (c >= '0' && c <= '9')) return Number();
            if (TryWord("true")) return true;
            if (TryWord("false")) return false;
            if (TryWord("null")) return null;
            throw Bad("no value starts with '" + c + "'");
        }

        Dictionary<string, object> Object(int depth)
        {
            Dictionary<string, object> members = new Dictionary<string, object>();
            _at++;
            SkipSpace();
            if (TryChar('}')) return members;
            while (true)
            {
                SkipSpace();
                if (_at >= _text.Length || _text[_at] != '"') throw Bad("an object key must be a string");
                string key = String();
                if (members.ContainsKey(key)) throw Bad("the key '" + key + "' repeats");
                SkipSpace();
                if (!TryChar(':')) throw Bad("a colon must follow a key");
                members[key] = Value(depth + 1);
                SkipSpace();
                if (TryChar('}')) return members;
                if (!TryChar(',')) throw Bad("a comma or a closing brace must follow a member");
            }
        }

        List<object> Array(int depth)
        {
            List<object> items = new List<object>();
            _at++;
            SkipSpace();
            if (TryChar(']')) return items;
            while (true)
            {
                items.Add(Value(depth + 1));
                SkipSpace();
                if (TryChar(']')) return items;
                if (!TryChar(',')) throw Bad("a comma or a closing bracket must follow an item");
            }
        }

        string String()
        {
            StringBuilder text = new StringBuilder();
            _at++;
            while (_at < _text.Length)
            {
                char c = _text[_at++];
                if (c == '"') return text.ToString();
                if (c < ' ') throw Bad("a control character sits in a string");
                text.Append(c == (char)92 ? Escape() : c);
            }
            throw Bad("a string has no closing quote");
        }

        char Escape()
        {
            if (_at >= _text.Length) throw Bad("an escape has no character");
            char c = _text[_at++];
            switch (c)
            {
                case '"': return '"';
                case '/': return '/';
                case 'b': return (char)8;
                case 'f': return (char)12;
                case 'n': return (char)10;
                case 'r': return (char)13;
                case 't': return (char)9;
                case 'u': return UnicodeEscape();
                default:
                    if (c == (char)92) return c;
                    throw Bad("the escape '" + c + "' is unknown");
            }
        }

        char UnicodeEscape()
        {
            if (_at + 4 > _text.Length) throw Bad("a unicode escape is short");
            byte[] two;
            try { two = Hex.Decode(_text.Substring(_at, 4)); }
            catch (FormatException) { throw Bad("a unicode escape holds a bad digit"); }
            _at += 4;
            return (char)((two[0] << 8) | two[1]);
        }

        object Number()
        {
            int start = _at;
            if (_text[_at] == '-') _at++;
            int digits = _at;
            while (_at < _text.Length && _text[_at] >= '0' && _text[_at] <= '9') _at++;
            if (_at == digits) throw Bad("a number has no digits");
            if (_at - digits > 18) throw Bad("a number is too long");
            if (_at < _text.Length && (_text[_at] == '.' || _text[_at] == 'e' || _text[_at] == 'E')) throw Bad("a number must be whole");
            return long.Parse(_text.Substring(start, _at - start));
        }

        bool TryWord(string word)
        {
            if (string.CompareOrdinal(_text, _at, word, 0, word.Length) != 0) return false;
            _at += word.Length;
            return true;
        }

        bool TryChar(char c)
        {
            if (_at >= _text.Length || _text[_at] != c) return false;
            _at++;
            return true;
        }

        void SkipSpace()
        {
            while (_at < _text.Length && (_text[_at] == ' ' || _text[_at] == (char)9 || _text[_at] == (char)10 || _text[_at] == (char)13)) _at++;
        }

        ParseFailure Bad(string why)
        {
            return new ParseFailure(Malformed, why + " (at character " + _at + ")");
        }
    }

    public static class Base64Url
    {
        public static string Encode(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>Refuses padding and the standard alphabet, so one token has one spelling.</summary>
        public static byte[] Decode(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            if (text.IndexOfAny(new char[] { '=', '+', '/' }) >= 0 || text.Length % 4 == 1)
                throw new ParseFailure(MiniJsonReader.Malformed, "not base64url");
            string standard = text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4);
            try { return Convert.FromBase64String(standard); }
            catch (FormatException) { throw new ParseFailure(MiniJsonReader.Malformed, "not base64url"); }
        }
    }
}
