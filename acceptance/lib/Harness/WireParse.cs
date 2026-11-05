using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    public sealed class TlsRecord
    {
        public int Offset, Type, Version, BodyLength;
        public int Total { get { return 5 + BodyLength; } }
    }

    public sealed class ClientHelloInfo
    {
        public byte[] Random;
        public List<int> CipherSuites = new List<int>();
        public List<int> SupportedGroups = new List<int>();
        public List<int> KeyShareGroups = new List<int>();
        public List<int> SupportedVersions = new List<int>();
    }

    /// <summary>
    /// Reads TLS records and hellos straight from captured bytes. The tests use it on what a referee tap saw on the wire,
    /// so the evidence about the handshake comes from bytes and not from the trace of the code under test.
    /// </summary>
    public static class TlsWire
    {
        public static List<TlsRecord> Records(byte[] s)
        {
            List<TlsRecord> r = new List<TlsRecord>();
            int p = 0;
            while (p + 5 <= s.Length)
            {
                TlsRecord rec = new TlsRecord();
                rec.Offset = p; rec.Type = s[p]; rec.Version = (s[p + 1] << 8) | s[p + 2]; rec.BodyLength = (s[p + 3] << 8) | s[p + 4];
                if (rec.Type < 0x14 || rec.Type > 0x18) break;                       // not a TLS record: stop
                r.Add(rec);
                p += rec.Total;
            }
            return r;
        }

        /// <summary>Offset of the first application_data (0x17) record. After ServerHello every TLS 1.3 record has this type.</summary>
        public static int FirstProtectedRecord(byte[] s)
        {
            foreach (TlsRecord r in Records(s)) if (r.Type == 0x17) return r.Offset;
            return -1;
        }

        public static ClientHelloInfo ClientHello(byte[] s)
        {
            if (s.Length < 48 || s[0] != 0x16 || s[5] != 0x01) return null;
            ClientHelloInfo h = new ClientHelloInfo();
            int p = 5 + 4 + 2;
            h.Random = Hex.Slice(s, p, 32); p += 32;
            p += 1 + s[p];
            int cs = (s[p] << 8) | s[p + 1]; p += 2;
            for (int i = 0; i < cs; i += 2) h.CipherSuites.Add((s[p + i] << 8) | s[p + i + 1]);
            p += cs;
            p += 1 + s[p];
            if (p + 2 > s.Length) return h;
            int extEnd = p + 2 + ((s[p] << 8) | s[p + 1]); p += 2;
            while (p + 4 <= extEnd && p + 4 <= s.Length)
            {
                int type = (s[p] << 8) | s[p + 1], len = (s[p + 2] << 8) | s[p + 3];
                int d = p + 4;
                if (type == 0x000a)                                                    // supported_groups
                    for (int i = 0; i + 1 < ((s[d] << 8) | s[d + 1]); i += 2) h.SupportedGroups.Add((s[d + 2 + i] << 8) | s[d + 3 + i]);
                else if (type == 0x002b)                                               // supported_versions (client form)
                    for (int i = 0; i + 1 < s[d]; i += 2) h.SupportedVersions.Add((s[d + 1 + i] << 8) | s[d + 2 + i]);
                else if (type == 0x0033)                                               // key_share (client form)
                {
                    int listEnd = d + 2 + ((s[d] << 8) | s[d + 1]);
                    int q = d + 2;
                    while (q + 4 <= listEnd) { h.KeyShareGroups.Add((s[q] << 8) | s[q + 1]); q += 4 + ((s[q + 2] << 8) | s[q + 3]); }
                }
                p += 4 + len;
            }
            return h;
        }

        /// <summary>The 32 random bytes of the first ServerHello in a server-to-client stream, or null.</summary>
        public static byte[] ServerHelloRandom(byte[] s)
        {
            if (s.Length < 43 || s[0] != 0x16 || s[5] != 0x02) return null;
            return Hex.Slice(s, 11, 32);
        }
    }

    /// <summary>One SSH binary packet seen on the wire before encryption starts.</summary>
    public sealed class SshPacket
    {
        public int Offset, Length, Type;
    }

    public static class SshWire
    {
        public static bool StartsWithVersion(byte[] s) { return s.Length > 8 && Encoding.ASCII.GetString(s, 0, 8) == "SSH-2.0-"; }

        /// <summary>
        /// Walks the clear packets of one direction (version line, KEXINIT, key exchange, NEWKEYS) and returns the offset of the first
        /// encrypted packet, which starts right after NEWKEYS (message 21). Returns -1 when NEWKEYS is not in the capture.
        /// </summary>
        public static int FirstEncryptedPacket(byte[] s, out List<SshPacket> clear)
        {
            clear = new List<SshPacket>();
            int p = 0;
            while (p < s.Length && s[p] != '\n') p++;
            p++;                                                                      // after the version line
            while (p + 6 <= s.Length)
            {
                int len = (s[p] << 24) | (s[p + 1] << 16) | (s[p + 2] << 8) | s[p + 3];
                if (len < 2 || len > 35000 || p + 4 + len > s.Length) return -1;
                int pad = s[p + 4];
                SshPacket pk = new SshPacket();
                pk.Offset = p; pk.Length = 4 + len; pk.Type = s[p + 5];
                clear.Add(pk);
                p += 4 + len;
                if (pk.Type == 21) return p;
            }
            return -1;
        }
    }

    /// <summary>
    /// The hex log a `tap` relay writes (acceptance/referees/README.md): one record per line, "&lt;conn&gt; c2s|s2c &lt;offset&gt; &lt;hex&gt;", and a
    /// "# flip conn=.. dir=.. offset=.. from=.. to=.." line when it flipped a byte. The hex is the bytes as forwarded.
    /// </summary>
    public sealed class TapLog
    {
        public byte[] ClientToServer = new byte[0];
        public byte[] ServerToClient = new byte[0];
        public List<string> Flips = new List<string>();
        public int Connections;

        public static TapLog Read(string path)
        {
            if (!File.Exists(path)) throw new FailException("tap log " + path + " does not exist");
            Dictionary<string, MemoryStream> streams = new Dictionary<string, MemoryStream>();
            TapLog t = new TapLog();
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (StreamReader sr = new StreamReader(fs))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.Length == 0) continue;
                    if (line.StartsWith("#")) { if (line.StartsWith("# flip")) t.Flips.Add(line); continue; }
                    string[] f = line.Split(new char[] { ' ' }, 4);
                    if (f.Length != 4) throw new FailException("tap log line has " + f.Length + " fields, expected '<conn> <dir> <offset> <hex>': " + line.Substring(0, Math.Min(60, line.Length)));
                    int conn = int.Parse(f[0]);
                    if (conn > t.Connections) t.Connections = conn;
                    if (f[1] != "c2s" && f[1] != "s2c") throw new FailException("tap log direction must be c2s or s2c, got " + f[1]);
                    string key = conn.ToString("D4") + f[1];
                    MemoryStream ms;
                    if (!streams.TryGetValue(key, out ms)) { ms = new MemoryStream(); streams[key] = ms; }
                    long offset = long.Parse(f[2]);
                    if (offset != ms.Length) throw new FailException("tap log offset " + offset + " does not continue the stream (length so far " + ms.Length + ")");
                    byte[] bytes = Hex.Decode(f[3]);
                    ms.Write(bytes, 0, bytes.Length);
                }
            }
            List<string> keys = new List<string>(streams.Keys);
            keys.Sort(StringComparer.Ordinal);
            MemoryStream c2s = new MemoryStream(), s2c = new MemoryStream();
            foreach (string k in keys)
            {
                byte[] b = streams[k].ToArray();
                if (k.EndsWith("c2s")) c2s.Write(b, 0, b.Length); else s2c.Write(b, 0, b.Length);
            }
            t.ClientToServer = c2s.ToArray();
            t.ServerToClient = s2c.ToArray();
            return t;
        }
    }
}
