using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Acceptance
{
    /// <summary>
    /// Parsers for what OpenSSL 3.5.7 prints. They have no product code in them, so the self-test checks them against real
    /// s_server and s_client runs (SELF.openssl-referee-smoke) before any clause depends on them.
    /// </summary>
    public static class OpenSslLines
    {
        /// <summary>s_server prints "Peer Temp Key: X25519MLKEM768" or "Peer Temp Key: X25519, 253 bits" once a client connects.</summary>
        public static string ServerGroup(string output)
        {
            Match m = Regex.Match(output, @"Peer Temp Key:\s*(?<g>[A-Za-z0-9]+)");
            return m.Success ? m.Groups["g"].Value : null;
        }

        /// <summary>s_client -brief prints "Peer Temp Key: X25519MLKEM768". Without -brief the session dump says "Negotiated TLS1.3 group:".</summary>
        public static string ClientGroup(string output)
        {
            Match m = Regex.Match(output, @"(?:Negotiated TLS1\.3 group|Peer Temp Key):\s*(?<g>[A-Za-z0-9]+)");
            return m.Success ? m.Groups["g"].Value : null;
        }

        public static string Protocol(string output)
        {
            Match m = Regex.Match(output, @"Protocol version:\s*(?<v>\S+)");
            return m.Success ? m.Groups["v"].Value : null;
        }

        public static string Ciphersuite(string output)
        {
            Match m = Regex.Match(output, @"Ciphersuite:\s*(?<c>\S+)");
            return m.Success ? m.Groups["c"].Value : null;
        }

        /// <summary>Reads a file another process still has open (OpenSSL keeps its key log open for writing).</summary>
        public static string ReadShared(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (StreamReader sr = new StreamReader(fs))
                return sr.ReadToEnd();
        }

        /// <summary>NSS key log lines for one client random: label to secret hex.</summary>
        public static Dictionary<string, string> KeyLog(string path, string clientRandomHex)
        {
            Dictionary<string, string> r = new Dictionary<string, string>();
            if (!File.Exists(path)) return r;
            foreach (string line in ReadShared(path).Split(new char[] { (char)10 }, StringSplitOptions.RemoveEmptyEntries))
            {
                Match m = Regex.Match(line.TrimEnd(), @"^(?<label>[A-Z0-9_]+) (?<random>[0-9a-f]{64}) (?<secret>[0-9a-f]+)$");
                if (m.Success && m.Groups["random"].Value == clientRandomHex) r[m.Groups["label"].Value] = m.Groups["secret"].Value;
            }
            return r;
        }

        /// <summary>The client random of a ClientHello that starts the given bytes: record header 5, handshake header 4, version 2, random 32.</summary>
        public static string ClientRandomOf(byte[] firstBytesSent)
        {
            if (firstBytesSent == null || firstBytesSent.Length < 43 || firstBytesSent[0] != 0x16 || firstBytesSent[5] != 0x01) return null;
            return Hex.Encode(Hex.Slice(firstBytesSent, 11, 32));
        }
    }
}
