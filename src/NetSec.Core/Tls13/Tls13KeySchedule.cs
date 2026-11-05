using System;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;

namespace NetSec.Tls13
{
    /// <summary>The ladder of RFC 8446 section 7.1. A rung stays null until its input exists.</summary>
    public sealed class Tls13Secrets
    {
        public byte[] EarlySecret, HandshakeSecret, ClientHandshakeTrafficSecret, ServerHandshakeTrafficSecret, MasterSecret,
                      ClientApplicationTrafficSecret0, ServerApplicationTrafficSecret0, ExporterMasterSecret;
    }

    /// <summary>The two values a session ticket needs, RFC 8446 sections 7.1 and 4.6.1.</summary>
    public sealed class Tls13Resumption
    {
        public byte[] ResumptionMasterSecret, ResumptionSecret;
    }

    /// <summary>Pure functions over bytes. No session, no state, so A4 checks it against the RFC 8448 trace alone.</summary>
    public static class Tls13KeySchedule
    {
        /// <param name="helloHash">Transcript hash through ServerHello.</param>
        /// <param name="serverFinishedHash">Transcript hash through the server Finished, or null while the handshake has not reached it.</param>
        public static Tls13Secrets Derive(Func<IHash> h, byte[] shared, byte[] helloHash, byte[] serverFinishedHash)
        {
            if (h == null) throw new ArgumentNullException("h");
            if (shared == null) throw new ArgumentNullException("shared");
            if (helloHash == null) throw new ArgumentNullException("helloHash");

            byte[] zeros = new byte[h().DigestSize];
            Tls13Secrets s = new Tls13Secrets();
            s.EarlySecret = Hkdf.Extract(h, zeros, zeros);
            s.HandshakeSecret = Hkdf.Extract(h, DeriveSecret(h, s.EarlySecret, "derived", EmptyHash(h)), shared);
            s.ClientHandshakeTrafficSecret = DeriveSecret(h, s.HandshakeSecret, "c hs traffic", helloHash);
            s.ServerHandshakeTrafficSecret = DeriveSecret(h, s.HandshakeSecret, "s hs traffic", helloHash);
            s.MasterSecret = Hkdf.Extract(h, DeriveSecret(h, s.HandshakeSecret, "derived", EmptyHash(h)), zeros);
            if (serverFinishedHash == null) return s;

            s.ClientApplicationTrafficSecret0 = DeriveSecret(h, s.MasterSecret, "c ap traffic", serverFinishedHash);
            s.ServerApplicationTrafficSecret0 = DeriveSecret(h, s.MasterSecret, "s ap traffic", serverFinishedHash);
            s.ExporterMasterSecret = DeriveSecret(h, s.MasterSecret, "exp master", serverFinishedHash);
            return s;
        }

        /// <summary>
        /// The rung that needs the client Finished, which Derive does not take. This engine reads a ticket and drops it, so only
        /// the RFC 8448 check calls this. It stays apart so a later resumption lesson can start from it.
        /// </summary>
        public static Tls13Resumption Resume(Func<IHash> h, byte[] masterSecret, byte[] clientFinishedHash, byte[] ticketNonce)
        {
            if (h == null) throw new ArgumentNullException("h");
            if (masterSecret == null) throw new ArgumentNullException("masterSecret");
            if (clientFinishedHash == null) throw new ArgumentNullException("clientFinishedHash");
            if (ticketNonce == null) throw new ArgumentNullException("ticketNonce");

            Tls13Resumption r = new Tls13Resumption();
            r.ResumptionMasterSecret = DeriveSecret(h, masterSecret, "res master", clientFinishedHash);
            r.ResumptionSecret = ExpandLabel(h, r.ResumptionMasterSecret, "resumption", ticketNonce, h().DigestSize);
            return r;
        }

        public static byte[] ExpandLabel(Func<IHash> h, byte[] secret, string label, byte[] context, int length)
        {
            byte[] fullLabel = Encoding.UTF8.GetBytes("tls13 " + label);
            byte[] info = new ByteWriter().U16(length).U8(fullLabel.Length).Put(fullLabel).U8(context.Length).Put(context).ToArray();
            return Hkdf.Expand(h, secret, info, length);
        }

        public static byte[] DeriveSecret(Func<IHash> h, byte[] secret, string label, byte[] transcriptHash)
        {
            return ExpandLabel(h, secret, label, transcriptHash, h().DigestSize);
        }

        public static byte[] TrafficKey(Func<IHash> h, byte[] trafficSecret, int keyLength)
        {
            return ExpandLabel(h, trafficSecret, "key", new byte[0], keyLength);
        }

        public static byte[] TrafficIv(Func<IHash> h, byte[] trafficSecret)
        {
            return ExpandLabel(h, trafficSecret, "iv", new byte[0], 12);
        }

        /// <summary>RFC 8446 section 4.4.4: HMAC, under a key made from the traffic secret, of the transcript hash so far.</summary>
        public static byte[] VerifyData(Func<IHash> h, byte[] trafficSecret, byte[] transcriptHash)
        {
            return Hmac.Compute(h, FinishedKey(h, trafficSecret), transcriptHash);
        }

        /// <summary>Checks a received verify_data in constant time. A value of another length gives false.</summary>
        public static bool VerifyFinished(Func<IHash> h, byte[] trafficSecret, byte[] transcriptHash, byte[] received)
        {
            return Hmac.Verify(h, FinishedKey(h, trafficSecret), transcriptHash, received);
        }

        static byte[] FinishedKey(Func<IHash> h, byte[] trafficSecret)
        {
            return ExpandLabel(h, trafficSecret, "finished", new byte[0], h().DigestSize);
        }

        public static byte[] HashOf(Func<IHash> h, byte[] bytes)
        {
            IHash hash = h();
            hash.Update(bytes, 0, bytes.Length);
            return hash.Finish();
        }

        static byte[] EmptyHash(Func<IHash> h) { return HashOf(h, new byte[0]); }
    }

    /// <summary>The NSS key log format that Wireshark, OpenSSL, and Go all write.</summary>
    public static class KeyLog
    {
        public static string Line(string label, byte[] clientRandom, byte[] secret)
        {
            return label + " " + Hex.Encode(clientRandom) + " " + Hex.Encode(secret);
        }
    }
}
