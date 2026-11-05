using System;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// RFC 8446 section 7.1 written for the self-test on top of the BCL (HKDF, HMAC, SHA-256). It runs the A4 clause code
    /// against the RFC 8448 values, which proves the vector file and the clause logic before any product exists.
    /// </summary>
    sealed class KSubject
    {
        readonly HashAlgorithmName _alg = HashAlgorithmName.SHA256;
        readonly int _len = 32;
        public KSubject(string suite)
        {
            if (suite != "TLS_AES_128_GCM_SHA256") throw new NotRunException("SELFTEST_NO_REFERENCE", suite);
        }

        public byte[] EarlySecret(byte[] psk) { return HKDF.Extract(_alg, psk ?? new byte[_len], new byte[_len]); }

        public byte[] HandshakeSecret(byte[] early, byte[] ecdhe) { return HKDF.Extract(_alg, ecdhe, DeriveSecret(early, "derived", Sha256(new byte[0]))); }

        public byte[] MasterSecret(byte[] handshake) { return HKDF.Extract(_alg, new byte[_len], DeriveSecret(handshake, "derived", Sha256(new byte[0]))); }

        public byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash) { return ExpandLabel(secret, label, transcriptHash, _len); }

        public byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length)
        {
            byte[] full = Encoding.ASCII.GetBytes("tls13 " + label);
            byte[] info = Hex.Concat(new byte[] { (byte)(length >> 8), (byte)length, (byte)full.Length }, full, new byte[] { (byte)context.Length }, context);
            return HKDF.Expand(_alg, secret, length, info);
        }

        public byte[] TrafficKey(byte[] trafficSecret) { return ExpandLabel(trafficSecret, "key", new byte[0], 16); }
        public byte[] TrafficIv(byte[] trafficSecret) { return ExpandLabel(trafficSecret, "iv", new byte[0], 12); }
        public byte[] FinishedKey(byte[] baseKey) { return ExpandLabel(baseKey, "finished", new byte[0], _len); }

        public static byte[] Sha256(byte[] data) { return SHA256.HashData(data); }
        public static byte[] HmacSha256(byte[] key, byte[] data) { return HMACSHA256.HashData(key, data); }
        public static byte[] X25519(byte[] scalar, byte[] u) { throw new NotRunException("SELFTEST_NO_REFERENCE", "X25519 has no BCL reference on this runtime"); }
    }
}
