using System;
using NetSec.Crypto;
using NetSec.Tls13;

namespace Acceptance
{
    /// <summary>Product mapping for A4. Tls13KeySchedule members are ASSUMED (see CONTRACT.md).</summary>
    sealed class KSubject
    {
        readonly Tls13KeySchedule _ks;
        public KSubject(string suite) { _ks = new Tls13KeySchedule(suite); }

        public byte[] EarlySecret(byte[] psk) { return _ks.EarlySecret(psk); }
        public byte[] HandshakeSecret(byte[] early, byte[] ecdhe) { return _ks.HandshakeSecret(early, ecdhe); }
        public byte[] MasterSecret(byte[] handshake) { return _ks.MasterSecret(handshake); }
        public byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash) { return _ks.DeriveSecret(secret, label, transcriptHash); }
        public byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length) { return _ks.ExpandLabel(secret, label, context, length); }
        public byte[] TrafficKey(byte[] trafficSecret) { return _ks.TrafficKey(trafficSecret); }
        public byte[] TrafficIv(byte[] trafficSecret) { return _ks.TrafficIv(trafficSecret); }
        public byte[] FinishedKey(byte[] baseKey) { return _ks.FinishedKey(baseKey); }

        public static byte[] Sha256(byte[] data)
        {
            IHash h = Hashes.Sha256();
            h.Update(data, 0, data.Length);
            return h.Finish();
        }

        public static byte[] HmacSha256(byte[] key, byte[] data) { return Hmac.Compute(Hashes.Sha256, key, data); }
        public static byte[] X25519(byte[] scalar, byte[] u) { return NetSec.Crypto.X25519.Mult(scalar, u); }
    }
}
