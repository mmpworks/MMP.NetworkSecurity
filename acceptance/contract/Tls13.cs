// CONTRACT STUB, Tls13 folder. Tls13KeySchedule is "pure" in the design (A4 runs on it alone) but its members are not spelled out.
#pragma warning disable CS0169, CS0649, CS8618
using System;

namespace NetSec.Tls13
{
    /// <summary>RFC 8446 section 7.1 key schedule. ASSUMED members, named after the RFC and RFC 8448.</summary>
    public sealed class Tls13KeySchedule
    {
        /// <param name="suiteName">"TLS_AES_128_GCM_SHA256" or "TLS_AES_256_GCM_SHA384"</param>
        public Tls13KeySchedule(string suiteName) { throw new NotImplementedException(); }
        /// <summary>HKDF-Extract(salt 0, IKM = psk). A null psk means a string of zero bytes the hash length.</summary>
        public byte[] EarlySecret(byte[] psk) { throw new NotImplementedException(); }
        /// <summary>HKDF-Extract(Derive-Secret(early, "derived", ""), ecdheSecret).</summary>
        public byte[] HandshakeSecret(byte[] earlySecret, byte[] ecdheSecret) { throw new NotImplementedException(); }
        /// <summary>HKDF-Extract(Derive-Secret(handshake, "derived", ""), zeros).</summary>
        public byte[] MasterSecret(byte[] handshakeSecret) { throw new NotImplementedException(); }
        /// <summary>HKDF-Expand-Label(secret, label, transcriptHash, Hash.length). The label has no "tls13 " prefix.</summary>
        public byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash) { throw new NotImplementedException(); }
        public byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length) { throw new NotImplementedException(); }
        public byte[] TrafficKey(byte[] trafficSecret) { throw new NotImplementedException(); }
        public byte[] TrafficIv(byte[] trafficSecret) { throw new NotImplementedException(); }
        public byte[] FinishedKey(byte[] baseKey) { throw new NotImplementedException(); }
    }
}
