using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// RFC 8446 section 7.1 written for the self-test on top of the BCL (HKDF, SHA-256). It runs the A4 clause code against the
    /// RFC 8448 values, which proves the vector file and the clause logic before any product exists.
    /// </summary>
    static class KSubject
    {
        static readonly HashAlgorithmName Alg = HashAlgorithmName.SHA256;
        const int Len = 32;

        public static byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length)
        {
            byte[] full = Encoding.ASCII.GetBytes("tls13 " + label);
            byte[] info = Hex.Concat(new byte[] { (byte)(length >> 8), (byte)length, (byte)full.Length }, full, new byte[] { (byte)context.Length }, context);
            return HKDF.Expand(Alg, secret, length, info);
        }

        static byte[] DeriveSecret(byte[] secret, string label, byte[] hash) { return ExpandLabel(secret, label, hash, Len); }

        public static Dictionary<string, byte[]> Derive(byte[] shared, byte[] helloHash, byte[] serverFinishedHash)
        {
            byte[] empty = Sha256(new byte[0]);
            byte[] early = HKDF.Extract(Alg, new byte[Len], new byte[Len]);
            byte[] hs = HKDF.Extract(Alg, shared, DeriveSecret(early, "derived", empty));
            byte[] master = HKDF.Extract(Alg, new byte[Len], DeriveSecret(hs, "derived", empty));
            Dictionary<string, byte[]> r = new Dictionary<string, byte[]>();
            r["early_secret"] = early;
            r["handshake_secret"] = hs;
            r["c_hs_traffic"] = DeriveSecret(hs, "c hs traffic", helloHash);
            r["s_hs_traffic"] = DeriveSecret(hs, "s hs traffic", helloHash);
            r["master_secret"] = master;
            r["c_ap_traffic"] = DeriveSecret(master, "c ap traffic", serverFinishedHash);
            r["s_ap_traffic"] = DeriveSecret(master, "s ap traffic", serverFinishedHash);
            r["exp_master"] = DeriveSecret(master, "exp master", serverFinishedHash);
            return r;
        }

        public static byte[] Sha256(byte[] data) { return SHA256.HashData(data); }
        public static byte[] HmacSha256(byte[] key, byte[] data) { return HMACSHA256.HashData(key, data); }
        public static byte[] X25519(byte[] scalar, byte[] u) { throw new NotRunException("SELFTEST_NO_REFERENCE", "X25519 has no BCL reference on this runtime"); }
    }
}
