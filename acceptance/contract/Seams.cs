// CONTRACT STUB. The seams that docs/program-design.md section 11 adds. Io.cs and Labs.cs hold the older sections (1, 2.1 to 2.5, 3).
// Every body throws NotImplementedException. The suite maps that to NOT RUN PRODUCT_MISSING, never PASS.
// "ASSUMED" marks a member that section 11 names without a shape. CONTRACT.md lists them.
#pragma warning disable CS0169, CS0649, CS8618
using System;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Trace;

namespace NetSec.Pki
{
    /// <summary>
    /// Writes the training PKI for the referees into a folder (section 11, "PEM and OpenSSH files named in section 9").
    /// File names the suite reads (ASSUMED beyond the section 9 names): root.pem (CA root), srv.pem and srv.key (Ed25519 TLS server),
    /// rsa.pem and rsa.key (RSA TLS 1.1 server), host.key (Ed25519 SSH host key, OpenSSH format), rsa-host.key, user.pub (authorized_keys line),
    /// user.key (SSH client identity, OpenSSH format), issuer.pub (token issuer, PEM SPKI).
    /// </summary>
    public static class TrainingPki { public static void Export(string directory) { throw new NotImplementedException(); } }
}

namespace NetSec.Io
{
    public sealed class ProbeRequest
    {
        public WireProtocol Protocol; public string Host; public int Port; public KexGroup Group; public string Suite; public SshSuite SshSuite; public string PeerName;
        public string KnownHostsFile; public bool OfferOnlyTls11; public string ClientKeyId; public string ExecCommand; public string TunnelTo; public byte[] Send;
        public TamperPlan Tamper; public int Seed;          // Seed 0 means OsRandom
    }

    public sealed class ProbeResult
    {
        public bool Completed; public string Code, CheckName, Version, Suite, Group; public int AlertReceived; public string[] KeyLog; public byte[] Received; public TraceEvent[] Events;
    }

    public sealed class ProbeListener { public int Port; public IFuture<ProbeResult> Result; }

    public static class Probe
    {
        public static IFuture<ProbeResult> Connect(ProbeRequest r) { throw new NotImplementedException(); }
        public static ProbeListener Listen(ProbeRequest r) { throw new NotImplementedException(); }
    }
}

namespace NetSec.Tls13
{
    /// <summary>Fields named per RFC 8446 (ASSUMED spelling): EarlySecret, HandshakeSecret, ClientHandshakeTrafficSecret, ServerHandshakeTrafficSecret, MasterSecret, ClientApplicationTrafficSecret0, ServerApplicationTrafficSecret0, ExporterMasterSecret.</summary>
    public sealed class Tls13Secrets
    {
        public byte[] EarlySecret, HandshakeSecret, ClientHandshakeTrafficSecret, ServerHandshakeTrafficSecret, MasterSecret,
                      ClientApplicationTrafficSecret0, ServerApplicationTrafficSecret0, ExporterMasterSecret;
    }

    /// <summary>ASSUMED (asked of Richard): the resumption secrets, which need the client Finished hash that Derive does not take.</summary>
    public sealed class Tls13Resumption { public byte[] ResumptionMasterSecret, ResumptionSecret; }

    public static class Tls13KeySchedule
    {
        public static Tls13Resumption Resume(Func<IHash> h, byte[] masterSecret, byte[] clientFinishedHash, byte[] ticketNonce) { throw new NotImplementedException(); }
        public static Tls13Secrets Derive(Func<IHash> h, byte[] shared, byte[] helloHash, byte[] serverFinishedHash) { throw new NotImplementedException(); }
    }
}

namespace NetSec.Dukpt
{
    /// <summary>ASSUMED: the enum values are the X9.24-3 codes (0x1000 PIN, 0x2000/0x2001/0x2002 MAC, 0x3000/0x3001/0x3002 data, 0x0002 key encryption).</summary>
    public enum DukptKeyUsage : ushort { KeyEncryption = 0x0002, PinEncryption = 0x1000, MacGeneration = 0x2000, MacVerification = 0x2001, MacBothWays = 0x2002, DataEncrypt = 0x3000, DataDecrypt = 0x3001, DataBothWays = 0x3002 }
    /// <summary>ASSUMED: the enum values are the X9.24-3 algorithm codes (2 = AES-128, 3 = AES-192, 4 = AES-256).</summary>
    public enum DukptKeyType : ushort { Aes128 = 2, Aes192 = 3, Aes256 = 4 }

    public sealed class DukptUse { public byte[] Ksn; public byte[] Key; }       // Ksn: 8-byte initial key id then 4-byte big-endian counter

    public sealed class DukptPinPad
    {
        public DukptPinPad(byte[] initialKey, byte[] initialKeyId) { throw new NotImplementedException(); }
        public DukptUse Next(DukptKeyUsage u, DukptKeyType t) { throw new NotImplementedException(); }
        public byte[][] HeldKeys() { throw new NotImplementedException(); }     // copies of every key register held now
    }

    /// <summary>ASSUMED shape (design section 11 names the type only): ISO 9564 format 4 over AES.</summary>
    public static class PinBlock
    {
        public static byte[] EncryptFormat4(byte[] pinKey, string pin, string pan, byte[] random8) { throw new NotImplementedException(); }
        public static bool TryDecryptFormat4(byte[] pinKey, byte[] block, string pan, out string pin) { throw new NotImplementedException(); }
    }

    public static class DukptBank
    {
        public static byte[] DeriveInitialKey(byte[] bdk, byte[] initialKeyId) { throw new NotImplementedException(); }
        public static byte[] DeriveWorkingKey(byte[] bdk, byte[] ksn, DukptKeyUsage u, DukptKeyType t) { throw new NotImplementedException(); }
    }
}

namespace NetSec.Auth
{
    public sealed class AuthDecision { public bool Allowed; public string Code, CheckName; }

    public static class Token
    {
        public static string Issue(ITrainingKey k, string claimsJson) { throw new NotImplementedException(); }
        public static AuthDecision Verify(byte[] pub, string jws, DateTime now) { throw new NotImplementedException(); }
    }
}
