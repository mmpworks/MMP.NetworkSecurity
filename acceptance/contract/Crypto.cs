// CONTRACT STUB. Public signatures the acceptance suite compiles against (program-design.md section 2).
// Every body throws NotImplementedException. The suite maps that to NOT RUN PRODUCT_MISSING, never PASS.
// "ASSUMED" marks a member the design names but does not spell out. CONTRACT.md lists them for the builders.
#pragma warning disable CS0169, CS0649, CS8618, IDE0060
using System;

namespace NetSec.Crypto
{
    public interface IHash
    {
        int DigestSize { get; }
        int BlockSize { get; }
        void Update(byte[] b, int off, int n);
        byte[] Finish();
        IHash Clone();
    }

    public static class Hashes
    {
        public static IHash Md5() { throw new NotImplementedException(); }
        public static IHash Sha1() { throw new NotImplementedException(); }
        public static IHash Sha256() { throw new NotImplementedException(); }
        public static IHash Sha384() { throw new NotImplementedException(); }
        public static IHash Sha512() { throw new NotImplementedException(); }
        public static IHash Sha3_256() { throw new NotImplementedException(); }
        public static IHash Sha3_512() { throw new NotImplementedException(); }
    }

    public sealed class Shake
    {
        public static Shake New128() { throw new NotImplementedException(); }
        public static Shake New256() { throw new NotImplementedException(); }
        public void Absorb(byte[] b, int off, int n) { throw new NotImplementedException(); }
        public void Squeeze(byte[] b, int off, int n) { throw new NotImplementedException(); }
    }

    public static class Hmac { public static byte[] Compute(Func<IHash> h, byte[] key, byte[] data) { throw new NotImplementedException(); } }

    public static class Hkdf
    {
        public static byte[] Extract(Func<IHash> h, byte[] salt, byte[] ikm) { throw new NotImplementedException(); }
        public static byte[] Expand(Func<IHash> h, byte[] prk, byte[] info, int n) { throw new NotImplementedException(); }
    }

    public sealed class AesKey
    {
        public AesKey(byte[] key) { throw new NotImplementedException(); }
        public void EncryptBlock(byte[] i, int io, byte[] o, int oo) { throw new NotImplementedException(); }
        public void DecryptBlock(byte[] i, int io, byte[] o, int oo) { throw new NotImplementedException(); }
        // docs/walkthrough-design.md section 3.3 (A19)
        public AesBlockWalk WalkEncrypt(byte[] block) { throw new NotImplementedException(); }
        public AesBlockWalk WalkDecrypt(byte[] block) { throw new NotImplementedException(); }
        public AesKeyWord[] WalkKeyExpansion() { throw new NotImplementedException(); }
        public static byte[] SubstitutionTable() { throw new NotImplementedException(); }
        public static byte[] InverseSubstitutionTable() { throw new NotImplementedException(); }
    }

    public enum AesStepKind { AddRoundKey, SubBytes, ShiftRows, MixColumns, InvShiftRows, InvSubBytes, InvMixColumns }

    public sealed class AesStep
    {
        public readonly AesStepKind Kind = default(AesStepKind);
        public readonly int Round = 0;
        public readonly byte[] State = null;
        public readonly byte[] RoundKey = null;
    }

    public sealed class AesBlockWalk
    {
        public readonly int Rounds = 0;
        public readonly byte[] Input = null, Output = null;
        public readonly AesStep[] Steps = null;
    }

    public sealed class AesKeyWord
    {
        public readonly int Index = 0;
        public readonly byte[] Previous = null, Rotated = null, Substituted = null, Rcon = null, AfterRcon = null, KeyBack = null, Word = null;
    }

    public sealed class TdesKey
    {
        public TdesKey(byte[] key) { throw new NotImplementedException(); }
        public void EncryptBlock(byte[] i, int io, byte[] o, int oo) { throw new NotImplementedException(); }
        public void DecryptBlock(byte[] i, int io, byte[] o, int oo) { throw new NotImplementedException(); }
    }

    public static class Modes
    {
        public static byte[] EcbEncrypt(AesKey k, byte[] data) { throw new NotImplementedException(); }
        public static byte[] CbcEncrypt(AesKey k, byte[] iv, byte[] data) { throw new NotImplementedException(); }
        public static byte[] CbcDecrypt(AesKey k, byte[] iv, byte[] data) { throw new NotImplementedException(); }
        public static byte[] Ctr(AesKey k, byte[] counter, byte[] data) { throw new NotImplementedException(); }
    }

    public static class Cmac { public static byte[] Compute(AesKey k, byte[] message) { throw new NotImplementedException(); } }

    public static class Gcm
    {
        public static byte[] Seal(AesKey k, byte[] nonce, byte[] aad, byte[] plain) { throw new NotImplementedException(); }
        public static bool TryOpen(AesKey k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { throw new NotImplementedException(); }
    }

    public static class X25519
    {
        public static byte[] Mult(byte[] scalar, byte[] point) { throw new NotImplementedException(); }
        public static byte[] MultBase(byte[] scalar) { throw new NotImplementedException(); }
    }

    public static class Ed25519
    {
        public static byte[] PublicFrom(byte[] seed) { throw new NotImplementedException(); }
        public static byte[] Sign(byte[] seed, byte[] msg) { throw new NotImplementedException(); }
        public static bool Verify(byte[] pub, byte[] msg, byte[] sig) { throw new NotImplementedException(); }
    }

    public sealed class MlKemPair
    {
        public byte[] Ek { get { throw new NotImplementedException(); } }     // 
        public byte[] Dk { get { throw new NotImplementedException(); } }     // 
    }

    public sealed class MlKemSealed
    {
        public byte[] Ciphertext { get { throw new NotImplementedException(); } }           // 
        public byte[] SharedSecret { get { throw new NotImplementedException(); } }         // 
    }

    public static class MlKem768
    {
        public static MlKemPair KeyGen(byte[] d, byte[] z) { throw new NotImplementedException(); }
        public static MlKemSealed Encaps(byte[] ek, byte[] m) { throw new NotImplementedException(); }
        public static byte[] Decaps(byte[] dk, byte[] c) { throw new NotImplementedException(); }
    }

    public sealed class BigUInt
    {
        public static BigUInt FromBytes(byte[] b) { throw new NotImplementedException(); }   // ASSUMED
        public byte[] ToBigEndian() { throw new NotImplementedException(); }                      // ASSUMED
    }

    public sealed class RsaPublic
    {
        public RsaPublic(BigUInt n, BigUInt e) { throw new NotImplementedException(); }
        public byte[] Raw(byte[] m) { throw new NotImplementedException(); }
    }

    public sealed class RsaPrivate
    {
        public RsaPrivate(BigUInt n, BigUInt d) { throw new NotImplementedException(); }     // "RsaPrivate(n, d) mirrors it"
    }

    public interface IRandomSource { void Fill(byte[] b, int off, int n); }

    public static class Pkcs1
    {
        public static byte[] EncryptV15(RsaPublic pub, IRandomSource rng, byte[] plain) { throw new NotImplementedException(); }
        public static bool TryDecryptV15(RsaPrivate priv, byte[] cipher, out byte[] plain) { throw new NotImplementedException(); }
        public static bool VerifySha1(RsaPublic pub, byte[] message, byte[] signature) { throw new NotImplementedException(); }      // ASSUMED parameter order
        public static bool VerifySha256(RsaPublic pub, byte[] message, byte[] signature) { throw new NotImplementedException(); }    // ASSUMED parameter order
        public static byte[] SignSha1(RsaPrivate priv, byte[] message) { throw new NotImplementedException(); }                         // ASSUMED parameter order
    }

    public static class DhGroup14
    {
        public static byte[] Public(byte[] x) { throw new NotImplementedException(); }
        public static byte[] Shared(byte[] x, byte[] peer) { throw new NotImplementedException(); }
    }
}
