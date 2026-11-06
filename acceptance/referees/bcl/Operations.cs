using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace NetSec.Referees.Bcl;

/// <summary>
/// The oracle's operation table. Ed25519 and X25519 are absent, because the BCL has
/// no public API for them.
/// </summary>
internal static class Operations
{
    private static readonly Dictionary<string, Func<Request, JsonObject>> Table = new()
    {
        ["info"] = _ => Info(),
        ["hash"] = Hash,
        ["hmac"] = Hmac,
        ["hkdf"] = Hkdf,
        ["hkdf-extract"] = HkdfExtract,
        ["hkdf-expand"] = HkdfExpand,
        ["aes-ecb-encrypt"] = request => WithAes(request, aes => aes.EncryptEcb(request.Hex("data"), Padding(request))),
        ["aes-ecb-decrypt"] = request => WithAes(request, aes => aes.DecryptEcb(request.Hex("data"), Padding(request))),
        ["aes-cbc-encrypt"] = request => WithAes(request, aes => aes.EncryptCbc(request.Hex("data"), request.Hex("iv"), Padding(request))),
        ["aes-cbc-decrypt"] = request => WithAes(request, aes => aes.DecryptCbc(request.Hex("data"), request.Hex("iv"), Padding(request))),
        ["aes-gcm-encrypt"] = GcmEncrypt,
        ["aes-gcm-decrypt"] = GcmDecrypt,
        ["rsa-keygen"] = RsaKeyGen,
        ["rsa-sign"] = RsaSign,
        ["rsa-verify"] = RsaVerify,
        ["rsa-encrypt"] = RsaEncrypt,
        ["rsa-decrypt"] = RsaDecrypt,
        ["mlkem768-keygen"] = MlKemKeyGen,
        ["mlkem768-encaps"] = MlKemEncapsulate,
        ["mlkem768-decaps"] = MlKemDecapsulate,
    };

    public static JsonObject Run(Request request) =>
        Table.TryGetValue(request.Op, out Func<Request, JsonObject>? operation)
            ? operation(request)
            : throw new OracleException("UNKNOWN_OP", $"unknown op '{request.Op}'");

    private static JsonObject Bytes(string name, byte[] value) =>
        new() { [name] = Convert.ToHexStringLower(value) };

    private static JsonObject Info() => new()
    {
        ["runtime"] = RuntimeInformation.FrameworkDescription,
        ["mlkem"] = MLKem.IsSupported,
        ["sha3"] = SHA3_256.IsSupported,
        ["shake"] = Shake128.IsSupported,
    };

    private static JsonObject Hash(Request request)
    {
        byte[] data = request.Hex("data");
        return Bytes("digest", request.Text("alg") switch
        {
            "md5" => MD5.HashData(data),
            "sha1" => SHA1.HashData(data),
            "sha256" => SHA256.HashData(data),
            "sha384" => SHA384.HashData(data),
            "sha512" => SHA512.HashData(data),
            "sha3-256" => SHA3_256.HashData(data),
            "sha3-384" => SHA3_384.HashData(data),
            "sha3-512" => SHA3_512.HashData(data),
            "shake128" => Shake128.HashData(data, request.Number("length")),
            "shake256" => Shake256.HashData(data, request.Number("length")),
            string other => throw UnknownAlgorithm(other),
        });
    }

    private static JsonObject Hmac(Request request)
    {
        byte[] key = request.Hex("key");
        byte[] data = request.Hex("data");
        return Bytes("mac", request.Text("alg") switch
        {
            "sha1" => HMACSHA1.HashData(key, data),
            "sha256" => HMACSHA256.HashData(key, data),
            "sha384" => HMACSHA384.HashData(key, data),
            "sha512" => HMACSHA512.HashData(key, data),
            string other => throw UnknownAlgorithm(other),
        });
    }

    private static HashAlgorithmName HashName(Request request) => request.Text("alg") switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        "sha384" => HashAlgorithmName.SHA384,
        "sha512" => HashAlgorithmName.SHA512,
        string other => throw UnknownAlgorithm(other),
    };

    private static JsonObject Hkdf(Request request) => Bytes("okm", HKDF.DeriveKey(
        HashName(request), request.Hex("ikm"), request.Number("length"), request.HexOr("salt", []), request.HexOr("info", [])));

    private static JsonObject HkdfExtract(Request request) =>
        Bytes("prk", HKDF.Extract(HashName(request), request.Hex("ikm"), request.HexOr("salt", [])));

    private static JsonObject HkdfExpand(Request request) =>
        Bytes("okm", HKDF.Expand(HashName(request), request.Hex("prk"), request.Number("length"), request.HexOr("info", [])));

    private static JsonObject WithAes(Request request, Func<Aes, byte[]> transform)
    {
        using Aes aes = Aes.Create();
        aes.Key = request.Hex("key");
        return Bytes("output", transform(aes));
    }

    // The default is none, because a referee compares raw block output.
    private static PaddingMode Padding(Request request) => request.TextOr("padding", "none") switch
    {
        "none" => PaddingMode.None,
        "pkcs7" => PaddingMode.PKCS7,
        string other => throw new OracleException("BAD_REQUEST", $"unknown padding '{other}'"),
    };

    private static JsonObject GcmEncrypt(Request request)
    {
        byte[] plaintext = request.Hex("data");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[request.NumberOr("tagLength", 16)];
        using var gcm = new AesGcm(request.Hex("key"), tag.Length);
        gcm.Encrypt(request.Hex("nonce"), plaintext, ciphertext, tag, request.HexOr("aad", []));
        return new JsonObject
        {
            ["output"] = Convert.ToHexStringLower(ciphertext),
            ["tag"] = Convert.ToHexStringLower(tag),
        };
    }

    private static JsonObject GcmDecrypt(Request request)
    {
        byte[] ciphertext = request.Hex("data");
        byte[] tag = request.Hex("tag");
        byte[] plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(request.Hex("key"), tag.Length);
        try
        {
            gcm.Decrypt(request.Hex("nonce"), ciphertext, tag, plaintext, request.HexOr("aad", []));
        }
        catch (AuthenticationTagMismatchException failure)
        {
            throw new OracleException("GCM_TAG_MISMATCH", failure.Message);
        }
        return Bytes("output", plaintext);
    }

    private static JsonObject RsaKeyGen(Request request)
    {
        using RSA rsa = RSA.Create(request.Number("bits"));
        RSAParameters k = rsa.ExportParameters(true);
        return new JsonObject
        {
            ["n"] = Convert.ToHexStringLower(k.Modulus!), ["e"] = Convert.ToHexStringLower(k.Exponent!), ["d"] = Convert.ToHexStringLower(k.D!),
            ["p"] = Convert.ToHexStringLower(k.P!), ["q"] = Convert.ToHexStringLower(k.Q!),
            ["dp"] = Convert.ToHexStringLower(k.DP!), ["dq"] = Convert.ToHexStringLower(k.DQ!), ["qi"] = Convert.ToHexStringLower(k.InverseQ!),
        };
    }

    private static RSA RsaKey(Request request)
    {
        RSAParameters k = new() { Modulus = request.Hex("n"), Exponent = request.Hex("e"), D = request.HexOr("d", []), P = request.HexOr("p", []), Q = request.HexOr("q", []), DP = request.HexOr("dp", []), DQ = request.HexOr("dq", []), InverseQ = request.HexOr("qi", []) };
        if (k.D!.Length == 0) { k.D = null; k.P = null; k.Q = null; k.DP = null; k.DQ = null; k.InverseQ = null; }
        return RSA.Create(k);
    }

    private static HashAlgorithmName RsaHash(Request request) => request.Text("alg") switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        string other => throw UnknownAlgorithm(other),
    };

    private static JsonObject RsaSign(Request request)
    {
        using RSA rsa = RsaKey(request);
        return Bytes("output", rsa.SignData(request.Hex("data"), RsaHash(request), RSASignaturePadding.Pkcs1));
    }

    private static JsonObject RsaVerify(Request request)
    {
        using RSA rsa = RsaKey(request);
        bool ok = rsa.VerifyData(request.Hex("data"), request.Hex("signature"), RsaHash(request), RSASignaturePadding.Pkcs1);
        return Bytes("output", ok ? [1] : [0]);
    }

    private static JsonObject RsaEncrypt(Request request)
    {
        using RSA rsa = RsaKey(request);
        return Bytes("output", rsa.Encrypt(request.Hex("data"), RSAEncryptionPadding.Pkcs1));
    }

    private static JsonObject RsaDecrypt(Request request)
    {
        using RSA rsa = RsaKey(request);
        return Bytes("output", rsa.Decrypt(request.Hex("data"), RSAEncryptionPadding.Pkcs1));
    }

    private static JsonObject MlKemKeyGen(Request request)
    {
        using MLKem key = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, request.Hex("seed"));
        return new JsonObject
        {
            ["ek"] = Convert.ToHexStringLower(key.ExportEncapsulationKey()),
            ["dk"] = Convert.ToHexStringLower(key.ExportDecapsulationKey()),
        };
    }

    private static JsonObject MlKemEncapsulate(Request request)
    {
        using MLKem key = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, request.Hex("ek"));
        key.Encapsulate(out byte[] ciphertext, out byte[] secret);
        return new JsonObject
        {
            ["ciphertext"] = Convert.ToHexStringLower(ciphertext),
            ["secret"] = Convert.ToHexStringLower(secret),
        };
    }

    private static JsonObject MlKemDecapsulate(Request request)
    {
        using MLKem key = request.Has("seed")
            ? MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, request.Hex("seed"))
            : MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, request.Hex("dk"));
        return Bytes("secret", key.Decapsulate(request.Hex("ciphertext")));
    }

    private static OracleException UnknownAlgorithm(string name) =>
        new("UNKNOWN_ALG", $"unknown algorithm '{name}'");
}
