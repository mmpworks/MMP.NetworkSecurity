using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Pki;
using NetSec.Platform;

namespace NetSec.Host.Security;

public sealed record CheckFact(string TypeId, string Judge, string Says, string Command, string Output, bool Passed, string? Code = null, string? Message = null, string? ControlCommand = null, string? ControlOutput = null);
public sealed record ReviewFact(string TypeId, string Name, string NotAfter, string Algorithm, string Fingerprint);

/// <summary>One line per built type: how a flow makes its key, names it, and checks it. A type with no row here reports WIZARD_PART_NOT_BUILT.</summary>
public sealed class FlowParts(SecurityStore store, Func<string, string?> env)
{
    public const string JudgeOpenSsl = "openssl", JudgeNone = "none";
    public const string SaysAgainstRoot = "checked-against-root", SaysSignatureOnly = "checked-signature-only", SaysNoOutsideJudge = "no-outside-judge", SaysWithOpenSsl = "checked-with-openssl";
    const string ReadOnlyNotAfter = "2049-12-31";

    readonly OpenSslTool _openSsl = new(env);

    static readonly HashSet<string> Built =
    [
        SecurityTypes.RootCa, SecurityTypes.TlsTrust, SecurityTypes.Tls13Server, SecurityTypes.Tls13Client, SecurityTypes.Tls11Server,
        SecurityTypes.TokenIssuer, SecurityTypes.DeviceEnrolment, SecurityTypes.LabAesKey, SecurityTypes.LabSealKey,
        SecurityTypes.DukptBdk, SecurityTypes.DukptPad,
    ];

    static readonly HashSet<string> ImportBuilt = [SecurityTypes.TokenIssuer, SecurityTypes.DeviceEnrolment, SecurityTypes.DukptBdk];

    // What OpenSSL says when it refuses each control. Any other failure proves nothing about the key, such as a tool that ran out of memory or timed out.
    const string SignatureRefused = "Signature Verification Failure", ChainRefused = "verification failed";

    public static bool IsBuilt(string typeId) => Built.Contains(typeId);
    public static bool CanImport(string typeId) => ImportBuilt.Contains(typeId);

    /// <summary>The engines read an imported token or device key as an Ed25519 seed.</summary>
    public static KeyAlgorithm ImportedAlgorithm(string typeId) => KeyAlgorithm.Ed25519;

    public static string JudgeOf(string typeId) => typeId is SecurityTypes.DeviceEnrolment or SecurityTypes.DukptBdk or SecurityTypes.DukptPad ? JudgeNone : JudgeOpenSsl;

    public static string SaysOf(string typeId) => typeId switch
    {
        SecurityTypes.DeviceEnrolment or SecurityTypes.DukptBdk or SecurityTypes.DukptPad => SaysNoOutsideJudge,
        SecurityTypes.TokenIssuer => SaysSignatureOnly,
        SecurityTypes.LabAesKey or SecurityTypes.LabSealKey => SaysWithOpenSsl,
        _ => SaysAgainstRoot,
    };

    public void Make(string typeId)
    {
        switch (typeId)
        {
            case SecurityTypes.TlsTrust or SecurityTypes.DukptPad: store.PlaceDerived(typeId); break;
            case SecurityTypes.Tls11Server: store.PlaceKey(typeId, NewRsaPem()); break;
            case SecurityTypes.LabAesKey or SecurityTypes.LabSealKey or SecurityTypes.DukptBdk: store.PlaceBytes(typeId, NewLessonKey()); break;
            default: store.PlaceKey(typeId, NewEd25519Pem()); break;
        }
    }

    public ReviewFact Review(string typeId)
    {
        ITrainingKey? key = store.PlacedKey(typeId) ?? store.PlacedKey(typeId == SecurityTypes.DukptPad ? SecurityTypes.DukptBdk : SecurityTypes.RootCa);
        return new ReviewFact(typeId, NameOf(typeId), ReadOnlyNotAfter, key is null ? "" : AlgorithmOf(key), key is null ? "" : SecurityStore.FingerprintOf(key.CopyPublic()));
    }

    public CheckFact Check(string typeId, string proofDirectory)
    {
        Directory.CreateDirectory(proofDirectory);
        return typeId switch
        {
            SecurityTypes.TokenIssuer => CheckToken(proofDirectory),
            SecurityTypes.DeviceEnrolment => CheckDevice(),
            SecurityTypes.LabAesKey => CheckAesKey(proofDirectory),
            SecurityTypes.LabSealKey => CheckSealKey(proofDirectory),
            SecurityTypes.DukptBdk or SecurityTypes.DukptPad => PaymentKeys.Check(typeId, Placed(SecurityTypes.DukptBdk).CopyMaterial()),
            SecurityTypes.RootCa => CheckRoot(proofDirectory),
            SecurityTypes.TlsTrust => CheckChain(typeId, SecurityTypes.Tls13Server, proofDirectory),
            _ => CheckChain(typeId, typeId, proofDirectory),
        };
    }

    static string NameOf(string typeId) => typeId switch
    {
        SecurityTypes.RootCa or SecurityTypes.TlsTrust => TrainingCa.RootName,
        SecurityTypes.Tls13Server or SecurityTypes.Tls11Server => TrainingPki.ServerName,
        SecurityTypes.Tls13Client or SecurityTypes.DeviceEnrolment => TrainingPki.ClientName,
        SecurityTypes.TokenIssuer => "https://pump.training/issuer",
        _ => typeId,
    };

    static string AlgorithmOf(ITrainingKey key) => key.Algorithm switch
    {
        KeyAlgorithm.Rsa2048 => "RSA-2048",
        KeyAlgorithm.Raw => key.CopyMaterial().Length + " random bytes",
        _ => "Ed25519",
    };

    static byte[] NewLessonKey()
    {
        byte[] key = new byte[NetSec.Labs.LabCredentials.LessonKeyBytes];
        new OsRandom().Fill(key, 0, key.Length);
        return key;
    }

    static string NewEd25519Pem()
    {
        byte[] seed = new byte[32];
        new OsRandom().Fill(seed, 0, seed.Length);
        return TrainingPki.Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(seed));
    }

    static string NewRsaPem()
    {
        using RSA rsa = RSA.Create(2048);
        return TrainingPki.Pem("PRIVATE KEY", rsa.ExportPkcs8PrivateKey());
    }

    /// <summary>The signature only. A11 and the suite's Go referee judge the claims from outside the product.</summary>
    CheckFact CheckToken(string dir)
    {
        ITrainingKey key = Placed(SecurityTypes.TokenIssuer);
        string[] parts = Token.Issue(key, "{\"iss\":\"https://pump.training/issuer\",\"aud\":\"https://pump.training/api\"}").Split('.');
        byte[] input = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        File.WriteAllText(Path.Combine(dir, "issuer.pub"), TrainingPki.Pem("PUBLIC KEY", TrainingCa.Ed25519Spki(key.CopyPublic())));
        File.WriteAllBytes(Path.Combine(dir, "signing-input.bin"), input);
        File.WriteAllBytes(Path.Combine(dir, "signature.bin"), Base64Url.Decode(parts[2]));
        byte[] changed = (byte[])input.Clone();
        changed[0] ^= 1;
        File.WriteAllBytes(Path.Combine(dir, "changed-input.bin"), changed);

        const string Arguments = "pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin";
        return Judged(SecurityTypes.TokenIssuer, SaysSignatureOnly, dir, Arguments, Arguments.Replace("signing-input", "changed-input"), SignatureRefused);
    }

    /// <summary>Our own check only: the key signs a challenge, and the public half verifies it. No outside tool can judge a passkey-shaped login.</summary>
    CheckFact CheckDevice()
    {
        ITrainingKey key = Placed(SecurityTypes.DeviceEnrolment);
        byte[] challenge = new byte[32];
        new OsRandom().Fill(challenge, 0, challenge.Length);
        const string Origin = "https://pump.training";
        bool passed = Challenge.Verify(key.CopyPublic(), challenge, Origin, Challenge.Sign(key.CopyMaterial(), challenge, Origin)).Allowed;
        return new CheckFact(SecurityTypes.DeviceEnrolment, JudgeNone, SaysNoOutsideJudge, "", "", passed, passed ? null : "CHECK_FAILED", passed ? null : "This key did not sign and verify a test challenge. Make the keys again.");
    }

    CheckFact CheckRoot(string dir) => CheckChain(SecurityTypes.RootCa, SecurityTypes.Tls13Server, dir);

    /// <summary>The leaf must verify under the learner's root, and must not verify under another root of the same name.</summary>
    CheckFact CheckChain(string typeId, string leafType, string dir)
    {
        WriteChain(leafType, dir);
        File.WriteAllText(Path.Combine(dir, "other-root.pem"), TrainingPki.Pem("CERTIFICATE", new TrainingCa(KeyFileReader.Parse(NewEd25519Pem(), "other-root"), TrainingCa.RootName).RootCertificateDer));
        return Judged(typeId, SaysAgainstRoot, dir, "verify -CAfile root.pem leaf.pem", "verify -CAfile other-root.pem leaf.pem", ChainRefused);
    }

    /// <summary>The learner's key as placed, whatever the type's mode. A check must judge this key and never a built-in one.</summary>
    ITrainingKey Placed(string typeId) => store.PlacedKey(typeId)
        ?? throw new NetSecException(NetSecError.Of(ErrorCodes.SecurityTypeNotReady, $"{typeId} has no key placed. Run the flow {store.FlowOf(typeId)}."));

    void WriteChain(string leafType, string dir)
    {
        TrainingCa ca = new(Placed(SecurityTypes.RootCa), TrainingCa.RootName);
        byte[] leaf = leafType switch
        {
            SecurityTypes.Tls13Client => TrainingPki.ClientCertificate(ca, Placed(SecurityTypes.Tls13Client)),
            SecurityTypes.Tls11Server => ca.IssueServerCertificate(TrainingPki.ServerName, Placed(SecurityTypes.Tls11Server).CopyPublic(), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter),
            _ => TrainingPki.ServerCertificate(ca, Placed(SecurityTypes.Tls13Server)),
        };
        File.WriteAllText(Path.Combine(dir, "root.pem"), TrainingPki.Pem("CERTIFICATE", ca.RootCertificateDer));
        File.WriteAllText(Path.Combine(dir, "leaf.pem"), TrainingPki.Pem("CERTIFICATE", leaf));
    }

    const string KeyInCommand = "<key>";
    static readonly byte[] LessonCheckBlock = Encoding.ASCII.GetBytes("MMP.NetworkSecur");

    /// <summary>modes-design.md section 8: HMAC and CMAC under the key, and for lab.aes-key also one AES block. Lessons 1 and 2 use the keys these ways.</summary>
    CheckFact CheckAesKey(string dir)
    {
        byte[] key = Placed(SecurityTypes.LabAesKey).CopyMaterial();
        return AllOf(() => CheckBlock(SecurityTypes.LabAesKey, key, dir), () => CheckHmac(SecurityTypes.LabAesKey, key, dir), () => CheckCmac(SecurityTypes.LabAesKey, key, dir));
    }

    CheckFact CheckSealKey(string dir)
    {
        byte[] key = Placed(SecurityTypes.LabSealKey).CopyMaterial();
        return AllOf(() => CheckHmac(SecurityTypes.LabSealKey, key, dir), () => CheckCmac(SecurityTypes.LabSealKey, key, dir));
    }

    /// <summary>Each check runs in order and the first failure is the answer. A pass names every command and every control that ran.</summary>
    static CheckFact AllOf(params Func<CheckFact>[] checks)
    {
        List<CheckFact> passed = [];
        foreach (Func<CheckFact> check in checks)
        {
            CheckFact fact = check();
            if (!fact.Passed) return fact;
            passed.Add(fact);
        }
        const string Between = " ; ";
        return passed[0] with
        {
            Command = string.Join(Between, passed.Select(f => f.Command)),
            Output = string.Join(Between, passed.Select(f => f.Output)),
            ControlCommand = string.Join(Between, passed.Select(f => f.ControlCommand)),
            ControlOutput = string.Join(Between, passed.Select(f => f.ControlOutput)),
        };
    }

    static string[] InputFiles(string dir, string stem)
    {
        byte[] changed = (byte[])LessonCheckBlock.Clone();
        changed[0] ^= 1;
        File.WriteAllBytes(Path.Combine(dir, stem + ".bin"), LessonCheckBlock);
        File.WriteAllBytes(Path.Combine(dir, stem + "-changed.bin"), changed);
        return [stem + ".bin", stem + "-changed.bin"];
    }

    /// <summary>OpenSSL locks one block under the key, and it must give the block the course's AES gives. Another block must give another answer.</summary>
    CheckFact CheckBlock(string typeId, byte[] key, string dir)
    {
        string[] input = InputFiles(dir, "block");
        byte[] engine = new byte[LessonCheckBlock.Length];
        new AesKey(key).EncryptBlock(LessonCheckBlock, 0, engine, 0);
        string Arguments(string keyText, string file, string output) => $"enc -aes-128-ecb -nopad -K {keyText} -in {file} -out {output}";
        string hex = Hex.Encode(key);
        return Compared(typeId, dir, hex, Hex.Encode(engine), Arguments(hex, input[0], "locked.bin"), Arguments(hex, input[1], "changed-locked.bin"),
            Arguments(KeyInCommand, input[0], "locked.bin"), Arguments(KeyInCommand, input[1], "changed-locked.bin"),
            () => Hex.Encode(File.ReadAllBytes(Path.Combine(dir, "locked.bin"))), () => Hex.Encode(File.ReadAllBytes(Path.Combine(dir, "changed-locked.bin"))));
    }

    /// <summary>OpenSSL computes the HMAC with the key, and it must give the tag the course's HMAC gives. Another message must give another tag.</summary>
    CheckFact CheckHmac(string typeId, byte[] key, string dir)
    {
        string[] input = InputFiles(dir, "hmac");
        string Arguments(string keyText, string file) => $"mac -digest SHA256 -macopt hexkey:{keyText} -in {file} HMAC";
        string hex = Hex.Encode(key);
        return Compared(typeId, dir, hex, Hex.Encode(Hmac.Compute(Hashes.Sha256, key, LessonCheckBlock)), Arguments(hex, input[0]), Arguments(hex, input[1]),
            Arguments(KeyInCommand, input[0]), Arguments(KeyInCommand, input[1]), null, null);
    }

    /// <summary>OpenSSL computes the AES-CMAC with the key, and it must give the tag the course's CMAC gives. Another message must give another tag.</summary>
    CheckFact CheckCmac(string typeId, byte[] key, string dir)
    {
        string[] input = InputFiles(dir, "cmac");
        string Arguments(string keyText, string file) => $"mac -cipher AES-128-CBC -macopt hexkey:{keyText} -in {file} CMAC";
        string hex = Hex.Encode(key);
        return Compared(typeId, dir, hex, Hex.Encode(Cmac.Compute(new AesKey(key), LessonCheckBlock)), Arguments(hex, input[0]), Arguments(hex, input[1]),
            Arguments(KeyInCommand, input[0]), Arguments(KeyInCommand, input[1]), null, null);
    }

    /// <summary>
    /// The tool and the course must give one answer, and the tool must give another for a changed input. The key is on the tool's command line,
    /// so the command this returns shows a mark in its place: the fact reaches the screen with Show keys off.
    /// </summary>
    CheckFact Compared(string typeId, string dir, string keyHex, string engineAnswer, string arguments, string mustDiffer, string shownCommand, string shownControl, Func<string>? readAnswer, Func<string>? readControl)
    {
        CheckFact fact = ComparedRaw(typeId, dir, engineAnswer, arguments, mustDiffer, shownCommand, shownControl, readAnswer, readControl);
        // The tool's own words reach the screen. If a tool ever repeats its command line, the key must not go with them.
        string Hidden(string? text) => (text ?? "").Replace(keyHex, KeyInCommand, StringComparison.OrdinalIgnoreCase);
        return fact with { Output = Hidden(fact.Output), ControlOutput = fact.ControlOutput is null ? null : Hidden(fact.ControlOutput) };
    }

    CheckFact ComparedRaw(string typeId, string dir, string engineAnswer, string arguments, string mustDiffer, string shownCommand, string shownControl, Func<string>? readAnswer, Func<string>? readControl)
    {
        string? openssl = _openSsl.Locate();
        string command = "openssl " + shownCommand, control = "openssl " + shownControl;
        if (openssl is null) return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, "", false, "REFEREE_MISSING", "OpenSSL is not on this machine, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        (int code, string output) = OpenSslTool.Run(openssl, arguments, dir);
        if (code == OpenSslTool.CouldNotStart) return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, output, false, "REFEREE_MISSING", "OpenSSL could not start, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        if (code != 0) return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, output, false, "CHECK_FAILED", "OpenSSL did not accept this key. Make the keys again.");
        string answer = readAnswer is null ? output.Trim() : readAnswer();
        if (!string.Equals(answer, engineAnswer, StringComparison.OrdinalIgnoreCase))
            return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, answer, false, "CHECK_FAILED", "OpenSSL and this course gave different answers with this key.");
        (int controlCode, string controlOutput) = OpenSslTool.Run(openssl, mustDiffer, dir);
        string other = controlCode != 0 ? "" : readControl is null ? controlOutput.Trim() : readControl();
        if (controlCode != 0 || string.Equals(other, engineAnswer, StringComparison.OrdinalIgnoreCase))
            return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, answer, false, "CHECK_FAILED", "OpenSSL gave the same answer for a changed input, so this check proves nothing.", control, other);
        return new CheckFact(typeId, JudgeOpenSsl, SaysWithOpenSsl, command, answer, true, null, null, control, other);
    }

    /// <summary>A check must have a way to fail, so a second run with one thing changed must be refused by the same tool.</summary>
    CheckFact Judged(string typeId, string says, string dir, string arguments, string mustFail, string refusal)
    {
        string? openssl = _openSsl.Locate();
        if (openssl is null) return new CheckFact(typeId, JudgeOpenSsl, says, "openssl " + arguments, "", false, "REFEREE_MISSING", "OpenSSL is not on this machine, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        (int code, string output) = OpenSslTool.Run(openssl, arguments, dir);
        string command = "openssl " + arguments;
        if (code == OpenSslTool.CouldNotStart) return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "REFEREE_MISSING", "OpenSSL could not start, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        if (code != 0) return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL did not accept this key. Make the keys again.");
        (int controlCode, string controlOutput) = OpenSslTool.Run(openssl, mustFail, dir);
        string control = "openssl " + mustFail;
        if (controlCode <= 0 || !controlOutput.Contains(refusal, StringComparison.Ordinal))
            return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL did not refuse a changed input for the expected reason, so this check proves nothing.", control, controlOutput);
        return new CheckFact(typeId, JudgeOpenSsl, says, command, output, true, null, null, control, controlOutput);
    }
}
