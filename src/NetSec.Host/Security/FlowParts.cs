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
    public const string SaysAgainstRoot = "checked-against-root", SaysSignatureOnly = "checked-signature-only", SaysNoOutsideJudge = "no-outside-judge";
    const string ReadOnlyNotAfter = "2049-12-31";

    static readonly HashSet<string> Built =
    [
        SecurityTypes.RootCa, SecurityTypes.TlsTrust, SecurityTypes.Tls13Server, SecurityTypes.Tls13Client, SecurityTypes.Tls11Server,
        SecurityTypes.TokenIssuer, SecurityTypes.DeviceEnrolment,
    ];

    static readonly HashSet<string> ImportBuilt = [SecurityTypes.TokenIssuer, SecurityTypes.DeviceEnrolment];

    // What OpenSSL says when it refuses each control. Any other failure proves nothing about the key, such as a tool that ran out of memory or timed out.
    const string SignatureRefused = "Signature Verification Failure", ChainRefused = "verification failed";

    public static bool IsBuilt(string typeId) => Built.Contains(typeId);
    public static bool CanImport(string typeId) => ImportBuilt.Contains(typeId);

    /// <summary>The engines read an imported token or device key as an Ed25519 seed.</summary>
    public static KeyAlgorithm ImportedAlgorithm(string typeId) => KeyAlgorithm.Ed25519;

    public static string JudgeOf(string typeId) => typeId == SecurityTypes.DeviceEnrolment ? JudgeNone : JudgeOpenSsl;

    public static string SaysOf(string typeId) => typeId switch
    {
        SecurityTypes.DeviceEnrolment => SaysNoOutsideJudge,
        SecurityTypes.TokenIssuer => SaysSignatureOnly,
        _ => SaysAgainstRoot,
    };

    public void Make(string typeId)
    {
        switch (typeId)
        {
            case SecurityTypes.TlsTrust: store.PlaceDerived(typeId); break;
            case SecurityTypes.Tls11Server: store.PlaceKey(typeId, NewRsaPem()); break;
            default: store.PlaceKey(typeId, NewEd25519Pem()); break;
        }
    }

    public ReviewFact Review(string typeId)
    {
        ITrainingKey? key = store.PlacedKey(typeId) ?? store.PlacedKey(SecurityTypes.RootCa);
        return new ReviewFact(typeId, NameOf(typeId), ReadOnlyNotAfter, key is null ? "" : AlgorithmOf(key), key is null ? "" : SecurityStore.FingerprintOf(key.CopyPublic()));
    }

    public CheckFact Check(string typeId, string proofDirectory)
    {
        Directory.CreateDirectory(proofDirectory);
        return typeId switch
        {
            SecurityTypes.TokenIssuer => CheckToken(proofDirectory),
            SecurityTypes.DeviceEnrolment => CheckDevice(),
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

    static string AlgorithmOf(ITrainingKey key) => key.Algorithm == KeyAlgorithm.Rsa2048 ? "RSA-2048" : "Ed25519";

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

    /// <summary>A check must have a way to fail, so a second run with one thing changed must be refused by the same tool.</summary>
    CheckFact Judged(string typeId, string says, string dir, string arguments, string mustFail, string refusal)
    {
        string? openssl = OpenSslPath();
        if (openssl is null) return new CheckFact(typeId, JudgeOpenSsl, says, "openssl " + arguments, "", false, "REFEREE_MISSING", "OpenSSL is not on this machine, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        (int code, string output) = Run(openssl, arguments, dir);
        string command = "openssl " + arguments;
        if (code == CouldNotStart) return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "REFEREE_MISSING", "OpenSSL could not start, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        if (code != 0) return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL did not accept this key. Make the keys again.");
        (int controlCode, string controlOutput) = Run(openssl, mustFail, dir);
        string control = "openssl " + mustFail;
        if (controlCode <= 0 || !controlOutput.Contains(refusal, StringComparison.Ordinal))
            return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL did not refuse a changed input for the expected reason, so this check proves nothing.", control, controlOutput);
        return new CheckFact(typeId, JudgeOpenSsl, says, command, output, true, null, null, control, controlOutput);
    }

    string? OpenSslPath()
    {
        string? set = env("NETSEC_OPENSSL");
        if (!string.IsNullOrEmpty(set)) return File.Exists(set) ? set : null;
        const string Pinned = @"C:\Program Files\Git\mingw64\bin\openssl.exe";
        return File.Exists(Pinned) ? Pinned : null;
    }

    const int CouldNotStart = -2, TimedOut = -1;

    static Process? TryStart(ProcessStartInfo info)
    {
        try { return Process.Start(info); }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    static (int Code, string Output) Run(string exe, string arguments, string dir)
    {
        ProcessStartInfo info = new(exe, arguments) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using Process? process = TryStart(info);
        if (process is null) return (CouldNotStart, "the tool could not start");
        Task<string> errors = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            return (TimedOut, "the tool did not finish in 30 s");
        }
        return (process.ExitCode, (output + errors.Result).Trim());
    }
}
