using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
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

    public static bool IsBuilt(string typeId) => Built.Contains(typeId);
    public static bool CanImport(string typeId) => ImportBuilt.Contains(typeId);

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
        return new ReviewFact(typeId, NameOf(typeId), ReadOnlyNotAfter, AlgorithmOf(typeId), key is null ? "" : SecurityStore.FingerprintOf(key.CopyPublic()));
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

    static string AlgorithmOf(string typeId) => typeId == SecurityTypes.Tls11Server ? "RSA-2048" : "Ed25519";

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
        ITrainingKey key = store.PlacedKey(SecurityTypes.TokenIssuer)!;
        string[] parts = Token.Issue(key, "{\"iss\":\"https://pump.training/issuer\",\"aud\":\"https://pump.training/api\"}").Split('.');
        byte[] input = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        File.WriteAllText(Path.Combine(dir, "issuer.pub"), TrainingPki.Pem("PUBLIC KEY", TrainingCa.Ed25519Spki(key.CopyPublic())));
        File.WriteAllBytes(Path.Combine(dir, "signing-input.bin"), input);
        File.WriteAllBytes(Path.Combine(dir, "signature.bin"), Base64Url.Decode(parts[2]));
        byte[] changed = (byte[])input.Clone();
        changed[0] ^= 1;
        File.WriteAllBytes(Path.Combine(dir, "changed-input.bin"), changed);

        const string Arguments = "pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin";
        return Judged(SecurityTypes.TokenIssuer, SaysSignatureOnly, dir, Arguments, Arguments.Replace("signing-input", "changed-input"));
    }

    /// <summary>Our own check only: the key signs a challenge, and the public half verifies it. No outside tool can judge a passkey-shaped login.</summary>
    CheckFact CheckDevice()
    {
        ITrainingKey key = store.PlacedKey(SecurityTypes.DeviceEnrolment)!;
        byte[] challenge = new byte[32];
        new OsRandom().Fill(challenge, 0, challenge.Length);
        const string Origin = "https://pump.training";
        bool passed = Challenge.Verify(key.CopyPublic(), challenge, Origin, Challenge.Sign(key.CopyMaterial(), challenge, Origin)).Allowed;
        return new CheckFact(SecurityTypes.DeviceEnrolment, JudgeNone, SaysNoOutsideJudge, "", "", passed, passed ? null : "CHECK_FAILED", passed ? null : "This key did not sign and verify a test challenge. Make the keys again.");
    }

    CheckFact CheckRoot(string dir)
    {
        WriteChain(SecurityTypes.Tls13Server, dir);
        File.WriteAllText(Path.Combine(dir, "other-root.pem"), TrainingPki.Pem("CERTIFICATE", new TrainingCa(KeyFileReader.Parse(NewEd25519Pem(), "other-root"), TrainingCa.RootName).RootCertificateDer));
        return Judged(SecurityTypes.RootCa, SaysAgainstRoot, dir, "verify -CAfile root.pem leaf.pem", "verify -CAfile other-root.pem leaf.pem");
    }

    CheckFact CheckChain(string typeId, string leafType, string dir)
    {
        WriteChain(leafType, dir);
        return Judged(typeId, SaysAgainstRoot, dir, "verify -CAfile root.pem leaf.pem", null);
    }

    void WriteChain(string leafType, string dir)
    {
        CredentialSet set = store.Credentials();
        TrainingCa ca = new(set);
        byte[] leaf = leafType switch
        {
            SecurityTypes.Tls13Client => TrainingPki.ClientCertificate(ca, set.Find(KeyIds.ClientTlsEd25519)),
            SecurityTypes.Tls11Server => ca.IssueServerCertificate(TrainingPki.ServerName, set.Find(KeyIds.ServerTls11Rsa).CopyPublic(), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter),
            _ => TrainingPki.ServerCertificate(ca, set.Find(KeyIds.ServerTlsEd25519)),
        };
        File.WriteAllText(Path.Combine(dir, "root.pem"), TrainingPki.Pem("CERTIFICATE", ca.RootCertificateDer));
        File.WriteAllText(Path.Combine(dir, "leaf.pem"), TrainingPki.Pem("CERTIFICATE", leaf));
    }

    /// <summary>A check must have a way to fail, so a second run with one thing changed must be refused by the same tool.</summary>
    CheckFact Judged(string typeId, string says, string dir, string arguments, string? mustFail)
    {
        string? openssl = OpenSslPath();
        if (openssl is null) return new CheckFact(typeId, JudgeOpenSsl, says, "openssl " + arguments, "", false, "REFEREE_MISSING", "OpenSSL is not on this machine, so this key is saved and not yet checked. Set NETSEC_OPENSSL to its path.");
        (int code, string output) = Run(openssl, arguments, dir);
        string command = "openssl " + arguments;
        if (code != 0) return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL did not accept this key. Make the keys again.");
        if (mustFail is not null && Run(openssl, mustFail, dir).Code == 0)
            return new CheckFact(typeId, JudgeOpenSsl, says, command, output, false, "CHECK_FAILED", "OpenSSL also accepted a changed input, so this check proves nothing.");
        return new CheckFact(typeId, JudgeOpenSsl, says, command, output, true);
    }

    string? OpenSslPath()
    {
        string? set = env("NETSEC_OPENSSL");
        if (!string.IsNullOrEmpty(set)) return File.Exists(set) ? set : null;
        const string Pinned = @"C:\Program Files\Git\mingw64\bin\openssl.exe";
        return File.Exists(Pinned) ? Pinned : null;
    }

    static (int Code, string Output) Run(string exe, string arguments, string dir)
    {
        ProcessStartInfo info = new(exe, arguments) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using Process process = Process.Start(info)!;
        Task<string> errors = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            return (-1, "the tool did not finish in 30 s");
        }
        return (process.ExitCode, (output + errors.Result).Trim());
    }
}
