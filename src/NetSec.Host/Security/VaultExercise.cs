using System.Text;
using NetSec.Bytes;
using NetSec.Pki;
using NetSec.Vault;

namespace NetSec.Host.Security;

public sealed record ExerciseSigned(string KeyName, int Version, string InputHex, string SignatureHex, string PublicKeyHex, string Command, string Output, string Code);
public sealed record ExerciseDerived(string KeyName, int Version, string Label, string OutputHex, string Code);
public sealed record AuditChecked(AuditRow[] Rows, long FirstBadSeq, string Code);

/// <summary>
/// The vault exercise (docs/modes-design.md section 4.3): sign, derive, refuse, audit, on two keys that never leave the vault.
/// It is routes, not a lab, because the learner types. It changes no mode and no key a lesson uses.
/// </summary>
public sealed class VaultExercise
{
    public const string SigningKey = "exercise/signing", DeriveKey = "exercise/derive";
    const string Caller = "host/vault-exercise", SetupCaller = "host/vault-setup", CodeOk = "OK";
    const string VerifyArguments = "pkeyutl -verify -pubin -inkey public.pem -rawin -in message.bin -sigfile signature.bin";

    readonly IVault _vault;
    readonly OpenSslTool _openSsl;
    readonly string _proofRoot;

    public VaultExercise(IVault vault, OpenSslTool openSsl, string proofRoot)
    {
        _vault = vault;
        _openSsl = openSsl;
        _proofRoot = proofRoot;
        Ensure(SigningKey, new VaultKeyPolicy(VaultAlgorithms.Ed25519, false, [VaultOps.Sign]));
        Ensure(DeriveKey, new VaultKeyPolicy(VaultAlgorithms.HkdfSecret, false, [VaultOps.Derive]));
    }

    /// <summary>The two keys exist from the first start, so the exercise needs no flow. Non-exportable is set here and is one-way.</summary>
    void Ensure(string name, VaultKeyPolicy policy)
    {
        if (!_vault.Exists(name)) _vault.CreateKey(name, policy, SetupCaller);
        if (_vault.Describe(name).Versions == 0) _vault.Generate(name, SetupCaller);
    }

    /// <summary>The key signs inside the vault. OpenSSL then judges the signature from the public key alone, and its words go back to the screen.</summary>
    public ExerciseSigned Sign(string text)
    {
        byte[] message = Encoding.UTF8.GetBytes(text), signature = _vault.Sign(SigningKey, message, Caller);
        byte[] publicKey = _vault.PublicKey(SigningKey, null)!;
        (string output, string code) = Verify(publicKey, message, signature);
        return new ExerciseSigned(SigningKey, _vault.Describe(SigningKey).Versions, Hex.Encode(message), Hex.Encode(signature), Hex.Encode(publicKey), "openssl " + VerifyArguments, output, code);
    }

    (string Output, string Code) Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        string? openssl = _openSsl.Locate();
        if (openssl is null) return ("OpenSSL is not on this machine, so no outside tool judged this signature. Set NETSEC_OPENSSL to its path.", "REFEREE_MISSING");
        string dir = Path.Combine(_proofRoot, "vault-exercise-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "public.pem"), TrainingPki.Pem("PUBLIC KEY", TrainingCa.Ed25519Spki(publicKey)));
            File.WriteAllBytes(Path.Combine(dir, "message.bin"), message);
            File.WriteAllBytes(Path.Combine(dir, "signature.bin"), signature);
            (int exit, string output) = OpenSslTool.Run(openssl, VerifyArguments, dir);
            return (output, exit == 0 ? CodeOk : "CHECK_FAILED");
        }
        finally { Directory.Delete(dir, true); }
    }

    /// <summary>HKDF-SHA256 with the typed label as the info. The idea behind a DUKPT base key; not DUKPT, because a typed label stands in for a KSN.</summary>
    public ExerciseDerived Derive(string label) =>
        new(DeriveKey, _vault.Describe(DeriveKey).Versions, label, Hex.Encode(_vault.Derive(DeriveKey, Encoding.UTF8.GetBytes(label), Caller)), CodeOk);

    /// <summary>Always refused: VAULT_EXPORT_REFUSED, and the refusal is an audit row.</summary>
    public void Export() => _vault.Export(SigningKey, Caller);

    public AuditChecked AuditCheck()
    {
        AuditRow[] rows = _vault.Audit(0, int.MaxValue);
        return new AuditChecked(rows, AuditChain.FirstBadSeq(rows), CodeOk);
    }
}
