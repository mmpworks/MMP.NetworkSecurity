using System.Security.Cryptography;
using System.Text;

namespace NetSec.Vault;

/// <summary>
/// GEM:seeded-hash-linked-custody-chain — each audit row stores the hash of the row before it, so a changed row breaks the link to the next one.
/// The first row links to a fixed seed. This finds an edit; it does not stop one, and the newest row has no row after it to show its change.
/// </summary>
public static class AuditChain
{
    public static readonly string Seed = Hash("netsec-vault-audit-seed-v1");

    /// <summary>The value the next row stores as prev_hash.</summary>
    public static string HashOf(AuditRow row) => Hash(string.Join("\n",
        row.PrevHash, row.Seq.ToString(System.Globalization.CultureInfo.InvariantCulture), row.At, row.Caller, row.Op, row.Name,
        row.Version?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "", row.Result, row.Detail));

    /// <summary>The seq of the first row whose prev_hash does not fit the row before it, or 0 while the chain is whole.</summary>
    public static long FirstBadSeq(IReadOnlyList<AuditRow> rows)
    {
        string expected = Seed;
        foreach (AuditRow row in rows)
        {
            if (row.PrevHash != expected) return row.Seq;
            expected = HashOf(row);
        }
        return 0;
    }

    static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}

/// <summary>One format for a public key's fingerprint, shared by the vault and the Host's screens.</summary>
public static class Fingerprints
{
    public static string OfPublic(byte[] publicPart) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(publicPart)).TrimEnd('=');

    /// <summary>A secret with no public half shows a check value: the first 3 bytes of an HMAC over nothing, as a key check value shows a few bytes.</summary>
    public static string OfSecret(byte[] secret) => "check:" + Convert.ToHexString(HMACSHA256.HashData(secret, Array.Empty<byte>())[..3]).ToLowerInvariant();
}
