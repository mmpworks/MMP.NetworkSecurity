using NetSec.Vault;

namespace NetSec.Host;

/// <summary>One link of the fixture chain: the row, the text its hash covers, the prev_hash it stores, the hash of the row before as that row now stands, and whether they match.</summary>
public sealed record SealChainLink(AuditRow Row, string Text, string StoredPrevHash, string ExpectedPrevHash, bool LinkHolds, string Hash);

public sealed record SealChainWalkResult(string Edit, string Seed, IReadOnlyList<SealChainLink> Links, long FirstBadSeq);

/// <summary>
/// The seal-chain walk (docs/sections-plan.md, section 4, the chain row) on a fixture chain built by the vault's own AuditChain from its public seed.
/// It never reads the learner's audit rows. It lives in the Host because the vault is not in Core. Three edits show the chain's limits from
/// AuditChain's own doc: none (the chain is whole), middle (a changed middle row breaks the next link), and newest (a changed newest row breaks
/// nothing, because no row after it holds its hash).
/// </summary>
public static class SealChainWalks
{
    public static readonly string[] Edits = ["none", "middle", "newest"];

    /// <summary>The fixture rows, before their prev_hash is filled. Made-up names; no key bytes, as a real row holds none.</summary>
    static readonly (string At, string Caller, string Op, string Name, int? Version, string Result, string Detail)[] Fixture =
    [
        ("2030-01-01T09:00:00Z", "wizard", "put", "tls13.server", 1, "ok", "made by the wizard"),
        ("2030-01-01T09:05:00Z", "lab-05", "read", "tls13.server", 1, "ok", "lesson 5 run"),
        ("2030-01-01T09:10:00Z", "wizard", "rotate", "tls13.server", 2, "ok", "rotated"),
        ("2030-01-01T09:15:00Z", "lab-05", "read", "tls13.server", 2, "ok", "lesson 5 run"),
    ];

    public static SealChainWalkResult Build(string edit)
    {
        if (Array.IndexOf(Edits, edit) < 0) throw new ArgumentException("edit must be none, middle or newest", nameof(edit));
        List<AuditRow> rows = [];
        string prev = AuditChain.Seed;
        for (int i = 0; i < Fixture.Length; i++)
        {
            var f = Fixture[i];
            AuditRow row = new(i + 1, f.At, f.Caller, f.Op, f.Name, f.Version, f.Result, f.Detail, prev);
            rows.Add(row);
            prev = AuditChain.HashOf(row);
        }

        // The edit lands after the chain is built, as a later change to a stored row would.
        int edited = edit == "middle" ? 1 : edit == "newest" ? rows.Count - 1 : -1;
        if (edited >= 0) rows[edited] = rows[edited] with { Detail = rows[edited].Detail + " (edited)" };

        List<SealChainLink> links = [];
        string expected = AuditChain.Seed;
        foreach (AuditRow row in rows)
        {
            string hash = AuditChain.HashOf(row);
            links.Add(new SealChainLink(row, AuditChain.TextOf(row), row.PrevHash, expected, row.PrevHash == expected, hash));
            expected = hash;
        }
        return new SealChainWalkResult(edit, AuditChain.Seed, links, AuditChain.FirstBadSeq(rows));
    }
}
