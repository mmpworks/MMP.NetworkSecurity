using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// The seal-chain walk (docs/sections-plan.md section 4, slice P6): GET /api/walk/seal-chain?edit=none|middle|newest. It runs on a 4-row
    /// fixture chain from a public seed, never a learner's audit rows, so it stays open with Show keys OFF. The suite composes each row's text
    /// itself, from the row's own fields in the audit table's order (docs/modes-design.md line 370: prev_hash, seq, at, caller, op, name,
    /// version, result, detail, joined by newlines, with an empty version for none), and hashes it with .NET's SHA-256. The seed is
    /// SHA-256("netsec-vault-audit-seed-v1"). The chain's limit 1 is pinned: an edit to the newest row breaks no link.
    /// </summary>
    public static class SealChainWalkClauses
    {
        public const string Path = "/api/walk/seal-chain";
        public const string SeedText = "netsec-vault-audit-seed-v1";

        public static string Sha256Hex(string text)
        {
            using (SHA256 sha = SHA256.Create()) return Hex.Encode(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        }

        static string Field(Dictionary<string, object> d, string name)
        {
            if (!d.ContainsKey(name) || d[name] == null) return "";
            object v = d[name];
            return v is double ? ((double)v).ToString("0", CultureInfo.InvariantCulture) : Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        /// <summary>The text the suite composes for one row: its fields in the audit table's order, joined by newlines.</summary>
        public static string Compose(Dictionary<string, object> link)
        {
            return string.Join("\n", Field(link, "storedPrevHash"), Field(link, "seq"), Field(link, "at"), Field(link, "caller"), Field(link, "op"),
                Field(link, "name"), Field(link, "version"), Field(link, "result"), Field(link, "detail"));
        }

        static List<Dictionary<string, object>> Links(Reply r, string where)
        {
            List<Dictionary<string, object>> links = new List<Dictionary<string, object>>();
            foreach (object o in MiniJson.Arr(r.Json, "links") ?? new List<object>()) links.Add(MiniJson.AsObject(o));
            Check.True(links.Count == 4, where + ": " + links.Count + " links, and the fixture chain has 4");
            return links;
        }

        [Clause("A19.host.seal-chain-walk-open-and-own-hash")]
        public static string WalkOpenAndOwnHash(Ctx c)
        {
            string seed = Sha256Hex(SeedText);
            using (HostProc h = A17.Host(c, "walk-seal-chain"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                Dictionary<string, List<Dictionary<string, object>>> byEdit = new Dictionary<string, List<Dictionary<string, object>>>();
                Dictionary<string, int> wantBad = new Dictionary<string, int> { { "none", 0 }, { "middle", 3 }, { "newest", 0 } };
                foreach (string edit in new string[] { "none", "middle", "newest" })
                {
                    string where = "edit=" + edit;
                    Reply r = HostHttp.Get(h, Path + "?edit=" + edit);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P6)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + where + " got " + r + ". The walk runs on a public fixture chain, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, where + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    Check.Equal(where + ": seed is SHA-256(\"" + SeedText + "\")", seed, (MiniJson.Str(r.Json, "seed") ?? "").ToLowerInvariant());
                    List<Dictionary<string, object>> links = Links(r, where);
                    string expected = seed;
                    int firstBad = 0;
                    for (int i = 0; i < links.Count; i++)
                    {
                        Dictionary<string, object> l = links[i];
                        string lw = where + " link " + i;
                        Check.True((int)MiniJson.Num(l, "seq", -1) == i + 1, lw + ": seq should be " + (i + 1));
                        string text = Compose(l);
                        Check.Equal(lw + ": text is the row's fields in the audit table's order, composed by the suite", text, MiniJson.Str(l, "text") ?? "");
                        Check.Equal(lw + ": hash is SHA-256(text)", Sha256Hex(text), (MiniJson.Str(l, "hash") ?? "").ToLowerInvariant());
                        Check.Equal(lw + ": expectedPrevHash is the hash of the row before (the seed for row 1)", expected, (MiniJson.Str(l, "expectedPrevHash") ?? "").ToLowerInvariant());
                        bool holds = Field(l, "storedPrevHash").ToLowerInvariant() == expected;
                        Check.True(MiniJson.Bool(l, "linkHolds", !holds) == holds, lw + ": linkHolds should be " + holds);
                        if (!holds && firstBad == 0) firstBad = i + 1;
                        expected = Sha256Hex(text);
                    }
                    Check.True(firstBad == wantBad[edit], where + ": the suite's walk finds the first bad link at " + firstBad + ", and the plan for this edit is " + wantBad[edit]);
                    Check.True((int)MiniJson.Num(r.Json, "firstBadSeq", -1) == firstBad, where + ": firstBadSeq is " + MiniJson.Num(r.Json, "firstBadSeq", -1) + ", and the chain's first bad link is " + firstBad);
                    byEdit[edit] = links;
                }
                // The edits are real: middle changes row 2's content and newest changes row 4's, and nothing else differs from the whole chain.
                for (int i = 0; i < 4; i++)
                {
                    bool midSame = Compose(byEdit["middle"][i]) == Compose(byEdit["none"][i]);
                    bool newSame = Compose(byEdit["newest"][i]) == Compose(byEdit["none"][i]);
                    Check.True(midSame == (i != 1), "edit=middle: row " + (i + 1) + (i == 1 ? " should differ from" : " should equal") + " the whole chain's row");
                    Check.True(newSame == (i != 3), "edit=newest: row " + (i + 1) + (i == 3 ? " should differ from" : " should equal") + " the whole chain's row");
                }
                Reply bad = HostHttp.Get(h, Path + "?edit=nope");
                Check.True(bad.Status == 400 && bad.Code == "WALK_BAD_ARGUMENT", "an unknown edit should get 400 WALK_BAD_ARGUMENT, and got " + bad);
                // A missing edit is not an error: it defaults to none (Richard's shape), so it must give the whole chain.
                Reply plain = HostHttp.Get(h, Path);
                Check.True(plain.Ok && plain.Json != null, "GET " + Path + " with no edit should answer as edit=none, and got " + plain);
                Check.True(MiniJson.Str(plain.Json, "edit") == "none" && (int)MiniJson.Num(plain.Json, "firstBadSeq", -1) == 0, "with no edit the reply should be edit none, with firstBadSeq 0");
                List<Dictionary<string, object>> plainLinks = Links(plain, "no edit");
                for (int i = 0; i < 4; i++) Check.Equal("no edit: row " + (i + 1) + " equals edit=none's", Compose(byEdit["none"][i]), Compose(plainLinks[i]));
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF the 3 chains answer: each row's text is the suite's own composition and its hash is .NET's SHA-256, the links follow the seed, and the first bad link is 0, 3 and 0 (an edit to the newest row breaks no link); an unknown edit gets 400";
            }
        }
    }
}
