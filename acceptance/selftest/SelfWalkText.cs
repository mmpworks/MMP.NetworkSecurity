using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>Proof that the A19 text clauses bite. A stand-in tree must PASS. One change to it must FAIL. An empty tree reads NOT RUN PRODUCT_MISSING, so no product gives no PASS.</summary>
    public static class SelfWalkText
    {
        const string Ids = "A19.app.no-table-under-src,A19.app.words-follow-the-rules,A19.repo.walk-routes-listed";

        static void Good(string root)
        {
            SelfA17Text.Put(root, "app/src/walk.ts", "export const a = 1");
            SelfA17Text.Put(root, "app/src/components/AesBlockWalk.vue", "<template><p>A matrix with a special multiply. AES on one block reverses the steps.</p></template>");
            SelfA17Text.Put(root, "src/NetSec.Host/AesWalkRoutes.cs", "class R { string a = \"/api/walk/aes/tables\"; string b = \"/api/sessions/{id}/walk/aes/block\"; }");
        }

        static void Expect(Ctx c, string root, string id, string prefix, string change)
        {
            Dictionary<string, string> r = SelfA17Text.Docs(c, root, Ids);
            Check.True(r.ContainsKey(id) && r[id].StartsWith(prefix), id + " should read " + prefix + " when " + change + ", gave " + (r.ContainsKey(id) ? r[id] : "nothing"));
        }

        static int FieldLines(Ctx c, string tmp)
        {
            const string Def = "A19.app.field-definition-lines", Gcm = "A19.app.gcm-panel-names-the-field";
            string root = Path.Combine(tmp, "field");
            Dictionary<string, object> data = MiniJson.AsObject(MiniJson.Parse(File.ReadAllText(Path.Combine(c.AcceptanceDir, "checks", "walk_lines.json"))));
            List<string> lines = new List<string>();
            foreach (object o in MiniJson.Arr(data, "definition")) lines.Add((string)o);
            string gcm = MiniJson.Str(data, "gcmPanel");
            Dictionary<string, string> r = SelfA17Text.Docs(c, root, Def + "," + Gcm);
            Check.True(r[Def].StartsWith("NOT RUN:PRODUCT_MISSING") && r[Gcm].StartsWith("NOT RUN:PRODUCT_MISSING"), "an empty tree should read NOT RUN, gave " + r[Def] + " and " + r[Gcm]);
            SelfA17Text.Put(root, "app/src/components/FieldPanel.vue", "<p>" + string.Join("</p><p>", lines.ToArray()) + "</p>");
            SelfA17Text.Put(root, "app/src/components/AesFeedView.vue", "<p>" + gcm + "</p>");
            r = SelfA17Text.Docs(c, root, Def + "," + Gcm);
            Check.True(r[Def].StartsWith("PASS") && r[Gcm].StartsWith("PASS"), "the good tree should PASS, gave " + r[Def] + " and " + r[Gcm]);
            int bites = 0;
            for (int i = 0; i < lines.Count; i++)
            {
                List<string> less = new List<string>(lines);
                less.RemoveAt(i);
                SelfA17Text.Put(root, "app/src/components/FieldPanel.vue", "<p>" + string.Join("</p><p>", less.ToArray()) + "</p>");
                Expect2(c, root, Def, "definition line " + (i + 1) + " is gone");
                bites++;
            }
            List<string> swapped = new List<string>(lines);
            swapped.Reverse();
            SelfA17Text.Put(root, "app/src/components/FieldPanel.vue", "<p>" + string.Join("</p><p>", swapped.ToArray()) + "</p>");
            Expect2(c, root, Def, "the lines are out of order");
            bites++;
            SelfA17Text.Put(root, "app/src/components/AesFeedView.vue", "<p>GHASH makes the tag.</p>");
            Expect2(c, root, Gcm, "the GCM panel lacks the line");
            bites++;
            return bites;
        }

        static void Expect2(Ctx c, string root, string id, string change)
        {
            Dictionary<string, string> r = SelfA17Text.Docs(c, root, id);
            Check.True(r[id].StartsWith("FAIL"), id + " should FAIL when " + change + ", gave " + r[id]);
        }

        [Clause("SELF.walk-text-checks-bite")]
        public static string TextChecksBite(Ctx c)
        {
            string tmp = Path.Combine(c.WorkDir, "walk-text");
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            string empty = Path.Combine(tmp, "empty"), root = Path.Combine(tmp, "tree");
            Directory.CreateDirectory(empty);
            foreach (string id in Ids.Split(',')) Expect(c, empty, id, "NOT RUN:PRODUCT_MISSING", "the tree is empty");
            Good(root);
            foreach (string id in Ids.Split(',')) Expect(c, root, id, "PASS", "the tree is good");
            int bites = 0;
            string[] tables = new string[]
            {
                "export const s = '637c777bf26b6fc5'",
                "export const s = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]",
                "export const s = [99, 124, 119, 123, 242, 107, 111, 197]",
                "export const s = [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17]",
                "export const i = '52096ad53036a538'",
            };
            foreach (string t in tables)
            {
                SelfA17Text.Put(root, "app/src/tables.ts", t);
                Expect(c, root, "A19.app.no-table-under-src", "FAIL", "app/src holds " + t);
                bites++;
            }
            File.Delete(Path.Combine(root, "app/src/tables.ts"));
            string[] words = new string[]
            {
                "SubBytes replaces each byte of the plaintext", "10 main rounds, then a final round", "Decryption reverses the steps", "This is matrix multiplication", "each 4-bit chunk", "AES makes the tag",
                "Adds the round key", "The inverse round key", "A unique IV for CBC", "A corrupted block affects subsequent blocks", "GCM must check the tag first", "ECB is vulnerable to cryptanalysis",
            };
            foreach (string w in words)
            {
                SelfA17Text.Put(root, "app/src/components/AesBlockWalk.vue", "<p>" + w + "</p>");
                Expect(c, root, "A19.app.words-follow-the-rules", "FAIL", "the panel says " + w);
                bites++;
            }
            SelfA17Text.Put(root, "app/src/components/AesBlockWalk.vue", "<p>AES on one block reverses the steps in ECB. Decryption reverses the steps in ECB.</p>");
            Expect(c, root, "A19.app.words-follow-the-rules", "PASS", "the line names the mode");
            SelfA17Text.Put(root, "src/NetSec.Host/AesWalkRoutes.cs", "class R { string a = \"/api/walk/aes/secret-new-route\"; }");
            Expect(c, root, "A19.repo.walk-routes-listed", "FAIL", "the Host has a walk route that is not listed");
            bites++;
            bites += FieldLines(c, tmp);
            return "an empty tree reads NOT RUN, a good tree PASSES, and " + bites + " one-change trees each FAIL";
        }
    }
}
