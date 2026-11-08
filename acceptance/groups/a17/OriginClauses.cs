using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>
    /// NETSEC_ORIGINS, docs/program-design.md D14 amendment (#225): extra browser origins for test runs. The list adds to the built-in origins and
    /// never replaces them. An entry is the string http://localhost:PORT or http://127.0.0.1:PORT, PORT 1024 to 65535, no leading zero, no path,
    /// no trailing slash. The Host drops any other entry and keeps the rest, and prints one HOST-ORIGINS accepted=[...] dropped=[...] start line
    /// that names each dropped entry with its reason. The token check still runs on every request from an added origin.
    /// Each clause asks GET /api/health from outside the Host, with the Origin header it names.
    /// </summary>
    public static class OriginClauses
    {
        const string Default = "http://localhost:5173";

        static Reply Probe(HostProc h, string origin, bool withToken)
        {
            return HostHttp.Raw(h, "GET", "/api/health", null, withToken ? h.Token : null, origin);
        }

        static void Allowed(HostProc h, string origin, string why)
        {
            Reply r = Probe(h, origin, true);
            Check.True(r.Ok, why + ": " + origin + " with the token should reach the Host, and got " + r);
        }

        static void Refused(HostProc h, string origin, string why)
        {
            Reply r = Probe(h, origin, true);
            Check.True(r.Status == 403 && r.Code == "HOST_ORIGIN_REFUSED", why + ": " + origin + " should get 403 HOST_ORIGIN_REFUSED, and got " + r);
        }

        static string OriginsLine(HostProc h)
        {
            string line = h.P == null ? null : h.P.WaitForLine(delegate (string l) { return l.StartsWith("HOST-ORIGINS ", StringComparison.Ordinal); }, 10000);
            Check.True(line != null, "the Host printed no HOST-ORIGINS start line. Output: " + (h.P == null ? "(attached)" : h.P.AllOutput));
            return line;
        }

        static HostProc Start(Ctx c, string name, string origins)
        {
            // A product tree from before #225 has no NETSEC_ORIGINS, so these clauses cannot be judged there.
            if (!File.Exists(Path.Combine(c.RepoRoot, "src", "NetSec.Host", "ExtraOrigins.cs")))
                throw new NotRunException("PRODUCT_MISSING", "src/NetSec.Host/ExtraOrigins.cs does not exist yet (NETSEC_ORIGINS, #225)");
            Dictionary<string, string> env = new Dictionary<string, string>();
            // Unset is written as empty, as Electron does, so a value exported in the shell that runs the suite cannot leak in.
            env["NETSEC_ORIGINS"] = origins ?? "";
            return HostProc.Start(c, name, env);
        }

        [Clause("A17.origins.extra-refused-when-unset")]
        public static string ExtraRefusedWhenUnset(Ctx c)
        {
            using (HostProc h = Start(c, "origins-unset", null))
            {
                Allowed(h, Default, "control: a built-in origin");
                Allowed(h, "http://localhost:4180", "control: a built-in origin");
                Refused(h, "http://localhost:4181", "NETSEC_ORIGINS unset");
                Refused(h, "http://127.0.0.1:4180", "NETSEC_ORIGINS unset, and 127.0.0.1 is a separate entry from localhost");
                return "with NETSEC_ORIGINS unset, the 2 built-in origins reach the Host, and http://localhost:4181 and http://127.0.0.1:4180 get 403 HOST_ORIGIN_REFUSED";
            }
        }

        [Clause("A17.origins.set-list-adds-to-default")]
        public static string SetListAdds(Ctx c)
        {
            using (HostProc h = Start(c, "origins-set", "http://localhost:4181,http://127.0.0.1:4182"))
            {
                Allowed(h, "http://localhost:4181", "a listed origin");
                Allowed(h, "http://127.0.0.1:4182", "a listed origin");
                Allowed(h, Default, "the built-in list stays");
                Allowed(h, "http://localhost:4180", "the built-in list stays");
                Refused(h, "http://localhost:4183", "an origin nobody listed");
                Refused(h, "http://localhost:4182", "localhost and 127.0.0.1 are separate entries");
                string line = OriginsLine(h);
                Check.True(line.Contains("http://localhost:4181") && line.Contains("http://127.0.0.1:4182"), "the start line should name both accepted origins: " + line);
                return "2 listed origins reach the Host, the 2 built-in origins still do, and an unlisted one gets 403";
            }
        }

        [Clause("A17.origins.bad-entry-dropped-alone")]
        public static string BadEntryDroppedAlone(Ctx c)
        {
            string[] bad = { "http://localhost:80", "http://localhost:04184", "http://evil.example:4185", "http://localhost:4186/", "https://localhost:4187", "http://localhost:70000", "http://localhost:*" };
            using (HostProc h = Start(c, "origins-bad", string.Join(",", bad) + ",http://localhost:4188"))
            {
                Allowed(h, "http://localhost:4188", "the valid entry beside 7 bad ones");
                Refused(h, "http://localhost:80", "a port below 1024");
                Refused(h, "http://localhost:4184", "the leading-zero entry, in its canonical form");
                Refused(h, "http://localhost:4186", "the entry with a slash, without it");
                Refused(h, "http://evil.example:4185", "a host other than localhost or 127.0.0.1");
                string line = OriginsLine(h);
                int dropped = line.IndexOf("dropped=[", StringComparison.Ordinal);
                Check.True(dropped > 0, "the start line has no dropped list: " + line);
                string tail = line.Substring(dropped);
                foreach (string b in bad) Check.True(tail.Contains(b + " ("), "the start line should drop " + b + " with a reason: " + line);
                return "7 bad entries are each dropped with a reason, and the valid entry beside them still reaches the Host";
            }
        }

        [Clause("A17.origins.token-still-required")]
        public static string TokenStillRequired(Ctx c)
        {
            using (HostProc h = Start(c, "origins-token", "http://localhost:4181"))
            {
                Allowed(h, "http://localhost:4181", "control: the listed origin with the token");
                Reply r = Probe(h, "http://localhost:4181", false);
                Check.True(r.Status == 401 && r.Code == "HOST_TOKEN_REFUSED", "a listed origin with no token should get 401 HOST_TOKEN_REFUSED, and got " + r);
                return "a listed origin with no token gets 401 HOST_TOKEN_REFUSED, so the list grants nothing without the token";
            }
        }
    }
}
