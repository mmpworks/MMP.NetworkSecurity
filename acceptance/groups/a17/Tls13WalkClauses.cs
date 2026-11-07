using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// The Handshake section's key schedule walk (docs/sections-plan.md section 4, slice P4): GET /api/walk/tls13/schedule. It runs on the public
    /// inputs of RFC 8448 section 3, never on a session's key, so it stays open with Show keys OFF. Each step names its value, and a step whose
    /// name is a field of acceptance/vectors/tls13-rfc8448.nsv must equal RFC 8448's value.
    /// </summary>
    public static class Tls13WalkClauses
    {
        public const string Path = "/api/walk/tls13/schedule";

        /// <summary>The secrets every key schedule walk must show: the 3 stage secrets and the 4 traffic secrets of RFC 8446 section 7.1.</summary>
        public static readonly string[] Core = { "early_secret", "handshake_secret", "master_secret", "c_hs_traffic", "s_hs_traffic", "c_ap_traffic", "s_ap_traffic" };

        [Clause("A19.host.tls13-schedule-open-and-rfc8448")]
        public static string ScheduleOpenAndRfc8448(Ctx c)
        {
            VectorRecord rfc = c.Vectors("tls13-rfc8448.nsv", "tls13-rfc8448-1rtt")[0];
            using (HostProc h = A17.Host(c, "walk-tls13"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                Reply r = HostHttp.Get(h, Path);
                Check.True(r.Ok && r.Json != null, "OFF: GET " + Path + " got " + r + ". The walk runs on RFC 8448's public inputs, so it stays open");
                Check.Equal("keySource of the schedule walk", "rfc8448", MiniJson.Str(r.Json, "keySource"));
                List<object> steps = MiniJson.Arr(r.Json, "steps");
                Check.True(steps != null && steps.Count > 0, "the schedule walk has no steps");
                int matched = 0;
                List<string> seen = new List<string>(), misses = new List<string>();
                foreach (object o in steps)
                {
                    Dictionary<string, object> s = MiniJson.AsObject(o);
                    string name = MiniJson.Str(s, "name");
                    if (string.IsNullOrEmpty(name) || !rfc.Has(name)) continue;
                    seen.Add(name);
                    string got = (MiniJson.Str(s, "output") ?? "").ToLowerInvariant(), want = rfc.Str(name).ToLowerInvariant();
                    if (got != want) misses.Add(name + ": the walk shows " + got + ", and RFC 8448 has " + want);
                    else matched++;
                }
                foreach (string name in Core) if (!seen.Contains(name)) misses.Add(name + ": the walk has no step with this name");
                if (misses.Count > 0) throw new FailException(misses.Count + " schedule values differ from RFC 8448 or are missing: " + string.Join("; ", misses.ToArray()));
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF the schedule walk answers, names keySource rfc8448, and " + matched + " of its " + steps.Count + " steps equal RFC 8448 section 3 by name, the 7 core secrets among them";
            }
        }
    }
}
