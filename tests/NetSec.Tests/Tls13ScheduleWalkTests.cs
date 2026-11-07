using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Tls13;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Slice P4's key schedule walk. The referee is acceptance/vectors/tls13-rfc8448.nsv, which a script extracted from the RFC 8448 text.
    /// Every step the walk shows must match a value there, by name, so no step is shown that nothing outside the engine checks.
    /// </summary>
    public class Tls13ScheduleWalkTests
    {
        static Dictionary<string, string> Vectors()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "tls13-rfc8448.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/tls13-rfc8448.nsv was not found above the test folder");
            Dictionary<string, string> v = new Dictionary<string, string>();
            foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "tls13-rfc8448.nsv")))
            {
                string line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq > 0 && !line.StartsWith("#")) v[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
            }
            return v;
        }

        [Fact]
        public void Every_step_matches_rfc_8448_by_name()
        {
            Dictionary<string, string> v = Vectors();
            Tls13ScheduleWalk walk = Tls13ScheduleWalks.Rfc8448();
            Assert.Equal(21, walk.Steps.Length);
            foreach (Tls13ScheduleStep s in walk.Steps)
            {
                Assert.True(v.ContainsKey(s.Name), s.Name + " has no RFC 8448 value to check it against");
                Assert.Equal(v[s.Name], Hex.Encode(s.Output));
            }
        }

        [Fact]
        public void Each_step_shows_the_inputs_its_kind_uses()
        {
            Dictionary<string, string> v = Vectors();
            Tls13ScheduleStep[] steps = Tls13ScheduleWalks.Rfc8448().Steps;
            Tls13ScheduleStep handshake = steps.Single(s => s.Name == "handshake_secret");
            Assert.Equal(Tls13StepKind.Extract, handshake.Kind);
            Assert.Equal(v["derived_for_handshake"], Hex.Encode(handshake.Salt));
            Assert.Equal(v["ecdhe_shared"], Hex.Encode(handshake.Ikm));

            Tls13ScheduleStep cHs = steps.Single(s => s.Name == "c_hs_traffic");
            Assert.Equal("c hs traffic", cHs.Label);
            Assert.Equal(v["handshake_secret"], Hex.Encode(cHs.Secret));
            Assert.Equal(v["hash_client_hello_to_server_hello"], Hex.Encode(cHs.Context));
            // HkdfLabel: length 32 (0020), "tls13 c hs traffic" (18 bytes), then the 32-byte transcript hash.
            Assert.Equal("0020" + "12" + Hex.Encode(System.Text.Encoding.ASCII.GetBytes("tls13 c hs traffic")) + "20" + v["hash_client_hello_to_server_hello"], Hex.Encode(cHs.HkdfLabel));

            Tls13ScheduleStep key = steps.Single(s => s.Name == "s_hs_key");
            Assert.Equal(Tls13StepKind.ExpandLabel, key.Kind);
            Assert.Equal("0010" + "09" + Hex.Encode(System.Text.Encoding.ASCII.GetBytes("tls13 key")) + "00", Hex.Encode(key.HkdfLabel));

            Tls13ScheduleStep hello = steps.Single(s => s.Name == "hash_client_hello_to_server_hello");
            Assert.Equal(new[] { "ClientHello", "ServerHello" }, hello.Messages);
            Assert.Null(hello.Secret);
        }

        [Fact]
        public void The_shared_secret_is_the_same_from_both_sides()
        {
            Tls13ScheduleStep shared = Tls13ScheduleWalks.Rfc8448().Steps.Single(s => s.Name == "ecdhe_shared");
            Assert.Equal(NetSec.Crypto.X25519.Mult(Rfc8448Trace.ServerPrivate, Rfc8448Trace.ClientPublic), shared.Output);
        }

        [Fact]
        public void The_guard_names_its_code_when_a_rung_differs()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => Tls13ScheduleWalks.RequireSame(new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal(ErrorCodes.Tls13WalkDiverged, e.Error.Code);
            Assert.Throws<NetSecException>(() => Tls13ScheduleWalks.RequireSame(new byte[] { 1 }, null));
        }
    }
}
