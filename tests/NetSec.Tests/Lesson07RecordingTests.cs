using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Tls11;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Lesson 7's record-now-decrypt-later run, L7-decrypt-recording (docs/sections-plan.md, R8 and slice P4b). The referee for the opened
    /// RSA recording is the run itself: the attacker's master secret must equal the one the server derived and logged, and the line it reads
    /// must equal the one the client sent.
    /// </summary>
    public class Lesson07RecordingTests
    {
        static (LabResult Result, TraceEvent[] Events) Run()
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext
            {
                SessionId = "r7", TraceId = "r7", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(0), Random = new SeededRandom(7),
                Attack = AttackCatalog.All.Single(a => a.AttackId == "L7-decrypt-recording"),
            };
            IFuture<LabResult> future = LabCatalog.Find(7).Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return (future.Result, sink.Events);
        }

        static readonly (LabResult Result, TraceEvent[] Events) R = Run();

        [Fact]
        public void The_run_ends_on_the_forward_secrecy_check_because_the_ecdhe_recording_stays_closed()
        {
            Assert.False(R.Result.Completed);
            Assert.Equal(Tls11Codes.NoStoredKey, R.Result.FailedCode);
            Assert.Equal(Lesson07Tls11.ForwardSecrecyCheck, R.Result.FailedCheck);
            TraceEvent check = R.Events.Single(e => e.Type == "check.result" && e.Message == Lesson07Tls11.ForwardSecrecyCheck);
            Assert.False(check.Check.Passed);
            Assert.Equal(Tls11Codes.NoStoredKey, check.Check.Code);
            Assert.Equal("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", check.Detail);
        }

        [Fact]
        public void Both_handshakes_run_and_only_the_ecdhe_one_sends_a_server_key_exchange()
        {
            // wire.sent events carry the protocol in their stream id. "tls11" is a prefix of "tls11-ecdhe", so the RSA half excludes the other.
            string[] Sent(string protocol) => R.Events.Where(e => e.Type == "wire.sent" && e.Actor == "server" && e.StreamId.Contains("/" + protocol)
                && (protocol == "tls11-ecdhe" || !e.StreamId.Contains("tls11-ecdhe"))).Select(e => e.Message).ToArray();
            Assert.DoesNotContain("ServerKeyExchange", Sent("tls11"));
            Assert.Contains("ServerKeyExchange", Sent("tls11-ecdhe"));
            Assert.Contains("ApplicationData", Sent("tls11"));
            Assert.Contains("ApplicationData", Sent("tls11-ecdhe"));
        }

        [Fact]
        public void The_stolen_key_opens_the_rsa_recording_and_reads_the_clients_line()
        {
            TraceEvent opened = R.Events.Single(e => e.Type == "attack.recording.opened");
            Assert.Equal("attacker", opened.Actor);
            Assert.Equal("TLS_RSA_WITH_AES_128_CBC_SHA", opened.Detail);
            Assert.Equal("hello from the old world\n", Encoding.UTF8.GetString(opened.Plain));
            Assert.Equal(new[] { "tls11.premaster", "tls11.master", "tls11.client_write_mac", "tls11.client_write_key" }, opened.Secrets.Select(s => s.Name));
            Assert.All(opened.Secrets, s => Assert.Equal("attacker", s.Holder));
        }

        [Fact]
        public void The_attackers_master_secret_equals_the_one_the_rsa_server_derived()
        {
            byte[] attackers = R.Events.Single(e => e.Type == "attack.recording.opened").Secrets.Single(s => s.Name == "tls11.master").Bytes;
            byte[] servers = R.Events.Where(e => e.Type == "secret.derived" && e.StreamId.EndsWith("/server/tls11"))
                .SelectMany(e => e.Secrets).Single(s => s.Name == Tls11Session.Master).Bytes;
            Assert.Equal(Hex.Encode(servers), Hex.Encode(attackers));
        }

        [Fact]
        public void Each_half_records_only_its_own_wire()
        {
            RecordingTap tap = new RecordingTap(null);
            tap.Apply(Machine.TamperPoint.Wire, "s/client/tls11", 1, "ClientHello", new byte[] { 1, 2 });
            tap.Apply(Machine.TamperPoint.Wire, "s/server/tls11", 1, "ServerHello", new byte[] { 3 });
            tap.Apply(Machine.TamperPoint.Plain, "s/client/tls11", 2, "Finished", new byte[] { 9 });
            Assert.Equal(new byte[] { 1, 2 }, tap.ClientToServer);
            Assert.Equal(new byte[] { 3 }, tap.ServerToClient);
        }
    }
}
