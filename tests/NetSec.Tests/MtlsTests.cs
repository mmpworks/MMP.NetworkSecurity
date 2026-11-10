using System;
using System.IO;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Mutual TLS in lesson 10. The server asks for a client certificate, and each attack changes one thing about what the client presents.</summary>
    public class MtlsTests
    {
        static async System.Threading.Tasks.Task<(LabResult Result, TraceEvent[] Events)> Lab(string clientCert = null)
        {
            AttackDefinition attack = clientCert == null ? null : new AttackDefinition
            {
                AttackId = "test", Lesson = 10, Kind = "scenario",
                Options = new[] { new LabOption { Name = "client-cert", Value = clientCert } },
            };
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> run = new Lesson10Auth().Run(c);
            Assert.True(await FutureWaits.Within(run, TimeSpan.FromMilliseconds(60000)), "the lab did not finish in 60 s");
            return (run.Result, sink.Events);
        }

        [Fact]
        public async System.Threading.Tasks.Task The_control_presents_a_certificate_and_proves_its_key()
        {
            (LabResult r, TraceEvent[] events) = await Lab();
            Assert.True(r.Completed, r.FailedCode + " " + r.FailedCheck);
            string[] client = events.Where(e => e.Type == "wire.sent" && e.Actor == "client").Select(e => e.Message).ToArray();
            string[] server = events.Where(e => e.Type == "wire.sent" && e.Actor == "server").Select(e => e.Message).ToArray();
            Assert.Contains("CertificateRequest", server);
            Assert.True(Array.IndexOf(client, "Certificate") >= 0 && Array.IndexOf(client, "Certificate") + 1 == Array.IndexOf(client, "CertificateVerify"), "the client must send Certificate and then CertificateVerify");
            string[] passed = events.Where(e => e.Type == "check.result" && e.Actor == "server" && e.Check.Passed).Select(e => e.Message).ToArray();
            Assert.Contains("certificate_required alert", passed);
            Assert.Contains("bad_certificate alert", passed);
            Assert.Contains("CertificateVerify signature", passed);
        }

        [Theory]
        [InlineData("none", "TLS13_CERT_REQUIRED", "certificate_required alert")]
        [InlineData("corrupt", "TLS13_BAD_CERTIFICATE", "bad_certificate alert")]
        [InlineData("server-usage", "TLS13_BAD_CERTIFICATE", "bad_certificate alert")]
        [InlineData("unknown-ca", "CHAIN_NO_ANCHOR", "chain to trust anchor")]
        [InlineData("expired", "CERT_VALIDITY", "validity window")]
        [InlineData("wrong-key", "TLS13_CERTVERIFY_BAD", "CertificateVerify signature")]
        public async System.Threading.Tasks.Task Each_bad_presentation_stops_at_its_named_check(string clientCert, string code, string check)
        {
            (LabResult r, TraceEvent[] events) = await Lab(clientCert);
            Assert.False(r.Completed, "the server took client-cert=" + clientCert);
            Assert.Equal(code, r.FailedCode);
            Assert.Equal(check, r.FailedCheck);
            Assert.DoesNotContain(events, e => e.Type == "wire.sent" && e.Message == "LoginRequest");
        }

        /// <summary>The chain is good, because the training root issued it. Only the application's compare of the name refuses it.</summary>
        [Fact]
        public async System.Threading.Tasks.Task A_certificate_for_another_name_passes_its_chain_and_is_refused_by_name()
        {
            (LabResult control, TraceEvent[] controlEvents) = await Lab();
            Assert.True(control.Completed);
            Assert.Contains(controlEvents, e => e.Type == "check.result" && e.Actor == "server" && e.Message == "client name" && e.Check.Passed);

            (LabResult r, TraceEvent[] events) = await Lab(Lesson10Auth.ClientCertWrongName);
            Assert.Equal("TLS13_CLIENT_NAME_REFUSED", r.FailedCode);
            Assert.Equal("client name", r.FailedCheck);
            // The name check runs only after the chain check passes, so a refusal here means the chain was good.
            TraceEvent refused = events.Single(e => e.Type == "check.result" && e.Actor == "server" && !e.Check.Passed);
            Assert.Equal("client name", refused.Message);
            Assert.Contains("the chain is good", refused.Check.Detail);
            TraceEvent alert = events.Single(e => e.Type == "wire.sent" && e.Actor == "server" && e.Message == "Alert");
            Assert.Equal(49, alert.Plain[alert.Plain.Length - 1]);
            Assert.DoesNotContain(events, e => e.Type == "wire.sent" && e.Message == "LoginRequest");
        }

        /// <summary>A server with no name to compare still acts as TLS does, so Go and OpenSSL referees see the same behaviour.</summary>
        [Fact]
        public async System.Threading.Tasks.Task A_server_with_no_expected_name_checks_the_chain_only()
        {
            ProbeResult[] r = await Probes(true, KeyIds.ClientTlsEd25519);
            Assert.True(r[1].Completed, r[1].Code + " " + r[1].CheckName);
            Assert.DoesNotContain(r[1].Events, e => e.Type == "check.result" && e.Message == "client name");
        }

        [Fact]
        public void A_client_with_a_chain_and_no_signing_key_is_refused_before_the_handshake()
        {
            Tls13Options o = new Tls13Options
            {
                Stream = new TraceStream("s1/client/tls13", "s1", "t1", null, "client", new FixedClock(1)),
                Random = new SeededRandom(1),
                CertificateChain = new[] { new byte[] { 1 } },
            };
            Assert.Throws<ArgumentException>(() => Tls13Engine.CreateClient(o));
            o.SigningSeed = new byte[32];
            Assert.NotNull(Tls13Engine.CreateClient(o));
        }

        [Fact]
        public void The_catalog_holds_both_rows_and_each_changes_one_thing()
        {
            AttackDefinition remove = AttackCatalog.All.Where(a => a.Lesson == 10).Single(a => a.AttackId == "L10-remove-client-cert");
            AttackDefinition corrupt = AttackCatalog.All.Where(a => a.Lesson == 10).Single(a => a.AttackId == "L10-corrupt-client-cert");
            Assert.Equal("certificate_required alert", remove.ExpectCheck);
            Assert.Equal("bad_certificate alert", corrupt.ExpectCheck);
            Assert.Single(remove.Options);
            Assert.Single(corrupt.Options);
        }

        static async System.Threading.Tasks.Task<ProbeResult[]> Probes(bool requireClientCert, string clientKeyId)
        {
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Tls13, Group = KexGroup.X25519, RequireClientCert = requireClientCert });
            IFuture<ProbeResult> client = Probe.Connect(new ProbeRequest { Protocol = WireProtocol.Tls13, Group = KexGroup.X25519, Host = "127.0.0.1", Port = listener.Port, ClientKeyId = clientKeyId, Send = new byte[] { 104, 105, 10 } });
            Assert.True(await FutureWaits.Within(client, TimeSpan.FromMilliseconds(30000)), "the client did not finish in 30 s");
            Assert.True(await FutureWaits.Within(listener.Result, TimeSpan.FromMilliseconds(30000)), "the server did not finish in 30 s");
            return new[] { client.Result, listener.Result.Result };
        }

        [Fact]
        public async System.Threading.Tasks.Task A_probe_client_with_a_key_passes_a_server_that_asks()
        {
            ProbeResult[] r = await Probes(true, KeyIds.ClientTlsEd25519);
            Assert.True(r[1].Completed, r[1].Code + " " + r[1].CheckName);
            Assert.Equal(new byte[] { 104, 105, 10 }, r[1].Received);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_probe_client_with_no_key_is_refused_with_alert_116()
        {
            ProbeResult[] r = await Probes(true, null);
            Assert.Equal("TLS13_CERT_REQUIRED", r[1].Code);
            // Read at the sender. The refusal closes a socket with the client's bytes unread, so TCP may reset before the client reads the alert.
            TraceEvent alert = r[1].Events.Single(e => e.Type == "wire.sent" && e.Message == "Alert");
            Assert.Equal(116, alert.Plain[alert.Plain.Length - 1]);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_server_that_does_not_ask_never_sees_a_client_certificate()
        {
            ProbeResult[] r = await Probes(false, KeyIds.ClientTlsEd25519);
            Assert.True(r[1].Completed, r[1].Code + " " + r[1].CheckName);
            Assert.DoesNotContain(r[1].Events, e => e.Message == "CertificateRequest");
            Assert.DoesNotContain(r[0].Events, e => e.Type == "wire.sent" && e.Message == "Certificate");
        }

        [Fact]
        public void The_export_writes_the_client_identity_for_the_referees()
        {
            string dir = Path.Combine(Path.GetTempPath(), "netsec-mtls-" + Guid.NewGuid().ToString("N"));
            try
            {
                TrainingPki.Export(dir);
                Assert.True(File.Exists(Path.Combine(dir, "client.pem")));
                Assert.True(File.Exists(Path.Combine(dir, "client.key")));
            }
            finally { Directory.Delete(dir, true); }
        }
    }
}
