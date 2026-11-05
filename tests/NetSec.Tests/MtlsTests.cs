using System;
using System.IO;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Mutual TLS in lesson 10. The server asks for a client certificate, and each attack changes one thing about what the client presents.</summary>
    public class MtlsTests
    {
        static LabResult Lab(out TraceEvent[] events, string clientCert = null)
        {
            AttackDefinition attack = clientCert == null ? null : new AttackDefinition
            {
                AttackId = "test", Lesson = 10, Kind = "scenario",
                Options = new[] { new LabOption { Name = "client-cert", Value = clientCert } },
            };
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> run = new Lesson10Auth().Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            events = sink.Events;
            return run.Result;
        }

        [Fact]
        public void The_control_presents_a_certificate_and_proves_its_key()
        {
            LabResult r = Lab(out TraceEvent[] events);
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
        public void Each_bad_presentation_stops_at_its_named_check(string clientCert, string code, string check)
        {
            LabResult r = Lab(out TraceEvent[] events, clientCert);
            Assert.False(r.Completed, "the server took client-cert=" + clientCert);
            Assert.Equal(code, r.FailedCode);
            Assert.Equal(check, r.FailedCheck);
            Assert.DoesNotContain(events, e => e.Type == "wire.sent" && e.Message == "LoginRequest");
        }

        [Fact]
        public void The_catalog_holds_both_rows_and_each_changes_one_thing()
        {
            AttackDefinition remove = AttackCatalog.Lesson10Unreleased.Single(a => a.AttackId == "L10-remove-client-cert");
            AttackDefinition corrupt = AttackCatalog.Lesson10Unreleased.Single(a => a.AttackId == "L10-corrupt-client-cert");
            Assert.Equal("certificate_required alert", remove.ExpectCheck);
            Assert.Equal("bad_certificate alert", corrupt.ExpectCheck);
            Assert.Single(remove.Options);
            Assert.Single(corrupt.Options);
        }

        static ProbeResult[] Probes(bool requireClientCert, string clientKeyId)
        {
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Tls13, Group = KexGroup.X25519, RequireClientCert = requireClientCert });
            IFuture<ProbeResult> client = Probe.Connect(new ProbeRequest { Protocol = WireProtocol.Tls13, Group = KexGroup.X25519, Host = "127.0.0.1", Port = listener.Port, ClientKeyId = clientKeyId, Send = new byte[] { 104, 105, 10 } });
            Assert.True(client.Wait(30000), "the client did not finish in 30 s");
            Assert.True(listener.Result.Wait(30000), "the server did not finish in 30 s");
            return new[] { client.Result, listener.Result.Result };
        }

        [Fact]
        public void A_probe_client_with_a_key_passes_a_server_that_asks()
        {
            ProbeResult[] r = Probes(true, KeyIds.ClientTlsEd25519);
            Assert.True(r[1].Completed, r[1].Code + " " + r[1].CheckName);
            Assert.Equal(new byte[] { 104, 105, 10 }, r[1].Received);
        }

        [Fact]
        public void A_probe_client_with_no_key_is_refused_with_alert_116()
        {
            ProbeResult[] r = Probes(true, null);
            Assert.Equal("TLS13_CERT_REQUIRED", r[1].Code);
            Assert.Equal(116, r[0].AlertReceived);
        }

        [Fact]
        public void A_server_that_does_not_ask_never_sees_a_client_certificate()
        {
            ProbeResult[] r = Probes(false, KeyIds.ClientTlsEd25519);
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
