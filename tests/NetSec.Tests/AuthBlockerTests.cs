using System;
using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>The findings of the review on PR #20, each as a test that failed before its fix. Codes are strings here, so a test can fail before its code exists.</summary>
    public class AuthReviewFindingTests
    {
        static readonly ITrainingKey Issuer = new TrainingKeySource().Find(KeyIds.TokenIssuer);
        static readonly byte[] Device = Enumerable.Repeat((byte)7, 32).ToArray();
        const string Claims = "{\"sub\":\"a\",\"exp\":2000}";
        const string Url = "https://x.test/a";
        const string AccessToken = "the.access.token";
        static readonly DateTime Now = AuthTime.FromUnix(1000);

        static string B64(string text) => Base64Url.Encode(Encoding.UTF8.GetBytes(text));

        static string SignRaw(byte[] seed, string header, string claims)
        {
            string input = B64(header) + "." + B64(claims);
            return input + "." + Base64Url.Encode(Ed25519.Sign(seed, Encoding.UTF8.GetBytes(input)));
        }

        // ---------------------------------------------------------------- finding 4: one token has one spelling

        [Theory]
        [InlineData("AR")]        // Spare bits set: a one-byte value decodes with "AQ" as its one spelling.
        [InlineData("AQJ")]       // Same, for two bytes: "AQI" is the one spelling.
        [InlineData("AQ ID")]
        [InlineData("AQ\nID")]
        [InlineData(" AQID")]
        [InlineData("AQID ")]
        public void Base64url_refuses_a_second_spelling(string text)
        {
            Assert.Throws<ParseFailure>(() => Base64Url.Decode(text));
        }

        [Fact]
        public void A_signature_with_spaces_in_it_is_refused()
        {
            string[] p = Token.Issue(Issuer, Claims).Split('.');
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), p[0] + "." + p[1] + "." + p[2].Substring(0, 4) + " " + p[2].Substring(4), Now);
            Assert.False(d.Allowed);
            Assert.Equal("TOKEN_MALFORMED", d.Code);
        }

        [Fact]
        public void A_signature_with_other_spare_bits_is_refused()
        {
            const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            string[] p = Token.Issue(Issuer, Claims).Split('.');
            // 64 bytes end in a character whose low 4 bits are spare, so a change there leaves the decoded bytes the same.
            char last = p[2][p[2].Length - 1];
            string other = p[2].Substring(0, p[2].Length - 1) + Alphabet[Alphabet.IndexOf(last) | 1];
            Assert.Equal(Base64Decoded(p[2]), Base64Decoded(other));
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), p[0] + "." + p[1] + "." + other, Now);
            Assert.False(d.Allowed, "a second spelling of the signature passed");
        }

        static byte[] Base64Decoded(string url) => Convert.FromBase64String(url.Replace('-', '+').Replace('_', '/') + "==");

        // ---------------------------------------------------------------- should-fix: the clock

        [Fact]
        public void A_local_clock_value_gets_the_same_answer_as_utc()
        {
            DateTime expiredOneHourAgo = DateTime.UtcNow.AddHours(-1);
            string token = Token.Issue(Issuer, "{\"exp\":" + AuthTime.ToUnix(expiredOneHourAgo) + "}");
            Assert.Equal("TOKEN_EXPIRED", Token.Verify(Issuer.CopyPublic(), token, DateTime.UtcNow).Code);
            Assert.Equal("TOKEN_EXPIRED", Token.Verify(Issuer.CopyPublic(), token, DateTime.Now).Code);
        }

        [Fact]
        public void A_clock_value_with_no_zone_is_refused()
        {
            string token = Token.Issue(Issuer, Claims);
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), token, new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Unspecified));
            Assert.False(d.Allowed);
            Assert.Equal("TOKEN_BAD_CLOCK", d.Code);
        }

        // ---------------------------------------------------------------- should-fix: crit, and the name of junk

        [Fact]
        public void A_token_with_a_crit_header_is_refused()
        {
            string token = SignRaw(Issuer.CopyMaterial(), "{\"alg\":\"EdDSA\",\"crit\":[\"x\"],\"x\":1}", Claims);
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), token, Now);
            Assert.False(d.Allowed);
            Assert.Equal("TOKEN_BAD_HEADER", d.Code);
        }

        [Theory]
        [InlineData("")]
        [InlineData("a.b")]
        [InlineData("a.b.c.d")]
        [InlineData("!!.!!.!!")]
        public void Junk_is_named_malformed_and_never_a_failed_signature(string token)
        {
            Assert.Equal("TOKEN_MALFORMED", Token.Verify(Issuer.CopyPublic(), token, Now).Code);
        }

        // ---------------------------------------------------------------- finding 3: a private key in the proof header

        [Theory]
        [InlineData("d")]
        [InlineData("p")]
        [InlineData("q")]
        [InlineData("dp")]
        [InlineData("dq")]
        [InlineData("qi")]
        [InlineData("oth")]
        [InlineData("k")]
        public void A_proof_with_a_private_member_in_its_jwk_is_refused(string member)
        {
            byte[] pub = Ed25519.PublicFrom(Device);
            string jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Base64Url.Encode(pub) + "\",\"" + member + "\":\"AQID\"}";
            string header = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":" + jwk + "}";
            byte[] ath = Sha256(AccessToken);
            string claims = "{\"jti\":\"id-1\",\"htm\":\"POST\",\"htu\":\"" + Url + "\",\"iat\":1000,\"ath\":\"" + Base64Url.Encode(ath) + "\"}";
            AuthDecision d = DpopProof.Check(SignRaw(Device, header, claims), "POST", Url, 1000, AccessToken, DpopProof.Thumbprint(pub));
            Assert.False(d.Allowed);
            Assert.Equal("DPOP_BAD_JWK", d.Code);
        }

        static string ProofWith(string headerExtra)
        {
            byte[] pub = Ed25519.PublicFrom(Device);
            string header = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Base64Url.Encode(pub) + "\"}" + headerExtra + "}";
            string claims = "{\"jti\":\"id-1\",\"htm\":\"POST\",\"htu\":\"" + Url + "\",\"iat\":1000,\"ath\":\"" + Base64Url.Encode(Sha256(AccessToken)) + "\"}";
            return SignRaw(Device, header, claims);
        }

        [Fact]
        public void A_proof_with_a_crit_header_is_refused_beside_a_control()
        {
            string jkt = DpopProof.Thumbprint(Ed25519.PublicFrom(Device));
            Assert.True(DpopProof.Check(ProofWith(""), "POST", Url, 1000, AccessToken, jkt).Allowed);
            AuthDecision d = DpopProof.Check(ProofWith(",\"crit\":[\"x\"],\"x\":1"), "POST", Url, 1000, AccessToken, jkt);
            Assert.False(d.Allowed);
            Assert.Equal("DPOP_MALFORMED", d.Code);
        }

        static byte[] Sha256(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            IHash h = Hashes.Sha256();
            h.Update(bytes, 0, bytes.Length);
            return h.Finish();
        }

        // ---------------------------------------------------------------- findings 1 and 2: the login

        static LabResult Login(params string[] nameThenValue)
        {
            LabOption[] options = new LabOption[nameThenValue.Length / 2];
            for (int i = 0; i < options.Length; i++) options[i] = new LabOption { Name = nameThenValue[i * 2], Value = nameThenValue[i * 2 + 1] };
            AttackDefinition attack = options.Length == 0 ? null : new AttackDefinition { AttackId = "test", Lesson = 10, Kind = "scenario", Options = options };
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> run = new Lesson10Auth().Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            return run.Result;
        }

        [Fact]
        public void A_signed_answer_to_a_challenge_the_issuer_never_sent_is_refused()
        {
            LabResult r = Login("answer-unissued", "yes");
            Assert.False(r.Completed, "a client that signed 32 zero bytes got a token");
            Assert.Equal("CHALLENGE_NOT_ISSUED", r.FailedCode);
            Assert.Equal("challenge issued", r.FailedCheck);
        }

        [Fact]
        public void A_device_nobody_enrolled_gets_no_token()
        {
            LabResult r = Login("unknown-device", "yes");
            Assert.False(r.Completed, "a key nobody enrolled got a token");
            Assert.Equal("DEVICE_NOT_ENROLLED", r.FailedCode);
            Assert.Equal("device enrolled", r.FailedCheck);
        }

        [Fact]
        public void The_small_order_key_with_no_private_half_gets_no_token()
        {
            LabResult r = Login("device-key-hex", "0100000000000000000000000000000000000000000000000000000000000000");
            Assert.False(r.Completed, "the small-order key got a token");
            Assert.Equal("DEVICE_NOT_ENROLLED", r.FailedCode);
        }

        static TraceEvent[] Events(AttackDefinition attack, out LabResult result)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> run = new Lesson10Auth().Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            result = run.Result;
            return sink.Events;
        }

        /// <summary>
        /// R = B, S = 1 verifies under the small-order key for any message, with no private key. The enrolment check stops that key. This is the
        /// same forgery with the enrolled key in the request, so the signature check is what must stop it, end to end.
        /// </summary>
        [Fact]
        public void A_forged_signature_on_the_enrolled_key_gets_no_token()
        {
            byte[] forged = Hex.Decode("5866666666666666666666666666666666666666666666666666666666666666" + "0100000000000000000000000000000000000000000000000000000000000000");
            byte[] anyChallenge = new byte[32];
            Assert.True(Challenge.Verify(Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000"), anyChallenge, "https://pump.training", forged).Allowed);

            // The same seed issues the same challenge, so the control run gives the bytes this login will issue.
            LabResult control;
            TraceEvent[] seen = Events(null, out control);
            Assert.True(control.Completed);
            byte[] challengeFrame = seen.First(e => e.Type == "wire.sent" && e.Message == "Challenge").Wire;
            byte[] challenge = challengeFrame.Skip(Frame.HeaderSize).ToArray();

            TamperPlan swap = new TamperPlan { Kind = "swap-field", Message = "ChallengeResponse", Replacement = Frame.Build(3, challenge.Concat(forged).ToArray()) };
            LabResult attacked;
            TraceEvent[] events = Events(new AttackDefinition { AttackId = "test", Lesson = 10, Kind = "swap-field", Plan = swap, Options = new LabOption[0] }, out attacked);
            Assert.False(attacked.Completed);
            Assert.Equal("CHALLENGE_BAD_SIGNATURE", attacked.FailedCode);
            Assert.Equal("challenge signature", attacked.FailedCheck);
            Assert.DoesNotContain(events, e => e.Type == "wire.sent" && e.Message == "TokenIssued");
        }

        /// <summary>The tour binds to these names, so a change here must reach the tour.</summary>
        [Fact]
        public void The_mutual_tls_phase_emits_the_event_types_the_tour_binds_to()
        {
            LabResult result;
            TraceEvent[] events = Events(null, out result);
            Assert.True(result.Completed);
            string[] Sent(string actor) => events.Where(e => e.Type == "tls.handshake.sent" && e.Actor == actor).Select(e => e.Message).ToArray();
            Assert.Equal(new[] { "ServerHello", "EncryptedExtensions", "CertificateRequest", "Certificate", "CertificateVerify", "Finished" }, Sent("server"));
            Assert.Equal(new[] { "ClientHello", "Certificate", "CertificateVerify", "Finished" }, Sent("client"));
            Assert.All(events.Where(e => e.Type == "tls.handshake.sent"), e => Assert.EndsWith("/auth-mtls", e.StreamId));
            Assert.Contains(events, e => e.Type == "tls.handshake.received" && e.Actor == "server" && e.Message == "CertificateVerify");
            Assert.Contains(events, e => e.Type == "check.result" && e.Actor == "server" && e.Message == "certificate_required alert" && e.Check.Passed);
            Assert.Contains(events, e => e.Type == "check.result" && e.Actor == "server" && e.Message == "bad_certificate alert" && e.Check.Passed);
        }

        [Theory]
        [InlineData("L10-remove-client-cert", "certificate_required alert")]
        [InlineData("L10-corrupt-client-cert", "bad_certificate alert")]
        public void A_refused_client_certificate_fails_its_check_on_the_server(string attackId, string check)
        {
            LabResult result;
            TraceEvent[] events = Events(AttackCatalog.Lesson10Unreleased.Single(a => a.AttackId == attackId), out result);
            Assert.False(result.Completed);
            Assert.Contains(events, e => e.Type == "check.result" && e.Actor == "server" && e.Message == check && !e.Check.Passed);
        }

        [Fact]
        public void The_catalog_holds_the_new_rows()
        {
            string[] ids = AttackCatalog.Lesson10Unreleased.Select(a => a.AttackId).ToArray();
            Assert.Contains("L10-unissued-challenge", ids);
            Assert.Contains("L10-unknown-device", ids);
            Assert.Contains("L10-wrong-audience", ids);
        }

        // ---------------------------------------------------------------- advisory 1: audience

        [Fact]
        public void A_token_for_another_audience_is_refused_by_the_server()
        {
            LabResult r = Login("token-audience", "https://other.training/api");
            Assert.False(r.Completed, "the server took a token written for another audience");
            Assert.Equal("TOKEN_BAD_AUDIENCE", r.FailedCode);
            Assert.Equal("token audience", r.FailedCheck);
        }
    }
}
