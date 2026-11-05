using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    public class MiniJsonReaderTests
    {
        [Fact]
        public void Reads_objects_arrays_strings_numbers_and_words()
        {
            var o = (Dictionary<string, object>)MiniJsonReader.Parse(" {\"a\":\"x\\n\\u0041\",\"b\":[1,-2,true,false,null],\"c\":{\"d\":{}}} ");
            Assert.Equal("x\nA", o["a"]);
            Assert.Equal(new object[] { 1L, -2L, true, false, null }, ((List<object>)o["b"]).ToArray());
            Assert.Empty((Dictionary<string, object>)((Dictionary<string, object>)o["c"])["d"]);
        }

        [Theory]
        [InlineData("")]
        [InlineData("{")]
        [InlineData("{\"a\":1,}")]
        [InlineData("{\"a\":1,\"a\":2}")]
        [InlineData("[1,]")]
        [InlineData("1.5")]
        [InlineData("1e3")]
        [InlineData("\"open")]
        [InlineData("\"\\q\"")]
        [InlineData("tru")]
        [InlineData("{} x")]
        [InlineData("1234567890123456789012")]
        public void Refuses_a_bad_shape_by_code(string text)
        {
            Assert.Equal(MiniJsonReader.Malformed, Assert.Throws<ParseFailure>(() => MiniJsonReader.Parse(text)).Code);
        }

        [Fact]
        public void Refuses_deep_nesting()
        {
            Assert.Throws<ParseFailure>(() => MiniJsonReader.Parse(new string('[', 40) + new string(']', 40)));
        }

        [Theory]
        [InlineData(new byte[] { }, "")]
        [InlineData(new byte[] { 0xFB }, "-w")]
        [InlineData(new byte[] { 0xFF, 0xEF }, "_-8")]
        [InlineData(new byte[] { 1, 2, 3 }, "AQID")]
        public void Base64url_round_trips(byte[] bytes, string text)
        {
            Assert.Equal(text, Base64Url.Encode(bytes));
            Assert.Equal(bytes, Base64Url.Decode(text));
        }

        [Theory]
        [InlineData("AQ==")]
        [InlineData("+w")]
        [InlineData("A")]
        [InlineData("A!")]
        public void Base64url_refuses_other_spellings(string text)
        {
            Assert.Throws<ParseFailure>(() => Base64Url.Decode(text));
        }
    }

    public class TokenTests
    {
        static readonly ITrainingKey Issuer = new TrainingKeySource().Find(KeyIds.TokenIssuer);
        static readonly DateTime Now = AuthTime.FromUnix(1000);
        const string Claims = "{\"sub\":\"a\",\"exp\":2000}";

        [Fact]
        public void A_token_verifies_under_its_issuer_and_hands_back_its_claims()
        {
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), Token.Issue(Issuer, Claims), Now);
            Assert.True(d.Allowed, d.Code);
            Assert.Equal("a", d.Claims["sub"]);
        }

        [Fact]
        public void Each_part_of_the_token_is_covered()
        {
            string token = Token.Issue(Issuer, Claims);
            for (int i = 0; i < token.Length; i++)
            {
                if (token[i] == '.') continue;
                char[] changed = token.ToCharArray();
                changed[i] = changed[i] == 'A' ? 'B' : 'A';
                AuthDecision d = Token.Verify(Issuer.CopyPublic(), new string(changed), Now);
                Assert.False(d.Allowed, "a change at character " + i + " passed");
                Assert.Contains(d.CheckName, new[] { Token.SignatureCheck, Token.FormatCheck });
            }
        }

        [Fact]
        public void A_token_signed_by_another_key_is_refused()
        {
            ITrainingKey attacker = new TrainingKeySource().Find(KeyIds.AttackerEd25519);
            Assert.Equal(ErrorCodes.TokenBadSignature, Token.Verify(Issuer.CopyPublic(), Token.Issue(attacker, Claims), Now).Code);
        }

        [Theory]
        [InlineData(1999, true)]
        [InlineData(2000, false)]
        [InlineData(2001, false)]
        public void Expiry_ends_at_exp(long now, bool allowed)
        {
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), Token.Issue(Issuer, Claims), AuthTime.FromUnix(now));
            Assert.Equal(allowed, d.Allowed);
            if (!allowed) Assert.Equal(ErrorCodes.TokenExpired, d.Code);
        }

        [Fact]
        public void A_token_with_no_exp_is_refused()
        {
            Assert.Equal(ErrorCodes.TokenMalformed, Token.Verify(Issuer.CopyPublic(), Token.Issue(Issuer, "{\"sub\":\"a\"}"), Now).Code);
        }

        /// <summary>The alg-none attack: a header that names no signature, and an empty signature part.</summary>
        [Theory]
        [InlineData("{\"alg\":\"none\"}")]
        [InlineData("{\"alg\":\"HS256\"}")]
        [InlineData("{}")]
        public void A_header_that_does_not_name_EdDSA_is_refused(string header)
        {
            string forged = Base64Url.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(Claims)) + ".";
            Assert.Equal(ErrorCodes.TokenBadAlg, Token.Verify(Issuer.CopyPublic(), forged, Now).Code);
        }

        [Theory]
        [InlineData("")]
        [InlineData("a.b")]
        [InlineData("a.b.c.d")]
        [InlineData("!!.!!.!!")]
        public void Junk_is_refused_with_no_exception(string token)
        {
            Assert.False(Token.Verify(Issuer.CopyPublic(), token, Now).Allowed);
        }

        [Fact]
        public void Issue_refuses_a_key_that_is_not_ed25519()
        {
            Assert.Throws<ArgumentException>(() => Token.Issue(new TrainingKeySource().Find(KeyIds.DukptBdk128), Claims));
        }
    }

    public class DpopTests
    {
        static readonly byte[] Seed = Enumerable.Repeat((byte)7, 32).ToArray();
        const string Url = "https://x.test/a";
        const string AccessToken = "the.access.token";
        static string Jkt => DpopProof.Thumbprint(Ed25519.PublicFrom(Seed));
        static string Proof(string htm = "POST", string htu = Url, long iat = 1000, string token = AccessToken, byte[] seed = null) =>
            DpopProof.Create(seed ?? Seed, htm, htu, iat, "id-1", token);

        [Fact]
        public void A_good_proof_passes_and_hands_back_its_jti()
        {
            AuthDecision d = DpopProof.Check(Proof(), "POST", Url, 1000, AccessToken, Jkt);
            Assert.True(d.Allowed, d.Code + " " + d.Detail);
            Assert.Equal("id-1", d.Jti);
        }

        [Fact]
        public void Each_binding_is_checked_by_name()
        {
            Assert.Equal(ErrorCodes.DpopHtmMismatch, DpopProof.Check(Proof(htm: "GET"), "POST", Url, 1000, AccessToken, Jkt).Code);
            Assert.Equal(ErrorCodes.DpopHtuMismatch, DpopProof.Check(Proof(htu: "https://x.test/b"), "POST", Url, 1000, AccessToken, Jkt).Code);
            Assert.Equal(ErrorCodes.DpopAthMismatch, DpopProof.Check(Proof(token: "another"), "POST", Url, 1000, AccessToken, Jkt).Code);
            Assert.Equal(ErrorCodes.DpopJktMismatch, DpopProof.Check(Proof(seed: Enumerable.Repeat((byte)8, 32).ToArray()), "POST", Url, 1000, AccessToken, Jkt).Code);
        }

        [Theory]
        [InlineData(1000 + DpopProof.MaxAgeSeconds, true)]
        [InlineData(1000 + DpopProof.MaxAgeSeconds + 1, false)]
        [InlineData(1000 - DpopProof.MaxAgeSeconds, true)]
        [InlineData(1000 - DpopProof.MaxAgeSeconds - 1, false)]
        public void The_age_window_has_two_edges(long now, bool allowed)
        {
            AuthDecision d = DpopProof.Check(Proof(), "POST", Url, now, AccessToken, Jkt);
            Assert.Equal(allowed, d.Allowed);
            if (!allowed) Assert.Equal(ErrorCodes.DpopIatWindow, d.Code);
        }

        [Fact]
        public void A_changed_proof_fails_its_signature()
        {
            string[] p = Proof().Split('.');
            char[] claims = p[1].ToCharArray();
            claims[3] = claims[3] == 'A' ? 'B' : 'A';
            Assert.Equal(ErrorCodes.DpopBadSignature, DpopProof.Check(p[0] + "." + new string(claims) + "." + p[2], "POST", Url, 1000, AccessToken, Jkt).Code);
        }

        /// <summary>The thumbprint example of RFC 8037 appendix A.3.</summary>
        [Fact]
        public void The_thumbprint_matches_the_rfc_8037_example()
        {
            byte[] pub = Hex.Decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            Assert.Equal("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", DpopProof.Thumbprint(pub));
        }

        [Theory]
        [InlineData("")]
        [InlineData("a.b.c")]
        public void Junk_is_refused_with_no_exception(string proof)
        {
            Assert.False(DpopProof.Check(proof, "POST", Url, 1000, AccessToken, Jkt).Allowed);
        }
    }

    public class AuthHardeningTests
    {
        static readonly ITrainingKey Issuer = new TrainingKeySource().Find(KeyIds.TokenIssuer);
        static readonly byte[] Seed = Enumerable.Repeat((byte)7, 32).ToArray();
        const string Claims = "{\"sub\":\"a\",\"exp\":2000}";
        const string Url = "https://x.test/a";
        const string AccessToken = "the.access.token";

        static string Part(string json) => Base64Url.Encode(Encoding.UTF8.GetBytes(json));

        static string SignedJws(byte[] seed, string header, string claims)
        {
            string input = Part(header) + "." + Part(claims);
            return input + "." + Base64Url.Encode(Ed25519.Sign(seed, Encoding.UTF8.GetBytes(input)));
        }

        static string ProofClaims(string token)
        {
            IHash sha = Hashes.Sha256();
            byte[] bytes = Encoding.UTF8.GetBytes(token);
            sha.Update(bytes, 0, bytes.Length);
            return "{\"jti\":\"id-1\",\"htm\":\"POST\",\"htu\":\"" + Url + "\",\"iat\":1000,\"ath\":\"" + Base64Url.Encode(sha.Finish()) + "\"}";
        }

        static string ProofHeader(string jwkExtra, string headerExtra)
        {
            return "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Base64Url.Encode(Ed25519.PublicFrom(Seed)) + "\"" + jwkExtra + "}" + headerExtra + "}";
        }

        static AuthDecision CheckProof(string proof)
        {
            return DpopProof.Check(proof, "POST", Url, 1000, AccessToken, DpopProof.Thumbprint(Ed25519.PublicFrom(Seed)));
        }

        [Fact]
        public void The_hand_built_proof_passes_with_no_extra_member()
        {
            AuthDecision d = CheckProof(SignedJws(Seed, ProofHeader("", ""), ProofClaims(AccessToken)));
            Assert.True(d.Allowed, d.Code + " " + d.Detail);
        }

        /// <summary>RFC 9449 section 4.3 step 7. A private key in the header means a client has leaked it, so the proof proves nothing.</summary>
        [Theory]
        [InlineData("d")]
        [InlineData("p")]
        [InlineData("q")]
        [InlineData("dp")]
        [InlineData("dq")]
        [InlineData("qi")]
        [InlineData("oth")]
        [InlineData("k")]
        public void A_proof_with_a_private_key_member_in_its_jwk_is_refused(string member)
        {
            AuthDecision d = CheckProof(SignedJws(Seed, ProofHeader(",\"" + member + "\":\"AQID\"", ""), ProofClaims(AccessToken)));
            Assert.False(d.Allowed);
            Assert.Equal(ErrorCodes.DpopBadKey, d.Code);
        }

        [Fact]
        public void A_proof_that_names_a_critical_extension_is_refused()
        {
            AuthDecision d = CheckProof(SignedJws(Seed, ProofHeader("", ",\"crit\":[\"x\"],\"x\":1"), ProofClaims(AccessToken)));
            Assert.False(d.Allowed);
            Assert.Equal(ErrorCodes.DpopMalformed, d.Code);
        }

        [Fact]
        public void A_token_that_names_a_critical_extension_is_refused()
        {
            string control = SignedJws(Issuer.CopyMaterial(), "{\"alg\":\"EdDSA\"}", Claims);
            string withCrit = SignedJws(Issuer.CopyMaterial(), "{\"alg\":\"EdDSA\",\"crit\":[\"x\"],\"x\":1}", Claims);
            Assert.True(Token.Verify(Issuer.CopyPublic(), control, AuthTime.FromUnix(1000)).Allowed);
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), withCrit, AuthTime.FromUnix(1000));
            Assert.False(d.Allowed);
            Assert.Equal(ErrorCodes.TokenBadHeader, d.Code);
        }

        /// <summary>Spare bits and white space gave a second spelling of one value.</summary>
        [Theory]
        [InlineData("AR")]
        [InlineData("AQJ")]
        [InlineData("AQ ID")]
        [InlineData(" AQID")]
        [InlineData("AQID\n")]
        [InlineData("AQ ID   ")]
        public void Base64url_refuses_spare_bits_and_white_space(string text)
        {
            Assert.Throws<ParseFailure>(() => Base64Url.Decode(text));
        }

        [Fact]
        public void A_token_with_a_second_spelling_of_its_signature_is_refused()
        {
            string token = Token.Issue(Issuer, Claims);
            char last = token[token.Length - 1];
            string respelled = token.Substring(0, token.Length - 1) + (char)(last + 1);
            AuthDecision control = Token.Verify(Issuer.CopyPublic(), token, AuthTime.FromUnix(1000));
            Assert.True(control.Allowed);
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), respelled, AuthTime.FromUnix(1000));
            Assert.False(d.Allowed);
            Assert.Equal(ErrorCodes.TokenMalformed, d.Code);
        }

        [Theory]
        [InlineData("")]
        [InlineData("a.b")]
        [InlineData("a.b.c.d")]
        [InlineData("!!.!!.!!")]
        public void Junk_is_named_malformed_and_no_signature_check_is_claimed(string token)
        {
            AuthDecision d = Token.Verify(Issuer.CopyPublic(), token, AuthTime.FromUnix(1000));
            Assert.Equal(ErrorCodes.TokenMalformed, d.Code);
            Assert.Equal(Token.FormatCheck, d.CheckName);
        }

        [Fact]
        public void A_local_time_is_converted_so_an_expired_token_stays_expired()
        {
            string token = Token.Issue(Issuer, Claims);
            AuthDecision expired = Token.Verify(Issuer.CopyPublic(), token, AuthTime.FromUnix(2001).ToLocalTime());
            Assert.False(expired.Allowed);
            Assert.Equal(ErrorCodes.TokenExpired, expired.Code);
            Assert.True(Token.Verify(Issuer.CopyPublic(), token, AuthTime.FromUnix(1999).ToLocalTime()).Allowed);
        }

        [Fact]
        public void A_time_with_no_kind_is_refused_because_its_zone_is_unknown()
        {
            DateTime unspecified = DateTime.SpecifyKind(AuthTime.FromUnix(1000), DateTimeKind.Unspecified);
            Assert.Throws<ArgumentException>(() => Token.Verify(Issuer.CopyPublic(), Token.Issue(Issuer, Claims), unspecified));
        }
    }

    public class AccessRuleTests
    {
        [Theory]
        [InlineData("cashier", "", "read-totals", null)]
        [InlineData("manager", "", "read-totals", null)]
        [InlineData("guest", "", "read-totals", ErrorCodes.RoleDenied)]
        [InlineData("", "", "read-totals", ErrorCodes.RoleDenied)]
        [InlineData("cashier", "void-sale", "void-sale", null)]
        [InlineData("manager", "", "void-sale", ErrorCodes.CapabilityDenied)]
        [InlineData("cashier", "void-sale", "refund", ErrorCodes.CapabilityDenied)]
        [InlineData("cashier", "void-sale", "no-such-action", ErrorCodes.CapabilityDenied)]
        public void A_role_or_capability_decides(string role, string capability, string action, string code)
        {
            string[] roles = role.Length == 0 ? new string[0] : new[] { role };
            string[] caps = capability.Length == 0 ? new string[0] : new[] { capability };
            AuthDecision d = AccessRules.Decide(roles, caps, action);
            Assert.Equal(code == null, d.Allowed);
            Assert.Equal(code, d.Code);
        }

        [Fact]
        public void A_claim_of_another_shape_grants_nothing()
        {
            var claims = (Dictionary<string, object>)MiniJsonReader.Parse("{\"roles\":\"cashier\",\"cap\":[1,\"x\"]}");
            Assert.Empty(AccessRules.Names(claims, "roles"));
            Assert.Equal(new[] { "x" }, AccessRules.Names(claims, "cap"));
            Assert.Empty(AccessRules.Names(claims, "absent"));
        }
    }

    public class Lesson10Tests
    {
        sealed class Run
        {
            public LabResult Result;
            public TraceEvent[] Events;
            public string[] Sent(string actor) => Events.Where(e => e.Type == "wire.sent" && e.Actor == actor).Select(e => e.Message).ToArray();
            public string[] SentAfterTls(string actor) => Events.Where(e => e.Type == "wire.sent" && e.Actor == actor && !e.StreamId.Contains("/tls13")).Select(e => e.Message).ToArray();
        }

        static Run Go(AttackDefinition attack = null, int seed = 7)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = seed, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(seed), Attack = attack };
            IFuture<LabResult> future = new Lesson10Auth().Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return new Run { Result = future.Result, Events = sink.Events };
        }

        [Fact]
        public void Lesson_10_stays_unbuilt_until_its_tour_lands()
        {
            Assert.Null(LabCatalog.Find(10));
            Assert.DoesNotContain(AttackCatalog.All, a => a.Lesson == 10);
        }

        [Fact]
        public void The_control_completes_with_the_named_messages_and_passes_every_check()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.Equal(new[] { "LoginRequest", "ChallengeResponse", "LoginDone", "ReadTotals", "VoidSale", "CallsDone" }, run.SentAfterTls("client"));
            Assert.Equal(new[] { "Challenge", "TokenIssued" }, run.SentAfterTls("issuer"));
            Assert.Equal(new[] { "CallOk", "CallOk" }, run.SentAfterTls("server"));
            string[] passed = run.Events.Where(e => e.Type == "check.result" && e.Check.Passed && !e.StreamId.Contains("/tls13")).Select(e => e.Message).Distinct().ToArray();
            Assert.Equal(new[] { "device registered", "challenge issued", "challenge already used", "challenge signature", "token signature", "token expiry", "proof signature", "proof binding", "proof age", "jti already used", "permission check" }, passed);
            Assert.DoesNotContain(run.Events, e => e.Check != null && !e.Check.Passed);
        }

        [Fact]
        public void Token_fields_add_up_to_the_wire_and_the_claims_show_as_text()
        {
            Run run = Go();
            TraceEvent read = run.Events.First(e => e.Type == "wire.sent" && e.Message == "ReadTotals");
            Assert.Equal(read.Wire.Length, read.Fields.Sum(f => f.Length));
            TraceField claims = read.Fields.Single(f => f.Name == "tokenClaims");
            string text = Encoding.UTF8.GetString(Base64Url.Decode(Encoding.ASCII.GetString(read.Wire, claims.Offset, claims.Length)));
            Assert.Contains("\"roles\":[\"cashier\"]", text);
            TraceEvent measure = run.Events.Single(e => e.Type == "measure.result" && e.Message == "token claims");
            Assert.Equal(text, Encoding.UTF8.GetString(measure.Plain));
        }

        [Fact]
        public void A_same_seed_rerun_gives_the_same_engine_bytes()
        {
            string[] Lines(Run r) => r.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray();
            Assert.Equal(Lines(Go(null, 21)), Lines(Go(null, 21)));
        }

        [Fact]
        public void Every_row_stops_at_its_named_check_with_one_thing_changed()
        {
            AttackDefinition[] rows = AttackCatalog.Lesson10Unreleased;
            Assert.Equal(10, rows.Length);
            foreach (AttackDefinition a in rows)
            {
                Assert.Equal(1, (a.Plan != null ? 1 : 0) + a.Options.Length);
                Run run = Go(a);
                Assert.False(run.Result.Completed, a.AttackId + " ran to the end");
                Assert.Equal(a.ExpectCode, run.Result.FailedCode);
                Assert.Equal(a.ExpectCheck, run.Result.FailedCheck);
            }
        }

        static AttackDefinition Scenario(string name, string value) =>
            new AttackDefinition { AttackId = "test", Lesson = 10, Options = new[] { new LabOption { Name = name, Value = value } } };

        static AttackDefinition Row(string id) => AttackCatalog.Lesson10Unreleased.Single(a => a.AttackId == id);

        static string[] Checks(Run run, string actor, bool passed) =>
            run.Events.Where(e => e.Type == "check.result" && e.Actor == actor && e.Check.Passed == passed).Select(e => e.Message).ToArray();

        [Fact]
        public void A_challenge_never_issued_is_refused_before_the_signature_is_read()
        {
            Run run = Go(Row("L10-unissued-challenge"));
            Assert.Equal(ErrorCodes.ChallengeNotIssued, run.Result.FailedCode);
            Assert.Equal(new[] { Challenge.IssuedCheck }, Checks(run, "issuer", false));
            Assert.DoesNotContain(Challenge.SignatureCheck, Checks(run, "issuer", true));
        }

        [Fact]
        public void The_replay_row_fires_on_a_challenge_that_was_issued_and_then_used()
        {
            Run run = Go(Row("L10-replay-challenge"));
            Assert.Equal(ErrorCodes.ChallengeReplay, run.Result.FailedCode);
            Assert.Contains(Challenge.IssuedCheck, Checks(run, "issuer", true));
            Assert.Equal(new[] { Challenge.ReplayCheck }, Checks(run, "issuer", false));
        }

        [Fact]
        public void A_device_key_nobody_registered_gets_no_challenge()
        {
            Run run = Go(Row("L10-unknown-device"));
            Assert.Equal(ErrorCodes.DeviceUnknown, run.Result.FailedCode);
            Assert.DoesNotContain("Challenge", run.Sent("issuer"));
            Assert.DoesNotContain("TokenIssued", run.Sent("issuer"));
        }

        /// <summary>The small-order key verifies R = B, S = 1 for any message, so a client needs no private key. RFC 8032 allows that key, so the registration check is what stops it.</summary>
        [Fact]
        public void The_small_order_client_with_no_private_key_gets_no_token()
        {
            Run run = Go(Scenario(Lesson10Auth.OptionDeviceKey, Lesson10Auth.DeviceKeySmallOrder));
            Assert.False(run.Result.Completed);
            Assert.Equal(ErrorCodes.DeviceUnknown, run.Result.FailedCode);
            Assert.DoesNotContain("TokenIssued", run.Sent("issuer"));
        }

        [Fact]
        public void Each_token_is_bound_to_the_registered_key_across_seeds()
        {
            Run a = Go(null, 7), b = Go(null, 8);
            Assert.True(a.Result.Completed && b.Result.Completed);
            string Claims(Run r) => Encoding.UTF8.GetString(r.Events.Single(e => e.Type == "measure.result" && e.Message == "token claims").Plain);
            Assert.Contains("\"sub\":\"pump-reader-4\"", Claims(a));
            Assert.NotEqual(Claims(a), Claims(b));
        }

        [Fact]
        public void The_control_presents_a_client_certificate_that_the_server_checks()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            string[] clientTls = run.Events.Where(e => e.Type == "wire.sent" && e.Actor == "client" && e.StreamId.Contains("/tls13/")).Select(e => e.Message).ToArray();
            Assert.Equal(new[] { "ClientHello", "Certificate", "CertificateVerify", "Finished" }, clientTls.Take(4).ToArray());
            string[] serverTls = run.Events.Where(e => e.Type == "wire.sent" && e.Actor == "server" && e.StreamId.Contains("/tls13/")).Select(e => e.Message).ToArray();
            Assert.Equal(new[] { "ServerHello", "EncryptedExtensions", "CertificateRequest", "Certificate", "CertificateVerify", "Finished" }, serverTls.Take(6).ToArray());
            string[] serverChecks = run.Events.Where(e => e.Type == "check.result" && e.Actor == "server" && e.Check.Passed && e.StreamId.EndsWith("/tls13")).Select(e => e.Message).ToArray();
            Assert.Contains("bad_certificate alert", serverChecks);
            Assert.Contains("chain to trust anchor", serverChecks);
            Assert.Contains("CertificateVerify signature", serverChecks);
            Assert.Contains("Finished verify_data", serverChecks);
        }

        [Fact]
        public void With_no_client_certificate_the_server_sends_alert_116_and_no_login_starts()
        {
            Run run = Go(Row("L10-remove-client-cert"));
            Assert.Equal(Tls13Codes.ClientCertRequired, run.Result.FailedCode);
            Assert.Equal(116, Tls13Codes.AlertFor(Tls13Codes.ClientCertRequired));
            Assert.DoesNotContain("LoginRequest", run.Sent("client"));
            Assert.Contains("Alert", run.Sent("server"));
        }

        [Fact]
        public void The_flip_row_aims_inside_the_token_claims()
        {
            AttackDefinition change = AttackCatalog.Lesson10Unreleased.Single(a => a.AttackId == "L10-change-token-claim");
            Assert.Equal(Lesson10Auth.ClaimsOffset + 5, change.Plan.Offset);
            Run control = Go();
            TraceEvent read = control.Events.First(e => e.Type == "wire.sent" && e.Message == "ReadTotals");
            Assert.Equal(Lesson10Auth.ClaimsOffset, read.Fields.Single(f => f.Name == "tokenClaims").Offset);
        }
    }
}
