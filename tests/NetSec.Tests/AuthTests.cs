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
            public string[] Sent(string actor) => Events.Where(e => e.Type == "wire.sent" && e.Actor == actor && !e.StreamId.Contains("auth-mtls")).Select(e => e.Message).ToArray();
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
        public void Lesson_10_is_released_with_its_lab_and_its_rows()
        {
            Assert.Equal("lab-10-auth", LabCatalog.Find(10).LabId);
            Assert.Equal(13, AttackCatalog.All.Count(a => a.Lesson == 10));
        }

        [Fact]
        public void The_control_completes_with_the_named_messages_and_passes_every_check()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.Equal(new[] { "LoginRequest", "ChallengeResponse", "LoginDone", "ReadTotals", "VoidSale", "CallsDone" }, run.Sent("client"));
            Assert.Equal(new[] { "Challenge", "TokenIssued" }, run.Sent("issuer"));
            Assert.Equal(new[] { "CallOk", "CallOk" }, run.Sent("server"));
            string[] passed = run.Events.Where(e => e.Type == "check.result" && e.Check.Passed && !e.StreamId.Contains("auth-mtls")).Select(e => e.Message).Distinct().ToArray();
            Assert.Equal(new[] { "device enrolled", "challenge issued", "challenge signature", "challenge already used", "token signature", "token expiry", "token audience", "proof signature", "proof binding", "proof age", "jti already used", "permission check" }, passed);
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
            AttackDefinition[] rows = AttackCatalog.All.Where(a => a.Lesson == 10).ToArray();
            Assert.Equal(13, rows.Length);
            foreach (AttackDefinition a in rows)
            {
                Assert.Equal(1, (a.Plan != null ? 1 : 0) + a.Options.Length);
                Run run = Go(a);
                Assert.False(run.Result.Completed, a.AttackId + " ran to the end");
                Assert.Equal(a.ExpectCode, run.Result.FailedCode);
                Assert.Equal(a.ExpectCheck, run.Result.FailedCheck);
            }
        }

        /// <summary>
        /// Jared's ruling: the challenge nonce and the signed answer travel in the clear and are public protocol values.
        /// Only the device key, the bearer token and the last call (token plus DPoP proof) are listed as secrets.
        /// </summary>
        [Fact]
        public void The_control_lists_the_device_key_the_token_and_the_last_call_as_its_only_secrets()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            TraceSecret[] secrets = run.Events.Where(e => e.Secrets != null && !e.StreamId.Contains("auth-mtls")).SelectMany(e => e.Secrets).ToArray();
            Assert.Equal(new[] { "client.auth.device-key", "client.auth.token", "client.auth.last-call" }, secrets.Select(s => s.Holder + "." + s.Name).Distinct().ToArray());
            Assert.DoesNotContain(run.Events, e => e.Actor == "issuer" && e.Secrets != null && !e.StreamId.Contains("auth-mtls"));
        }

        [Fact]
        public void Every_secrets_row_the_lesson_10_tour_points_at_is_a_secret_the_control_lists()
        {
            string tour = System.IO.File.ReadAllText(TourFile(10));
            string[] targets = System.Text.RegularExpressions.Regex.Matches(tour, "\"secrets:row=(?<row>[^\"]+)\"").Cast<System.Text.RegularExpressions.Match>().Select(m => m.Groups["row"].Value).ToArray();
            Assert.NotEmpty(targets);
            Run run = Go();
            string[] listed = run.Events.Where(e => e.Secrets != null && !e.StreamId.Contains("auth-mtls")).SelectMany(e => e.Secrets).Select(s => s.Holder + "." + s.Name).Distinct().ToArray();
            foreach (string row in targets) Assert.True(listed.Contains(row), "lesson-10.json points at secrets row " + row + ", and the control lists only " + string.Join(", ", listed));
        }

        static string TourFile(int lesson)
        {
            string name = System.IO.Path.Combine("app", "src", "tours", "lesson-" + lesson.ToString("00") + ".json");
            for (System.IO.DirectoryInfo d = new System.IO.DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
            {
                string path = System.IO.Path.Combine(d.FullName, name);
                if (System.IO.File.Exists(path)) return path;
            }
            throw new InvalidOperationException("no " + name + " above " + AppContext.BaseDirectory);
        }

        [Fact]
        public void The_flip_row_aims_inside_the_token_claims()
        {
            AttackDefinition change = AttackCatalog.All.Where(a => a.Lesson == 10).Single(a => a.AttackId == "L10-change-token-claim");
            Assert.Equal(Lesson10Auth.ClaimsOffset + 5, change.Plan.Offset);
            Run control = Go();
            TraceEvent read = control.Events.First(e => e.Type == "wire.sent" && e.Message == "ReadTotals");
            Assert.Equal(Lesson10Auth.ClaimsOffset, read.Fields.Single(f => f.Name == "tokenClaims").Offset);
        }
    }
}
