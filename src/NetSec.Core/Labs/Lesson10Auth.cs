using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 10. A device first shows a certificate to the server over mutual TLS. A device enrolled ahead of time then answers a challenge and gets a signed token bound to its key. A signature shows who calls only
    /// because the issuer already holds that key for that subject. The device then calls a server, with a fresh DPoP proof on each call, and the
    /// token's role or capability decides what it may do. The handshake, the login and the calls run on three separate connections. The login and
    /// the calls run in the clear, so the token shows on the wire, and neither of them reads the client certificate.
    /// A passkey-shaped challenge is not WebAuthn. Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson10Auth : ILab
    {
        public const string OptionTokenRole = "token-role";
        public const string OptionTokenExpired = "token-expired";
        public const string OptionReplayChallenge = "replay-challenge";
        public const string OptionReplayProof = "replay-proof";
        public const string OptionStolenToken = "stolen-token";
        public const string OptionCallRefund = "call-refund";
        public const string OptionAnswerUnissued = "answer-unissued";
        public const string OptionUnknownDevice = "unknown-device";
        public const string OptionDeviceKeyHex = "device-key-hex";
        public const string OptionTokenAudience = "token-audience";
        public const string OptionClientCert = "client-cert";
        public const string ClientCertNone = "none";
        public const string ClientCertCorrupt = "corrupt";
        const string ClientCertServerUsage = "server-usage";
        const string ClientCertUnknownCa = "unknown-ca";
        const string ClientCertExpired = "expired";
        const string ClientCertWrongKey = "wrong-key";
        public const string ClientCertWrongName = "wrong-name";
        const string WrongClientName = "bank-hsm-admin";

        // A fixed lab time, so a same-seed run gives the same bytes.
        const long LabNow = 1793836800;
        const int TokenLifeSeconds = 3600;
        const int ChallengeSize = 32;
        const int SeedSize = 32;
        const int PublicSize = 32;
        const int SignatureSize = 64;
        const int LengthPrefix = 2;
        const string Origin = "https://pump.training";
        const string BaseUrl = "https://pump.training/api/";
        const string Method = "POST";
        const string Subject = "pump-reader-4";
        const string Audience = "https://pump.training/api";
        const string IssuerName = "https://pump.training/issuer";
        const string Start0 = "Start";
        const string DeviceKeyName = "auth.device-key";
        const string TokenName = "auth.token";
        const string IssuerPublicName = "auth.issuer-public";

        const int LoginRequest = 1, ChallengeMessage = 2, ChallengeResponse = 3, TokenIssued = 4, LoginDone = 5;
        const int ReadTotals = 6, VoidSale = 7, Refund = 8, CallOk = 9, CallsDone = 10;

        static readonly string[] Names =
        {
            "", "LoginRequest", "Challenge", "ChallengeResponse", "TokenIssued", "LoginDone",
            "ReadTotals", "VoidSale", "Refund", "CallOk", "CallsDone",
        };

        /// <summary>Where the token's claims start in a ReadTotals frame, for a tamper plan.</summary>
        public static int ClaimsOffset { get { return Frame.HeaderSize + LengthPrefix + Token.HeaderPartLength + 1; } }

        /// <summary>The state of one lab run. One instance serves the client in both phases. A rule writes to it only through effects.</summary>
        sealed class Session : FrameSession
        {
            readonly Dictionary<string, bool> _seen = new Dictionary<string, bool>();
            public ITrainingKey Issuer;
            public string TokenRole = "cashier";
            public bool TokenExpired, ReplayChallenge, ReplayProof, StolenToken, CallRefund, AnswerUnissued, UnknownDevice;
            public byte[] PresentedKey;

            // Public protocol values, kept as state only. The nonce and the signed answer travel in the clear, so no trace lists them as secrets.
            public byte[] IssuedChallenge, LastAnswer;
            public string TokenAudience = Audience;

            // The issuer's one enrolment row. A real issuer holds one row per subject.
            public byte[] EnrolledKey;

            public Session(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "auth"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }

            public override void Absorb(byte[] seen) { _seen[Hex.Encode(seen)] = true; }
            public bool Seen(byte[] value) { return _seen.ContainsKey(Hex.Encode(value)); }
        }

        public string LabId { get { return "lab-10-auth"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, ret); });
        }

        /// <summary>The device's first connection. The bytes it echoes do not matter. The handshake is the point.</summary>
        static IFuture<LabResult> RunMutualTls(LabContext c, ITamperHook plan)
        {
            ITrainingKeySource keys = LabCredentials.Of(c);
            TrainingCa ca = new TrainingCa(keys);
            ITrainingKey serverKey = keys.Find(KeyIds.ServerTlsEd25519);
            DateTime now = AuthTime.FromUnix(LabNow);

            Tls13Options client = TlsOptions(c, plan, "client", "server", ca, now);
            PresentClientCertificate(client, LabPair.Option(c, OptionClientCert), keys, ca);

            Tls13Options server = TlsOptions(c, plan, "server", "client", ca, now);
            server.CertificateChain = new byte[][] { TrainingPki.ServerCertificate(ca, serverKey) };
            server.SigningSeed = serverKey.CopyMaterial();
            server.RequireClientCertificate = true;
            server.ExpectedClientName = TrainingPki.ClientName;

            Tls13Engine clientEngine = Tls13Engine.CreateClient(client);
            clientEngine.Command(new EngineCommand(EngineCommandKind.Send, 0, Encoding.UTF8.GetBytes("device hello" + (char)10), null));
            return LabPair.Run(c, clientEngine, Tls13Engine.CreateServer(server), plan, Tls13Lab.EchoThenClose);
        }

        static Tls13Options TlsOptions(LabContext c, ITamperHook plan, string actor, string peer, TrainingCa ca, DateTime now)
        {
            Tls13Options o = new Tls13Options();
            o.Stream = LabPair.Stream(c, actor, "auth-mtls");
            o.Peer = peer;
            o.Random = LabPair.Fork(c);
            o.Tamper = plan;
            o.Group = Tls13Group.X25519;
            o.ServerName = TrainingPki.ServerName;
            o.Now = now;
            o.TrustAnchors = new byte[][] { ca.RootCertificateDer };
            return o;
        }

        /// <summary>The one thing each attack changes about what the client shows. The control shows a good certificate and signs with its key.</summary>
        static void PresentClientCertificate(Tls13Options o, string scenario, ITrainingKeySource keys, TrainingCa ca)
        {
            if (scenario == ClientCertNone) return;
            ITrainingKey key = keys.Find(KeyIds.ClientTlsEd25519);
            ITrainingKey attacker = keys.Find(KeyIds.AttackerEd25519);
            byte[] spki = TrainingCa.Ed25519Spki(key.CopyPublic());
            byte[] leaf = TrainingPki.ClientCertificate(ca, key);
            byte[] seed = key.CopyMaterial();
            switch (scenario)
            {
                case ClientCertCorrupt:
                    leaf[leaf.Length - 1] ^= 1;
                    break;
                case ClientCertServerUsage:
                    leaf = ca.IssueServerCertificate(TrainingPki.ClientName, spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
                    break;
                case ClientCertUnknownCa:
                    leaf = TrainingPki.ClientCertificate(new TrainingCa(attacker, "Attacker training root"), key);
                    break;
                case ClientCertExpired:
                    leaf = ca.IssueClientCertificate(TrainingPki.ClientName, spki, new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc));
                    break;
                case ClientCertWrongKey:
                    seed = attacker.CopyMaterial();
                    break;
                case ClientCertWrongName:
                    leaf = ca.IssueClientCertificate(WrongClientName, TrainingCa.Ed25519Spki(attacker.CopyPublic()), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
                    seed = attacker.CopyMaterial();
                    break;
            }
            o.CertificateChain = new byte[][] { leaf };
            o.SigningSeed = seed;
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            ITrainingKey issuerKey = LabCredentials.Of(c).Find(KeyIds.TokenIssuer);
            ITamperHook plan = LabPair.Plan(c);

            IFuture<LabResult> mutual = RunMutualTls(c, plan);
            yield return mutual;
            if (!mutual.Result.Completed)
            {
                ret.Value = mutual.Result;
                yield break;
            }

            // Enrolment happens ahead of the login, out of band. The issuer learns this device's public key, and the device keeps its seed.
            byte[] deviceSeed = new byte[SeedSize];
            LabPair.Fork(c).Fill(deviceSeed, 0, SeedSize);
            ITrainingKey ownDevice = LabCredentials.Of(c).MineOrNull(SecurityTypes.DeviceEnrolment);
            if (ownDevice != null) deviceSeed = ownDevice.CopyMaterial();

            Session client = new Session(LabPair.Fork(c));
            client.Remember(DeviceKeyName, deviceSeed);
            client.AnswerUnissued = LabPair.Option(c, OptionAnswerUnissued) == "yes";
            client.UnknownDevice = LabPair.Option(c, OptionUnknownDevice) == "yes";
            string presented = LabPair.Option(c, OptionDeviceKeyHex);
            if (presented != null) client.PresentedKey = Hex.Decode(presented);
            client.ReplayChallenge = LabPair.Option(c, OptionReplayChallenge) == "yes";
            client.ReplayProof = LabPair.Option(c, OptionReplayProof) == "yes";
            client.StolenToken = LabPair.Option(c, OptionStolenToken) == "yes";
            client.CallRefund = LabPair.Option(c, OptionCallRefund) == "yes";

            Session issuer = new Session(LabPair.Fork(c));
            issuer.Issuer = issuerKey;
            issuer.EnrolledKey = Ed25519.PublicFrom(deviceSeed);
            string audience = LabPair.Option(c, OptionTokenAudience);
            if (audience != null) issuer.TokenAudience = audience;
            string role = LabPair.Option(c, OptionTokenRole);
            if (role != null) issuer.TokenRole = role;
            issuer.TokenExpired = LabPair.Option(c, OptionTokenExpired) == "yes";

            IFuture<LabResult> login = LabPair.Run(c,
                new FrameEngine<Session>(ClientLoginTable, client, Start0, LabPair.Stream(c, "client", "auth-login"), "issuer", plan),
                new FrameEngine<Session>(IssuerTable, issuer, Start0, LabPair.Stream(c, "issuer", "auth-login"), "client", plan),
                plan);
            yield return login;
            if (!login.Result.Completed)
            {
                ret.Value = login.Result;
                yield break;
            }

            Session server = new Session(LabPair.Fork(c));
            server.Remember(IssuerPublicName, issuerKey.CopyPublic());
            IFuture<LabResult> calls = LabPair.Run(c,
                new FrameEngine<Session>(ClientCallTable, client, Start0, LabPair.Stream(c, "client", "auth-call"), "server", plan),
                new FrameEngine<Session>(ServerTable, server, Start0, LabPair.Stream(c, "server", "auth-call"), "client", plan),
                plan);
            yield return calls;
            ret.Value = calls.Result;
        }

        // ---------------------------------------------------------------- login, client side

        static readonly StepTable<Session> ClientLoginTable = new StepTable<Session>(
            new StepRow<Session>("auth.c.login", Start0, InboundMessage.StartType, ClientLogin, "WaitChallenge"),
            new StepRow<Session>("auth.c.answer", "WaitChallenge", ChallengeMessage, ClientAnswer, "WaitToken"),
            new StepRow<Session>("auth.c.token", "WaitToken", TokenIssued, ClientToken, MachineStates.Closed));

        static StepDecision ClientLogin(Session s, InboundMessage m)
        {
            byte[] seed = s.UnknownDevice ? s.Draw(SeedSize) : s.Secret(DeviceKeyName);
            byte[] presented = s.PresentedKey ?? Ed25519.PublicFrom(seed);
            byte[] body = new ByteWriter().Put(Encoding.UTF8.GetBytes(Subject)).Put(presented).ToArray();
            return StepDecision.Advance(
                Effect.Secret("client", DeviceKeyName, seed),
                Send(LoginRequest, body, new FieldSpan("subject", "id", -1, PublicSize, true), new FieldSpan("devicePublicKey", "key", PublicSize, 0, true)));
        }

        static StepDecision ClientAnswer(Session s, InboundMessage m)
        {
            byte[] answered = s.AnswerUnissued ? new byte[ChallengeSize] : m.Body;
            byte[] response = new ByteWriter().Put(answered).Put(Challenge.Sign(s.Secret(DeviceKeyName), answered, Origin)).ToArray();
            return StepDecision.Advance(
                Effect.Store(delegate { s.LastAnswer = response; }),
                Send(ChallengeResponse, response, new FieldSpan("challenge", "random", ChallengeSize, 0, true), new FieldSpan("signature", "mac", -1, 0, true)));
        }

        static StepDecision ClientToken(Session s, InboundMessage m)
        {
            StepEffect keep = Effect.Secret("client", TokenName, m.Body);
            if (s.ReplayChallenge)
                return StepDecision.Advance(keep, Send(ChallengeResponse, s.LastAnswer, new FieldSpan("challenge", "random", ChallengeSize, 0, true), new FieldSpan("signature", "mac", -1, 0, true)));
            return StepDecision.Advance(keep, Send(LoginDone, new byte[0]));
        }

        // ---------------------------------------------------------------- login, issuer side

        static readonly StepTable<Session> IssuerTable = new StepTable<Session>(
            new StepRow<Session>("auth.i.start", Start0, InboundMessage.StartType, Nothing, "WaitLogin"),
            new StepRow<Session>("auth.i.login", "WaitLogin", LoginRequest, IssuerChallenge, "WaitResponse"),
            new StepRow<Session>("auth.i.response", "WaitResponse", ChallengeResponse, IssuerToken, "WaitDone"),
            new StepRow<Session>("auth.i.replay", "WaitDone", ChallengeResponse, IssuerToken, "WaitDone"),
            new StepRow<Session>("auth.i.done", "WaitDone", LoginDone, Nothing, MachineStates.Closed));

        static StepDecision Nothing(Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        static StepDecision IssuerChallenge(Session s, InboundMessage m)
        {
            if (m.Body.Length <= PublicSize) throw new ParseFailure(ErrorCodes.ParseTruncated, "a login request holds a subject and a " + PublicSize + "-byte key");
            byte[] subject = new byte[m.Body.Length - PublicSize], presented = new byte[PublicSize];
            Buffer.BlockCopy(m.Body, 0, subject, 0, subject.Length);
            Buffer.BlockCopy(m.Body, subject.Length, presented, 0, PublicSize);
            if (Encoding.UTF8.GetString(subject, 0, subject.Length) != Subject || !Same(presented, s.EnrolledKey))
                return StepDecision.Fail(ErrorCodes.DeviceNotEnrolled, Challenge.EnrolledCheck, "no enrolment row holds this key for this subject");
            byte[] challenge = s.Draw(ChallengeSize);
            return StepDecision.Advance(
                Effect.Check(Challenge.EnrolledCheck, ErrorCodes.DeviceNotEnrolled),
                Effect.Store(delegate { s.IssuedChallenge = challenge; }),
                Send(ChallengeMessage, challenge, new FieldSpan("challenge", "random", -1, 0, true)));
        }

        static StepDecision IssuerToken(Session s, InboundMessage m)
        {
            if (m.Body.Length != ChallengeSize + SignatureSize) throw new ParseFailure(ErrorCodes.ParseTruncated, "a challenge response holds " + (ChallengeSize + SignatureSize) + " bytes");
            byte[] challenge = new byte[ChallengeSize], signature = new byte[SignatureSize];
            Buffer.BlockCopy(m.Body, 0, challenge, 0, ChallengeSize);
            Buffer.BlockCopy(m.Body, ChallengeSize, signature, 0, SignatureSize);
            if (!Same(challenge, s.IssuedChallenge)) return StepDecision.Fail(ErrorCodes.ChallengeNotIssued, Challenge.IssuedCheck, "this issuer did not send this challenge in this login");
            if (s.Seen(challenge)) return StepDecision.Fail(ErrorCodes.ChallengeReplay, Challenge.ReplayCheck, "this challenge has been answered before");
            AuthDecision signed = Challenge.Verify(s.EnrolledKey, challenge, Origin, signature);
            if (!signed.Allowed) return StepDecision.Fail(signed.Code, signed.CheckName, signed.Detail);

            string claims = ClaimsFor(s);
            string token = Token.Issue(s.Issuer, claims);
            return StepDecision.Advance(
                Effect.Check(Challenge.IssuedCheck, ErrorCodes.ChallengeNotIssued),
                Effect.Check(Challenge.SignatureCheck, ErrorCodes.ChallengeBadSignature),
                Effect.Check(Challenge.ReplayCheck, ErrorCodes.ChallengeReplay),
                Effect.Absorb(challenge),
                Effect.Measure("token claims", null, Encoding.UTF8.GetBytes(claims)),
                SendToken(token));
        }

        static string ClaimsFor(Session s)
        {
            long exp = s.TokenExpired ? LabNow - 1 : LabNow + TokenLifeSeconds;
            return "{\"iss\":" + MiniJson.Quote(IssuerName) + ",\"aud\":" + MiniJson.Quote(s.TokenAudience) + ",\"sub\":" + MiniJson.Quote(Subject)
                + ",\"roles\":[" + MiniJson.Quote(s.TokenRole) + "],\"cap\":[\"void-sale\"],\"iat\":" + LabNow + ",\"exp\":" + exp
                + ",\"cnf\":{\"jkt\":\"" + DpopProof.Thumbprint(s.EnrolledKey) + "\"}}";
        }

        static StepEffect SendToken(string token)
        {
            string[] parts = token.Split('.');
            return Send(TokenIssued, Encoding.UTF8.GetBytes(token),
                new FieldSpan("tokenHeader", "header", parts[0].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                new FieldSpan("tokenClaims", "data", parts[1].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                new FieldSpan("tokenSignature", "mac", parts[2].Length, 0, true));
        }

        // ---------------------------------------------------------------- calls, client side

        static readonly StepTable<Session> ClientCallTable = new StepTable<Session>(
            new StepRow<Session>("auth.c.read", Start0, InboundMessage.StartType, ClientRead, "WaitRead"),
            new StepRow<Session>("auth.c.void", "WaitRead", CallOk, ClientVoid, "WaitVoid"),
            new StepRow<Session>("auth.c.done", "WaitVoid", CallOk, ClientDone, MachineStates.Closed));

        static StepDecision ClientRead(Session s, InboundMessage m)
        {
            return Call(s, ReadTotals, "read-totals");
        }

        static StepDecision ClientVoid(Session s, InboundMessage m)
        {
            if (s.ReplayProof)
            {
                byte[] again = s.Secret("auth.last-call");
                return StepDecision.Advance(Send(ReadTotals, again));
            }
            return Call(s, VoidSale, "void-sale");
        }

        static StepDecision ClientDone(Session s, InboundMessage m)
        {
            if (s.CallRefund) return Call(s, Refund, "refund");
            return StepDecision.Advance(Send(CallsDone, new byte[0]));
        }

        static StepDecision Call(Session s, int type, string action)
        {
            string token = Encoding.UTF8.GetString(s.Secret(TokenName), 0, s.Secret(TokenName).Length);
            string jti = Hex.Encode(s.Draw(16));
            byte[] proofKey = s.StolenToken ? s.Draw(SeedSize) : s.Secret(DeviceKeyName);
            string proof = DpopProof.Create(proofKey, Method, BaseUrl + action, LabNow, jti, token);
            byte[] tokenBytes = Encoding.UTF8.GetBytes(token), proofBytes = Encoding.UTF8.GetBytes(proof);
            byte[] body = new ByteWriter().U16(tokenBytes.Length).Put(tokenBytes).U16(proofBytes.Length).Put(proofBytes).ToArray();
            string[] t = token.Split('.'), p = proof.Split('.');
            byte[] proofClaims = Base64Url.Decode(p[1]);
            return StepDecision.Advance(
                Effect.Secret("client", "auth.last-call", body),
                Effect.Measure("proof claims", null, proofClaims),
                Send(type, body,
                    new FieldSpan("tokenLength", "length", LengthPrefix, 0, true),
                    new FieldSpan("tokenHeader", "header", t[0].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                    new FieldSpan("tokenClaims", "data", t[1].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                    new FieldSpan("tokenSignature", "mac", t[2].Length, 0, true),
                    new FieldSpan("proofLength", "length", LengthPrefix, 0, true),
                    new FieldSpan("proofHeader", "header", p[0].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                    new FieldSpan("proofClaims", "data", p[1].Length, 0, true), new FieldSpan("dot", "header", 1, 0, true),
                    new FieldSpan("proofSignature", "mac", p[2].Length, 0, true)));
        }

        // ---------------------------------------------------------------- calls, server side

        static readonly StepTable<Session> ServerTable = new StepTable<Session>(
            new StepRow<Session>("auth.s.start", Start0, InboundMessage.StartType, Nothing, "WaitCall"),
            new StepRow<Session>("auth.s.read", "WaitCall", ReadTotals, ServeRead, "WaitCall"),
            new StepRow<Session>("auth.s.void", "WaitCall", VoidSale, ServeVoid, "WaitCall"),
            new StepRow<Session>("auth.s.refund", "WaitCall", Refund, ServeRefund, "WaitCall"),
            new StepRow<Session>("auth.s.done", "WaitCall", CallsDone, Nothing, MachineStates.Closed));

        static StepDecision ServeRead(Session s, InboundMessage m) { return Serve(s, m, "read-totals"); }
        static StepDecision ServeVoid(Session s, InboundMessage m) { return Serve(s, m, "void-sale"); }
        static StepDecision ServeRefund(Session s, InboundMessage m) { return Serve(s, m, "refund"); }

        static StepDecision Serve(Session s, InboundMessage m, string action)
        {
            ByteReader reader = new ByteReader(m.Body, 0, m.Body.Length, true);
            byte[] tokenBytes = reader.Take("token", "data", reader.U16("tokenLength", "length"));
            byte[] proofBytes = reader.Take("proof", "data", reader.U16("proofLength", "length"));
            string token = Encoding.UTF8.GetString(tokenBytes, 0, tokenBytes.Length);
            string proof = Encoding.UTF8.GetString(proofBytes, 0, proofBytes.Length);

            AuthDecision tokenDecision = Token.Verify(s.Secret(IssuerPublicName), token, AuthTime.FromUnix(LabNow));
            if (!tokenDecision.Allowed) return StepDecision.Fail(tokenDecision.Code, tokenDecision.CheckName, tokenDecision.Detail);
            object aud;
            if (!tokenDecision.Claims.TryGetValue("aud", out aud) || !Audience.Equals(aud))
                return StepDecision.Fail(ErrorCodes.TokenBadAudience, Token.AudienceCheck, "this token was written for another audience");

            AuthDecision proofDecision = DpopProof.Check(proof, Method, BaseUrl + action, LabNow, token, BoundKey(tokenDecision.Claims));
            if (!proofDecision.Allowed) return StepDecision.Fail(proofDecision.Code, proofDecision.CheckName, proofDecision.Detail);
            byte[] jti = Encoding.UTF8.GetBytes(proofDecision.Jti);
            if (s.Seen(jti)) return StepDecision.Fail(ErrorCodes.DpopReplay, DpopProof.ReplayCheck, "this proof has been used before");

            AuthDecision access = AccessRules.Decide(AccessRules.Names(tokenDecision.Claims, "roles"), AccessRules.Names(tokenDecision.Claims, "cap"), action);
            if (!access.Allowed) return StepDecision.Fail(access.Code, access.CheckName, access.Detail);

            return StepDecision.Stay(
                Effect.Check(Token.SignatureCheck, ErrorCodes.TokenBadSignature),
                Effect.Check(Token.ExpiryCheck, ErrorCodes.TokenExpired),
                Effect.Check(Token.AudienceCheck, ErrorCodes.TokenBadAudience),
                Effect.Check(DpopProof.SignatureCheck, ErrorCodes.DpopBadSignature),
                Effect.Check(DpopProof.BindingCheck, ErrorCodes.DpopJktMismatch),
                Effect.Check(DpopProof.AgeCheck, ErrorCodes.DpopIatWindow),
                Effect.Check(DpopProof.ReplayCheck, ErrorCodes.DpopReplay),
                Effect.Absorb(jti),
                Effect.Check(AccessRules.PermissionCheck, ErrorCodes.CapabilityDenied),
                Send(CallOk, new byte[0]));
        }

        // Plain compares: a public key and a challenge the issuer sent in the clear are both public, so their timing reveals nothing secret.
        static bool Same(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        static string BoundKey(Dictionary<string, object> claims)
        {
            object cnf, jkt;
            if (!claims.TryGetValue("cnf", out cnf)) return null;
            Dictionary<string, object> members = cnf as Dictionary<string, object>;
            return members != null && members.TryGetValue("jkt", out jkt) ? jkt as string : null;
        }

        static StepEffect Send(int type, byte[] body, params FieldSpan[] spans)
        {
            return Effect.SendProtected(Names[type], body, Frame.Build(type, body), Frame.Fields(body.Length, spans));
        }
    }
}
