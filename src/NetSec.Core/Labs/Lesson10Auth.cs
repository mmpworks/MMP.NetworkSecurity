using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Auth;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 10. Three phases, each proving who calls a different way. First a mutual TLS handshake, where the device shows a certificate.
    /// Then a registered device answers a challenge and gets a signed token bound to its key. Then it calls a server, with a fresh DPoP proof on
    /// each call, and the token's role or capability decides what it may do. The login and calls run in the clear so the token shows on the wire.
    /// A real system sends them inside TLS. A passkey-shaped challenge is not WebAuthn. Built to show the parts. Do not copy.
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
        public const string OptionDeviceKey = "device-key";
        public const string DeviceKeyOther = "other";
        public const string DeviceKeySmallOrder = "small-order";
        public const string OptionClientCert = "client-cert";
        public const string ClientCertNone = "none";
        public const string ClientCertCorrupt = "corrupt";

        // A fixed lab time, so a same-seed run gives the same bytes.
        const long LabNow = 1793836800;
        const int TokenLifeSeconds = 3600;
        const int ChallengeSize = 32;
        const int SeedSize = 32;
        const int PublicSize = 32;
        const int SignatureSize = 64;
        const int LengthPrefix = 2;
        const int SignatureBytesFromEnd = 10;   // Inside the certificate's Ed25519 signature, the last field of its DER.
        const string Origin = "https://pump.training";
        const string BaseUrl = "https://pump.training/api/";
        const string Method = "POST";
        const string Start0 = "Start";
        const string Subject = "pump-reader-4";
        const string DeviceKeyName = "auth.device-key";
        const string TokenName = "auth.token";
        const string ChallengeName = "auth.challenge";
        const string DevicePublicName = "auth.device-public";
        const string IssuerPublicName = "auth.issuer-public";

        const int LoginRequest = 1, ChallengeMessage = 2, ChallengeResponse = 3, TokenIssued = 4, LoginDone = 5;
        const int ReadTotals = 6, VoidSale = 7, Refund = 8, CallOk = 9, CallsDone = 10;

        static readonly string[] Names =
        {
            "", "LoginRequest", "Challenge", "ChallengeResponse", "TokenIssued", "LoginDone",
            "ReadTotals", "VoidSale", "Refund", "CallOk", "CallsDone",
        };

        // A client with no private key. Under the neutral point y = 1, the signature R = B, S = 1 verifies for any message (RFC 8032 allows this key).
        static readonly byte[] SmallOrderPublic = Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000");
        static readonly byte[] AnySmallOrderSignature = Hex.Decode("5866666666666666666666666666666666666666666666666666666666666666" + "0100000000000000000000000000000000000000000000000000000000000000");

        /// <summary>Where the token's claims start in a ReadTotals frame, for a tamper plan.</summary>
        public static int ClaimsOffset { get { return Frame.HeaderSize + LengthPrefix + Token.HeaderPartLength + 1; } }

        /// <summary>The state of one lab run. One instance serves the client in both phases. A rule writes to it only through effects.</summary>
        sealed class Session : FrameSession
        {
            readonly Dictionary<string, bool> _seen = new Dictionary<string, bool>();
            readonly Dictionary<string, byte[]> _registered = new Dictionary<string, byte[]>();
            public ITrainingKey Issuer;
            public string TokenRole = "cashier";
            public bool TokenExpired, ReplayChallenge, ReplayProof, StolenToken, CallRefund, AnswerUnissued, SmallOrderDevice;
            public byte[] DeviceSeed;
            public string LoginSubject;
            public byte[] IssuedChallenge;

            public Session(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "auth"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }

            public override void Absorb(byte[] seen) { _seen[Hex.Encode(seen)] = true; }
            public bool Seen(byte[] value) { return _seen.ContainsKey(Hex.Encode(value)); }

            public void Register(string subject, byte[] publicKey) { _registered[subject] = publicKey; }

            /// <summary>True when this exact key is on record for this subject.</summary>
            public bool IsRegistered(string subject, byte[] publicKey)
            {
                byte[] held;
                return _registered.TryGetValue(subject, out held) && held.Length == publicKey.Length && ConstantTime.Equal(held, 0, publicKey, 0, held.Length);
            }
        }

        public string LabId { get { return "lab-10-auth"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, ret); });
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            ITrainingKeySource keys = new TrainingKeySource();
            ITrainingKey issuerKey = keys.Find(KeyIds.TokenIssuer);
            ITamperHook plan = LabPair.Plan(c);

            Session client = new Session(LabPair.Fork(c));
            client.ReplayChallenge = LabPair.Option(c, OptionReplayChallenge) == "yes";
            client.ReplayProof = LabPair.Option(c, OptionReplayProof) == "yes";
            client.StolenToken = LabPair.Option(c, OptionStolenToken) == "yes";
            client.CallRefund = LabPair.Option(c, OptionCallRefund) == "yes";
            client.AnswerUnissued = LabPair.Option(c, OptionAnswerUnissued) == "yes";
            client.SmallOrderDevice = LabPair.Option(c, OptionDeviceKey) == DeviceKeySmallOrder;

            Session issuer = new Session(LabPair.Fork(c));
            issuer.Issuer = issuerKey;
            string role = LabPair.Option(c, OptionTokenRole);
            if (role != null) issuer.TokenRole = role;
            issuer.TokenExpired = LabPair.Option(c, OptionTokenExpired) == "yes";

            // Enrolment, before this lab starts: the device made a key, and the issuer filed its public half under the device's name.
            byte[] enrolledSeed = client.Draw(SeedSize);
            issuer.Register(Subject, Ed25519.PublicFrom(enrolledSeed));
            client.DeviceSeed = LabPair.Option(c, OptionDeviceKey) == DeviceKeyOther ? client.Draw(SeedSize) : enrolledSeed;

            IFuture<LabResult> handshake = RunMutualTls(c, plan, keys, enrolledSeed);
            yield return handshake;
            if (!handshake.Result.Completed)
            {
                ret.Value = handshake.Result;
                yield break;
            }

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

        // ---------------------------------------------------------------- mutual TLS

        /// <summary>The server asks for a certificate and requires one. The client sends one line, the server sends it back, and the client closes.</summary>
        static IFuture<LabResult> RunMutualTls(LabContext c, ITamperHook plan, ITrainingKeySource keys, byte[] deviceSeed)
        {
            TrainingCa ca = new TrainingCa(keys);
            DateTime now = AuthTime.FromUnix(LabNow);
            byte[] root = ca.RootCertificateDer;

            Tls13Options client = MutualTlsOptions(c, plan, "client", "server", now);
            client.TrustAnchors = new byte[][] { root };
            string certificateChoice = LabPair.Option(c, OptionClientCert);
            if (certificateChoice != ClientCertNone)
            {
                byte[] spki = TrainingCa.Ed25519Spki(Ed25519.PublicFrom(deviceSeed));
                byte[] leaf = ca.IssueClientCertificate(Subject, spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
                if (certificateChoice == ClientCertCorrupt) leaf[leaf.Length - SignatureBytesFromEnd] ^= 1;
                client.ClientCertificateChain = new byte[][] { leaf };
                client.ClientSigningSeed = deviceSeed;
            }

            Tls13Options server = MutualTlsOptions(c, plan, "server", "client", now);
            ITrainingKey serverKey = keys.Find(KeyIds.ServerTlsEd25519);
            server.CertificateChain = new byte[][] { ca.IssueServerCertificate(TrainingPki.ServerName, TrainingCa.Ed25519Spki(serverKey.CopyPublic()), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter) };
            server.SigningSeed = serverKey.CopyMaterial();
            server.ClientTrustAnchors = new byte[][] { root };
            server.ClientName = Subject;

            Tls13Engine clientEngine = Tls13Engine.CreateClient(client);
            clientEngine.Command(new EngineCommand(EngineCommandKind.Send, 0, Encoding.UTF8.GetBytes("hello from the device\n"), null));
            return LabPair.Run(c, clientEngine, Tls13Engine.CreateServer(server), plan, EchoThenClose);
        }

        static Tls13Options MutualTlsOptions(LabContext c, ITamperHook plan, string actor, string peer, DateTime now)
        {
            Tls13Options o = new Tls13Options();
            o.Stream = LabPair.Stream(c, actor, "tls13");
            o.Peer = peer;
            o.Random = LabPair.Fork(c);
            o.Tamper = plan;
            o.Group = Tls13Group.X25519;
            o.ServerName = TrainingPki.ServerName;
            o.Now = now;
            return o;
        }

        static void EchoThenClose(EnginePump client, EnginePump server)
        {
            server.OnApp = delegate(AppChunk chunk) { server.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, chunk.Bytes, null)); };
            client.OnApp = delegate(AppChunk chunk) { client.Enqueue(EngineCommand.Close); };
        }

        // ---------------------------------------------------------------- login, client side

        static readonly StepTable<Session> ClientLoginTable = new StepTable<Session>(
            new StepRow<Session>("auth.c.login", Start0, InboundMessage.StartType, ClientLogin, "WaitChallenge"),
            new StepRow<Session>("auth.c.answer", "WaitChallenge", ChallengeMessage, ClientAnswer, "WaitToken"),
            new StepRow<Session>("auth.c.token", "WaitToken", TokenIssued, ClientToken, MachineStates.Closed));

        static StepDecision ClientLogin(Session s, InboundMessage m)
        {
            byte[] publicKey = s.SmallOrderDevice ? SmallOrderPublic : Ed25519.PublicFrom(s.DeviceSeed);
            byte[] subject = Encoding.UTF8.GetBytes(Subject);
            byte[] request = new ByteWriter().U8(subject.Length).Put(subject).Put(publicKey).ToArray();
            return StepDecision.Advance(
                Effect.Secret("client", DeviceKeyName, s.DeviceSeed),
                Send(LoginRequest, request,
                    new FieldSpan("subjectLength", "length", 1, 0, true),
                    new FieldSpan("subject", "data", subject.Length, 0, true),
                    new FieldSpan("devicePublicKey", "key", -1, 0, true)));
        }

        static StepDecision ClientAnswer(Session s, InboundMessage m)
        {
            byte[] challenge = s.AnswerUnissued ? new byte[ChallengeSize] : m.Body;
            byte[] signature = s.SmallOrderDevice ? AnySmallOrderSignature : Challenge.Sign(s.Secret(DeviceKeyName), challenge, Origin);
            byte[] response = new ByteWriter().Put(challenge).Put(signature).ToArray();
            return StepDecision.Advance(
                Effect.Secret("client", ChallengeName, response),
                Send(ChallengeResponse, response, new FieldSpan("challenge", "random", ChallengeSize, 0, true), new FieldSpan("signature", "mac", -1, 0, true)));
        }

        static StepDecision ClientToken(Session s, InboundMessage m)
        {
            StepEffect keep = Effect.Secret("client", TokenName, m.Body);
            if (s.ReplayChallenge)
                return StepDecision.Advance(keep, Send(ChallengeResponse, s.Secret(ChallengeName), new FieldSpan("challenge", "random", ChallengeSize, 0, true), new FieldSpan("signature", "mac", -1, 0, true)));
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

        /// <summary>
        /// The issuer trusts its own record and never the key in the request. An unknown key gets no challenge. A small-order key is valid under
        /// RFC 8032 and verifies a forged signature, so this record is what stops a client with no private key.
        /// </summary>
        static StepDecision IssuerChallenge(Session s, InboundMessage m)
        {
            ByteReader reader = new ByteReader(m.Body, 0, m.Body.Length, true);
            byte[] subjectBytes = reader.Take("subject", "data", reader.U8("subjectLength", "length"));
            byte[] publicKey = reader.Take("devicePublicKey", "key", reader.Remaining);
            string subject = Encoding.UTF8.GetString(subjectBytes, 0, subjectBytes.Length);
            if (!s.IsRegistered(subject, publicKey)) return StepDecision.Fail(ErrorCodes.DeviceUnknown, Challenge.DeviceCheck, "no device with this key is registered under the name " + subject);

            byte[] challenge = s.Draw(ChallengeSize);
            return StepDecision.Advance(
                Effect.Check(Challenge.DeviceCheck, ErrorCodes.DeviceUnknown),
                Effect.Secret("issuer", DevicePublicName, publicKey),
                Effect.Store(delegate { s.LoginSubject = subject; s.IssuedChallenge = challenge; }),
                Send(ChallengeMessage, challenge, new FieldSpan("challenge", "random", -1, 0, true)));
        }

        static StepDecision IssuerToken(Session s, InboundMessage m)
        {
            if (m.Body.Length != ChallengeSize + SignatureSize) throw new ParseFailure(ErrorCodes.ParseTruncated, "a challenge response holds " + (ChallengeSize + SignatureSize) + " bytes");
            byte[] challenge = new byte[ChallengeSize], signature = new byte[SignatureSize];
            Buffer.BlockCopy(m.Body, 0, challenge, 0, ChallengeSize);
            Buffer.BlockCopy(m.Body, ChallengeSize, signature, 0, SignatureSize);
            // The issued value is the freshness: a recorded answer from an earlier login names a challenge this login never issued.
            if (!ConstantTime.Equal(challenge, 0, s.IssuedChallenge, 0, ChallengeSize)) return StepDecision.Fail(ErrorCodes.ChallengeNotIssued, Challenge.IssuedCheck, "this login issued a different challenge");
            if (s.Seen(challenge)) return StepDecision.Fail(ErrorCodes.ChallengeReplay, Challenge.ReplayCheck, "this challenge has been answered before");
            AuthDecision signed = Challenge.Verify(s.Secret(DevicePublicName), challenge, Origin, signature);
            if (!signed.Allowed) return StepDecision.Fail(signed.Code, signed.CheckName, signed.Detail);

            string claims = ClaimsFor(s);
            string token = Token.Issue(s.Issuer, claims);
            return StepDecision.Advance(
                Effect.Check(Challenge.IssuedCheck, ErrorCodes.ChallengeNotIssued),
                Effect.Check(Challenge.ReplayCheck, ErrorCodes.ChallengeReplay),
                Effect.Check(Challenge.SignatureCheck, ErrorCodes.ChallengeBadSignature),
                Effect.Absorb(challenge),
                Effect.Measure("token claims", null, Encoding.UTF8.GetBytes(claims)),
                SendToken(token));
        }

        static string ClaimsFor(Session s)
        {
            long exp = s.TokenExpired ? LabNow - 1 : LabNow + TokenLifeSeconds;
            return "{\"sub\":" + MiniJson.Quote(s.LoginSubject) + ",\"roles\":[" + MiniJson.Quote(s.TokenRole) + "],\"cap\":[\"void-sale\"],\"iat\":" + LabNow + ",\"exp\":" + exp
                + ",\"cnf\":{\"jkt\":\"" + DpopProof.Thumbprint(s.Secret(DevicePublicName)) + "\"}}";
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

            AuthDecision proofDecision = DpopProof.Check(proof, Method, BaseUrl + action, LabNow, token, BoundKey(tokenDecision.Claims));
            if (!proofDecision.Allowed) return StepDecision.Fail(proofDecision.Code, proofDecision.CheckName, proofDecision.Detail);
            byte[] jti = Encoding.UTF8.GetBytes(proofDecision.Jti);
            if (s.Seen(jti)) return StepDecision.Fail(ErrorCodes.DpopReplay, DpopProof.ReplayCheck, "this proof has been used before");

            AuthDecision access = AccessRules.Decide(AccessRules.Names(tokenDecision.Claims, "roles"), AccessRules.Names(tokenDecision.Claims, "cap"), action);
            if (!access.Allowed) return StepDecision.Fail(access.Code, access.CheckName, access.Detail);

            return StepDecision.Stay(
                Effect.Check(Token.SignatureCheck, ErrorCodes.TokenBadSignature),
                Effect.Check(Token.ExpiryCheck, ErrorCodes.TokenExpired),
                Effect.Check(DpopProof.SignatureCheck, ErrorCodes.DpopBadSignature),
                Effect.Check(DpopProof.BindingCheck, ErrorCodes.DpopJktMismatch),
                Effect.Check(DpopProof.AgeCheck, ErrorCodes.DpopIatWindow),
                Effect.Check(DpopProof.ReplayCheck, ErrorCodes.DpopReplay),
                Effect.Absorb(jti),
                Effect.Check(AccessRules.PermissionCheck, ErrorCodes.CapabilityDenied),
                Send(CallOk, new byte[0]));
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
