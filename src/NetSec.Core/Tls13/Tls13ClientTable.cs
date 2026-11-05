using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;
using NetSec.Pki;

namespace NetSec.Tls13
{
    /// <summary>The client rows of design section 2.6. Each rule reads the session, works on values, and returns effects.</summary>
    static class Tls13ClientTable
    {
        public const string Start = "Start";
        const string WaitServerHello = "WaitServerHello", WaitEE = "WaitEE", WaitCertOrReq = "WaitCertOrReq", WaitCert = "WaitCert",
            WaitCertVerify = "WaitCertVerify", WaitFinished = "WaitFinished", Open = MachineStates.Open;

        public static readonly StepTable<Tls13Session> Table = new StepTable<Tls13Session>(
            new StepRow<Tls13Session>("tls13.c.ch", Start, InboundMessage.StartType, ClientHello, WaitServerHello),
            new StepRow<Tls13Session>("tls13.c.sh", WaitServerHello, HandshakeType.ServerHello, ServerHello, WaitEE),
            new StepRow<Tls13Session>("tls13.c.ee", WaitEE, HandshakeType.EncryptedExtensions, Absorb, WaitCertOrReq),
            new StepRow<Tls13Session>("tls13.c.creq", WaitCertOrReq, HandshakeType.CertificateRequest, CertificateRequest, WaitCert),
            new StepRow<Tls13Session>("tls13.c.cert", WaitCertOrReq, HandshakeType.Certificate, Certificate, WaitCertVerify),
            new StepRow<Tls13Session>("tls13.c.cert", WaitCert, HandshakeType.Certificate, Certificate, WaitCertVerify),
            new StepRow<Tls13Session>("tls13.c.cv", WaitCertVerify, HandshakeType.CertificateVerify, CertificateVerify, WaitFinished),
            new StepRow<Tls13Session>("tls13.c.fin", WaitFinished, HandshakeType.Finished, Finished, Open),
            new StepRow<Tls13Session>("tls13.c.app", Open, HandshakeType.ApplicationData, Tls13Rules.OpenData, Open),
            new StepRow<Tls13Session>("tls13.c.ticket", Open, HandshakeType.NewSessionTicket, Tls13Rules.OpenTicket, Open),
            new StepRow<Tls13Session>("tls13.c.keyupdate", Open, HandshakeType.KeyUpdate, Tls13Rules.OpenKeyUpdate, Open));

        static StepDecision ClientHello(Tls13Session session, InboundMessage message)
        {
            Tls13Options o = session.Options;
            byte[] random = session.Draw(32);
            if (o.OfferOnlyTls11)
            {
                byte[] legacy = Tls13Messages.LegacyClientHello(random, o.ServerName);
                return StepDecision.Advance(Effect.Send("ClientHello", legacy, Tls13Messages.FieldsOf(HandshakeType.ClientHello, legacy, true)), Effect.Absorb(legacy));
            }
            KeyShareOffer offer = KeyExchange.Offer(o.Group, o.Random);
            byte[] hello = Tls13Messages.ClientHello(random, o.ServerName, o.Group, offer.Share);
            return StepDecision.Advance(
                Effect.Note("kex.share.computed", Tls13GroupInfo.Name(o.Group) + " client share, " + offer.Share.Length + " bytes"),
                Effect.Store(delegate { session.Offer = offer; session.ClientRandom = random; }),
                Effect.Send("ClientHello", hello, Tls13Messages.FieldsOf(HandshakeType.ClientHello, hello, true)),
                Effect.Absorb(hello));
        }

        static StepDecision ServerHello(Tls13Session session, InboundMessage message)
        {
            ServerHelloInfo hello = Tls13Messages.ReadServerHello(message.Bytes);
            if (hello.IsHelloRetry) return Tls13Rules.Refuse(Tls13Codes.HrrUnsupported, "the server asked for a second key share round, and this engine offers one group");
            if (hello.SelectedVersion != Tls13Messages.Tls13Version) return RefuseVersion(hello);

            Tls13Options o = session.Options;
            Tls13Suite suite = Tls13Suite.Find(hello.Suite);
            if (suite == null) return Tls13Rules.Refuse(Tls13Codes.IllegalParameter, "the server chose suite " + hello.Suite + ", which the client did not offer");
            if (hello.Group != Tls13GroupInfo.Code(o.Group) || hello.KeyShare == null) return Tls13Rules.Refuse(Tls13Codes.IllegalParameter, "the server chose group " + hello.Group + ", which the client did not offer");
            if (hello.SessionId.Length != 0) return Tls13Rules.Refuse(Tls13Codes.IllegalParameter, "the server echoed a session id the client never sent");

            KexOutcome kex = KeyExchange.Finish(o.Group, session.Offer, hello.KeyShare);
            byte[] helloHash = Tls13KeySchedule.HashOf(suite.Hash, new ByteWriter().Put(session.Transcript).Put(message.Bytes).ToArray());
            Tls13Secrets s = Tls13KeySchedule.Derive(suite.Hash, kex.Shared, helloHash, null);

            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(message.Bytes));
            effects.Add(Tls13Rules.Pass(Tls13Codes.DowngradeSentinel));
            effects.Add(Effect.Note("kex.share.computed", Tls13GroupInfo.Name(o.Group) + " shared secret, " + kex.Shared.Length + " bytes"));
            Tls13Rules.AddHandshakeLadder(effects, session, kex, s);
            effects.Add(Tls13Rules.KeepHandshakeSecrets(session, suite, kex.Shared, helloHash, s, session.ClientRandom));
            effects.Add(Tls13Rules.Install(Direction.Inbound, suite, s.ServerHandshakeTrafficSecret, "handshake"));
            effects.Add(Tls13Rules.Install(Direction.Outbound, suite, s.ClientHandshakeTrafficSecret, "handshake"));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision RefuseVersion(ServerHelloInfo hello)
        {
            if (hello.HasDowngradeSentinel) return Tls13Rules.Refuse(Tls13Codes.DowngradeSentinel, "the server random ends in DOWNGRD, so a TLS 1.3 server was pushed to an older version");
            return Tls13Rules.Refuse(Tls13Codes.VersionRefused, "the server chose legacy version " + hello.LegacyVersion + " and no TLS 1.3");
        }

        static StepDecision Absorb(Tls13Session session, InboundMessage message)
        {
            return StepDecision.Advance(Effect.Absorb(message.Bytes));
        }

        static StepDecision CertificateRequest(Tls13Session session, InboundMessage message)
        {
            return StepDecision.Advance(Effect.Absorb(message.Bytes), Effect.Store(delegate { session.ClientCertificateAsked = true; }));
        }

        static StepDecision Certificate(Tls13Session session, InboundMessage message)
        {
            CertificateInfo info = Tls13Messages.ReadCertificate(message.Bytes, false);
            Tls13Options o = session.Options;
            Certificate[] chain = ParseAll(info.Chain);
            ChainVerdict verdict = ChainCheck.Run(chain, ParseAll(o.TrustAnchors), o.ServerName, o.Now);
            if (!verdict.Passed) return Tls13Rules.Refuse(verdict.Code, verdict.Detail);
            Certificate leaf = chain[0];
            return StepDecision.Advance(
                Effect.Absorb(message.Bytes),
                Effect.Store(delegate { session.Leaf = leaf; }),
                Tls13Rules.Pass(ChainCheck.NoAnchor),
                Tls13Rules.Pass(ChainCheck.BadSignature),
                Tls13Rules.Pass(ChainCheck.Validity),
                Tls13Rules.Pass(ChainCheck.Name));
        }

        static Certificate[] ParseAll(byte[][] ders)
        {
            Certificate[] parsed = new Certificate[ders.Length];
            for (int i = 0; i < ders.Length; i++) parsed[i] = NetSec.Pki.Certificate.Parse(ders[i]);
            return parsed;
        }

        static StepDecision CertificateVerify(Tls13Session session, InboundMessage message)
        {
            CertificateVerifyInfo info = Tls13Messages.ReadCertificateVerify(message.Bytes, false);
            byte[] signed = Tls13Messages.SignedContent(Tls13Messages.ServerVerifyContext, session.HashWith());
            bool good = info.Scheme == Tls13Messages.Ed25519Scheme && session.Leaf.KeyIsEd25519 && info.Signature.Length == 64
                && Ed25519.Verify(session.Leaf.PublicKey, signed, info.Signature);
            if (!good) return Tls13Rules.Refuse(Tls13Codes.CertVerifyBad, "the signature over the transcript does not verify under the leaf key");
            return StepDecision.Advance(Effect.Absorb(message.Bytes), Tls13Rules.Pass(Tls13Codes.CertVerifyBad));
        }

        static StepDecision Finished(Tls13Session session, InboundMessage message)
        {
            Tls13Suite suite = session.Suite;
            byte[] expected = Tls13KeySchedule.VerifyData(suite.Hash, session.Secrets.ServerHandshakeTrafficSecret, session.HashWith());
            if (message.Body.Length != expected.Length || !ConstantTime.Equal(message.Body, 0, expected, 0, expected.Length))
                return Tls13Rules.Refuse(Tls13Codes.FinishedMismatch, "the server Finished does not match this transcript");

            byte[] serverFinishedHash = session.HashWith(message.Bytes);
            Tls13Secrets s = Tls13KeySchedule.Derive(suite.Hash, session.Shared, session.HelloHash, serverFinishedHash);
            byte[] emptyCertificate = session.ClientCertificateAsked ? Tls13Messages.CertificateMessage(new byte[0][]) : new byte[0];
            byte[] clientVerify = Tls13KeySchedule.VerifyData(suite.Hash, s.ClientHandshakeTrafficSecret, session.HashWith(message.Bytes, emptyCertificate));
            byte[] finished = Tls13Messages.Finished(clientVerify);

            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(message.Bytes));
            effects.Add(Tls13Rules.Pass(Tls13Codes.FinishedMismatch));
            Tls13Rules.AddApplicationLadder(effects, session, s);
            effects.Add(Tls13Rules.KeepApplicationSecrets(session, s, session.ClientRandom));
            if (session.ClientCertificateAsked)
            {
                effects.Add(Effect.Send("Certificate", emptyCertificate, Tls13Messages.FieldsOf(HandshakeType.Certificate, emptyCertificate, false)));
                effects.Add(Effect.Absorb(emptyCertificate));
            }
            effects.Add(Effect.Send("Finished", finished, Tls13Messages.FieldsOf(HandshakeType.Finished, finished, false)));
            effects.Add(Effect.Absorb(finished));
            effects.Add(Tls13Rules.Install(Direction.Inbound, suite, s.ServerApplicationTrafficSecret0, "application"));
            effects.Add(Tls13Rules.Install(Direction.Outbound, suite, s.ClientApplicationTrafficSecret0, "application"));
            return StepDecision.Advance(effects.ToArray());
        }
    }
}
