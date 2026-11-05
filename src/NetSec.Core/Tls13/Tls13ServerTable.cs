using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;

namespace NetSec.Tls13
{
    /// <summary>The server rows. One rule answers the ClientHello with the whole server flight, and one rule checks the client Finished.</summary>
    static class Tls13ServerTable
    {
        public const string Start = "Start";
        const string WaitClientHello = "WaitClientHello", WaitClientFinished = "WaitClientFinished", Open = MachineStates.Open;

        public static readonly StepTable<Tls13Session> Table = new StepTable<Tls13Session>(
            new StepRow<Tls13Session>("tls13.s.start", Start, InboundMessage.StartType, ServerStart, WaitClientHello),
            new StepRow<Tls13Session>("tls13.s.ch", WaitClientHello, HandshakeType.ClientHello, ClientHello, WaitClientFinished),
            new StepRow<Tls13Session>("tls13.s.fin", WaitClientFinished, HandshakeType.Finished, ClientFinished, Open),
            new StepRow<Tls13Session>("tls13.s.app", Open, HandshakeType.ApplicationData, Tls13Rules.OpenData, Open),
            new StepRow<Tls13Session>("tls13.s.keyupdate", Open, HandshakeType.KeyUpdate, Tls13Rules.OpenKeyUpdate, Open));

        static StepDecision ServerStart(Tls13Session session, InboundMessage message)
        {
            return StepDecision.Advance();
        }

        static StepDecision ClientHello(Tls13Session session, InboundMessage message)
        {
            ClientHelloInfo hello = Tls13Messages.ReadClientHello(message.Bytes);
            StepDecision refusal = Screen(hello, session.Options.Group);
            if (refusal != null) return refusal;

            Tls13Options o = session.Options;
            Tls13Suite suite = PickSuite(hello);
            KexOutcome kex = KeyExchange.Respond(o.Group, hello.KeyShares[Tls13GroupInfo.Code(o.Group)], o.Random);
            byte[] serverHello = Tls13Messages.ServerHello(session.Draw(32), hello.SessionId, suite, o.Group, kex.ServerShare);

            ByteWriter transcript = new ByteWriter().Put(message.Bytes).Put(serverHello);
            byte[] helloHash = Tls13KeySchedule.HashOf(suite.Hash, transcript.ToArray());
            Tls13Secrets s = Tls13KeySchedule.Derive(suite.Hash, kex.Shared, helloHash, null);

            byte[] extensions = Tls13Messages.EncryptedExtensions();
            byte[] certificate = Tls13Messages.CertificateMessage(o.CertificateChain);
            transcript.Put(extensions).Put(certificate);
            byte[] signed = Tls13Messages.SignedContent(Tls13Messages.ServerVerifyContext, Tls13KeySchedule.HashOf(suite.Hash, transcript.ToArray()));
            byte[] verify = Tls13Messages.CertificateVerify(Ed25519.Sign(o.SigningSeed, signed));
            transcript.Put(verify);
            byte[] verifyData = Tls13KeySchedule.VerifyData(suite.Hash, s.ServerHandshakeTrafficSecret, Tls13KeySchedule.HashOf(suite.Hash, transcript.ToArray()));
            byte[] finished = Tls13Messages.Finished(verifyData);
            transcript.Put(finished);
            Tls13Secrets full = Tls13KeySchedule.Derive(suite.Hash, kex.Shared, helloHash, Tls13KeySchedule.HashOf(suite.Hash, transcript.ToArray()));

            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(message.Bytes));
            effects.Add(Effect.Note("kex.share.computed", Tls13GroupInfo.Name(o.Group) + " server share, " + kex.ServerShare.Length + " bytes"));
            effects.Add(Effect.Send("ServerHello", serverHello, Tls13Messages.FieldsOf(HandshakeType.ServerHello, serverHello, true)));
            effects.Add(Effect.Absorb(serverHello));
            Tls13Rules.AddHandshakeLadder(effects, session, kex, s);
            effects.Add(Tls13Rules.KeepHandshakeSecrets(session, suite, kex.Shared, helloHash, s, hello.Random));
            effects.Add(Tls13Rules.Install(Direction.Outbound, suite, s.ServerHandshakeTrafficSecret, "handshake"));
            effects.Add(Tls13Rules.Install(Direction.Inbound, suite, s.ClientHandshakeTrafficSecret, "handshake"));
            AddFlight(effects, "EncryptedExtensions", HandshakeType.EncryptedExtensions, extensions);
            AddFlight(effects, "Certificate", HandshakeType.Certificate, certificate);
            AddFlight(effects, "CertificateVerify", HandshakeType.CertificateVerify, verify);
            AddFlight(effects, "Finished", HandshakeType.Finished, finished);
            Tls13Rules.AddApplicationLadder(effects, session, full);
            effects.Add(Tls13Rules.KeepApplicationSecrets(session, full, hello.Random));
            effects.Add(Tls13Rules.Install(Direction.Outbound, suite, full.ServerApplicationTrafficSecret0, "application"));
            return StepDecision.Advance(effects.ToArray());
        }

        static void AddFlight(List<StepEffect> effects, string name, int type, byte[] message)
        {
            effects.Add(Effect.Send(name, message, Tls13Messages.FieldsOf(type, message, false)));
            effects.Add(Effect.Absorb(message));
        }

        /// <summary>Null when the hello can go ahead. Each refusal names the first thing the two sides do not share.</summary>
        static StepDecision Screen(ClientHelloInfo hello, Tls13Group group)
        {
            int code = Tls13GroupInfo.Code(group);
            if (System.Array.IndexOf(hello.Versions, Tls13Messages.Tls13Version) < 0) return Tls13Rules.Refuse(Tls13Codes.VersionRefused, "the client did not offer TLS 1.3");
            if (PickSuite(hello) == null) return Tls13Rules.Refuse(Tls13Codes.NoCommonSuite, "the client offered no suite this server has");
            if (System.Array.IndexOf(hello.SignatureSchemes, Tls13Messages.Ed25519Scheme) < 0) return Tls13Rules.Refuse(Tls13Codes.NoCommonSignature, "the client did not offer ed25519");
            if (System.Array.IndexOf(hello.Groups, code) < 0) return Tls13Rules.Refuse(Tls13Codes.NoCommonGroup, "the client did not offer group " + Tls13GroupInfo.Name(group));
            if (!hello.KeyShares.ContainsKey(code)) return Tls13Rules.Refuse(Tls13Codes.HrrUnsupported, "the client sent no key share for group " + Tls13GroupInfo.Name(group) + ", and this engine does not ask twice");
            return null;
        }

        static Tls13Suite PickSuite(ClientHelloInfo hello)
        {
            for (int i = 0; i < hello.Suites.Length; i++)
            {
                Tls13Suite suite = Tls13Suite.Find(hello.Suites[i]);
                if (suite != null) return suite;
            }
            return null;
        }

        static StepDecision ClientFinished(Tls13Session session, InboundMessage message)
        {
            Tls13Suite suite = session.Suite;
            if (!Tls13KeySchedule.VerifyFinished(suite.Hash, session.Secrets.ClientHandshakeTrafficSecret, session.HashWith(), message.Body))
                return Tls13Rules.Refuse(Tls13Codes.FinishedMismatch, "the client Finished does not match this transcript");
            return StepDecision.Advance(
                Effect.Absorb(message.Bytes),
                Tls13Rules.Pass(Tls13Codes.FinishedMismatch),
                Tls13Rules.Install(Direction.Inbound, suite, session.Secrets.ClientApplicationTrafficSecret0, "application"));
        }
    }
}
