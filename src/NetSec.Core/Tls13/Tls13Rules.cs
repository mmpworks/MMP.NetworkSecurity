using System.Collections.Generic;
using NetSec.Crypto;
using NetSec.Machine;

namespace NetSec.Tls13
{
    /// <summary>The steps both roles share. Each returns effects for the interpreter and changes nothing itself.</summary>
    static class Tls13Rules
    {
        public static StepDecision Refuse(string code, string detail)
        {
            return StepDecision.Fail(code, Tls13Codes.CheckName(code), detail);
        }

        public static StepEffect Pass(string code)
        {
            return Effect.Check(Tls13Codes.CheckName(code), code);
        }

        public static void AddHandshakeLadder(List<StepEffect> effects, Tls13Session session, KexOutcome kex, Tls13Secrets s)
        {
            string holder = session.Holder;
            if (kex.MlKemPart != null) effects.Add(Effect.Secret(holder, "mlkem_shared", kex.MlKemPart, "mlkem_ciphertext"));
            effects.Add(Effect.Secret(holder, "x25519_shared", kex.X25519Part, "x25519_private", "x25519_peer_public"));
            if (kex.MlKemPart != null) effects.Add(Effect.Secret(holder, "hybrid_shared", kex.Shared, "mlkem_shared", "x25519_shared"));
            string sharedName = kex.MlKemPart != null ? "hybrid_shared" : "x25519_shared";
            effects.Add(Effect.Secret(holder, "early_secret", s.EarlySecret));
            effects.Add(Effect.Secret(holder, "handshake_secret", s.HandshakeSecret, "early_secret", sharedName));
            effects.Add(Effect.Secret(holder, "c_hs_traffic", s.ClientHandshakeTrafficSecret, "handshake_secret", "transcript_through_server_hello"));
            effects.Add(Effect.Secret(holder, "s_hs_traffic", s.ServerHandshakeTrafficSecret, "handshake_secret", "transcript_through_server_hello"));
            effects.Add(Effect.Secret(holder, "master_secret", s.MasterSecret, "handshake_secret"));
        }

        public static void AddApplicationLadder(List<StepEffect> effects, Tls13Session session, Tls13Secrets s)
        {
            string holder = session.Holder;
            effects.Add(Effect.Secret(holder, "c_ap_traffic", s.ClientApplicationTrafficSecret0, "master_secret", "transcript_through_server_finished"));
            effects.Add(Effect.Secret(holder, "s_ap_traffic", s.ServerApplicationTrafficSecret0, "master_secret", "transcript_through_server_finished"));
            effects.Add(Effect.Secret(holder, "exp_master", s.ExporterMasterSecret, "master_secret", "transcript_through_server_finished"));
        }

        public static StepEffect Install(Direction direction, Tls13Suite suite, byte[] trafficSecret, string stage)
        {
            string label = suite.Name + " " + stage + " " + (direction == Direction.Inbound ? "read" : "write");
            return Effect.InstallKeys(direction, label, Tls13KeySchedule.TrafficKey(suite.Hash, trafficSecret, suite.KeyLength), Tls13KeySchedule.TrafficIv(suite.Hash, trafficSecret));
        }

        /// <summary>Keeps the secrets, and writes the four NSS lines that the referees also write, plus the exporter line OpenSSL adds.</summary>
        public static StepEffect KeepHandshakeSecrets(Tls13Session session, Tls13Suite suite, byte[] shared, byte[] helloHash, Tls13Secrets s, byte[] clientRandom)
        {
            return Effect.Store(delegate
            {
                session.Suite = suite;
                session.Shared = shared;
                session.HelloHash = helloHash;
                session.Secrets = s;
                session.ClientRandom = clientRandom;
                session.KeyLogLines.Add(KeyLog.Line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", clientRandom, s.ClientHandshakeTrafficSecret));
                session.KeyLogLines.Add(KeyLog.Line("SERVER_HANDSHAKE_TRAFFIC_SECRET", clientRandom, s.ServerHandshakeTrafficSecret));
            });
        }

        public static StepEffect KeepApplicationSecrets(Tls13Session session, Tls13Secrets s, byte[] clientRandom)
        {
            return Effect.Store(delegate
            {
                session.Secrets = s;
                session.KeyLogLines.Add(KeyLog.Line("CLIENT_TRAFFIC_SECRET_0", clientRandom, s.ClientApplicationTrafficSecret0));
                session.KeyLogLines.Add(KeyLog.Line("SERVER_TRAFFIC_SECRET_0", clientRandom, s.ServerApplicationTrafficSecret0));
                session.KeyLogLines.Add(KeyLog.Line("EXPORTER_SECRET", clientRandom, s.ExporterMasterSecret));
            });
        }

        /// <summary>One side's CertificateVerify under the leaf it has already checked. The context string differs by role.</summary>
        public static StepDecision CheckCertificateVerify(Tls13Session session, InboundMessage message, string context)
        {
            CertificateVerifyInfo info = Tls13Messages.ReadCertificateVerify(message.Bytes, false);
            byte[] signed = Tls13Messages.SignedContent(context, session.HashWith());
            bool good = info.Scheme == Tls13Messages.Ed25519Scheme && session.Leaf.KeyIsEd25519 && info.Signature.Length == 64
                && Ed25519.Verify(session.Leaf.PublicKey, signed, info.Signature);
            if (!good) return Refuse(Tls13Codes.CertVerifyBad, "the signature over the transcript does not verify under the leaf key");
            return StepDecision.Advance(Effect.Absorb(message.Bytes), Pass(Tls13Codes.CertVerifyBad));
        }

        public static StepDecision OpenData(Tls13Session session, InboundMessage message)
        {
            return StepDecision.Stay(Effect.Deliver(0, message.Body));
        }

        public static StepDecision OpenTicket(Tls13Session session, InboundMessage message)
        {
            return StepDecision.Stay(Effect.Note("tls.ticket.ignored", "this engine does not resume, so it reads the ticket and drops it"));
        }

        public static StepDecision OpenKeyUpdate(Tls13Session session, InboundMessage message)
        {
            return Refuse(Tls13Codes.KeyUpdateUnsupported, "the peer asked for a key update, and this engine does not build one");
        }
    }
}
