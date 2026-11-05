using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Pki;

namespace NetSec.Tls11
{
    /// <summary>
    /// The state tables of docs/program-design.md section 2.6. Each rule reads the session and returns a decision. It runs no side effect except Draw.
    /// RFC 8996 retires TLS 1.1. This engine exists to show the old device's world. Built to show the parts. Do not copy.
    /// </summary>
    public static class Tls11Rules
    {
        public const string StartState = "Start";
        const string WaitServerHello = "WaitServerHello", WaitCert = "WaitCert", WaitSkeOrDone = "WaitSkeOrDone", WaitDone = "WaitDone",
            WaitClientHello = "WaitClientHello", WaitClientKeyExchange = "WaitClientKeyExchange", WaitCcs = "WaitCcs", WaitFinished = "WaitFinished";

        const int PremasterSize = 48;
        const int X25519Size = 32;

        public static readonly StepTable<Tls11Session> Client = new StepTable<Tls11Session>(Join(
            new StepRow<Tls11Session>[]
            {
                new StepRow<Tls11Session>("tls11.c.hello", StartState, InboundMessage.StartType, ClientStart, WaitServerHello),
                new StepRow<Tls11Session>("tls11.c.sh", WaitServerHello, Tls11Messages.ServerHello, ClientServerHello, WaitCert),
                new StepRow<Tls11Session>("tls11.c.cert", WaitCert, Tls11Messages.Certificate, ClientCertificate, WaitSkeOrDone),
                new StepRow<Tls11Session>("tls11.c.ske", WaitSkeOrDone, Tls11Messages.ServerKeyExchange, ClientServerKeyExchange, WaitDone),
                new StepRow<Tls11Session>("tls11.c.done", WaitSkeOrDone, Tls11Messages.ServerHelloDone, ClientDone, WaitCcs),
                new StepRow<Tls11Session>("tls11.c.done", WaitDone, Tls11Messages.ServerHelloDone, ClientDone, WaitCcs),
                new StepRow<Tls11Session>("tls11.c.ccs", WaitCcs, Tls11Messages.ChangeCipherSpecKey, ClientCcs, WaitFinished),
                new StepRow<Tls11Session>("tls11.c.fin", WaitFinished, Tls11Messages.Finished, ClientFinished, MachineStates.Open),
                new StepRow<Tls11Session>("tls11.c.data", MachineStates.Open, Tls11Messages.ApplicationDataKey, OnData, MachineStates.Open),
            },
            AlertRows("tls11.c.alert", WaitServerHello, WaitCert, WaitSkeOrDone, WaitDone, WaitCcs, WaitFinished)));

        public static readonly StepTable<Tls11Session> Server = new StepTable<Tls11Session>(Join(
            new StepRow<Tls11Session>[]
            {
                new StepRow<Tls11Session>("tls11.s.start", StartState, InboundMessage.StartType, ServerStart, WaitClientHello),
                new StepRow<Tls11Session>("tls11.s.ch", WaitClientHello, Tls11Messages.ClientHello, ServerClientHello, WaitClientKeyExchange),
                new StepRow<Tls11Session>("tls11.s.cke", WaitClientKeyExchange, Tls11Messages.ClientKeyExchange, ServerClientKeyExchange, WaitCcs),
                new StepRow<Tls11Session>("tls11.s.ccs", WaitCcs, Tls11Messages.ChangeCipherSpecKey, ServerCcs, WaitFinished),
                new StepRow<Tls11Session>("tls11.s.fin", WaitFinished, Tls11Messages.Finished, ServerFinished, MachineStates.Open),
                new StepRow<Tls11Session>("tls11.s.data", MachineStates.Open, Tls11Messages.ApplicationDataKey, OnData, MachineStates.Open),
            },
            AlertRows("tls11.s.alert", WaitClientHello, WaitClientKeyExchange, WaitCcs, WaitFinished)));

        /// <summary>An alert can arrive in any state, so each state gets one row. A clean close reaches Closed. A warning stays through Stay.</summary>
        static StepRow<Tls11Session>[] AlertRows(string step, params string[] handshakeStates)
        {
            List<StepRow<Tls11Session>> rows = new List<StepRow<Tls11Session>>();
            for (int i = 0; i < handshakeStates.Length; i++)
                rows.Add(new StepRow<Tls11Session>(step, handshakeStates[i], Tls11Messages.AlertKey, OnHandshakeAlert, MachineStates.Closed));
            rows.Add(new StepRow<Tls11Session>(step, MachineStates.Open, Tls11Messages.AlertKey, OnOpenAlert, MachineStates.Closed));
            return rows.ToArray();
        }

        static StepRow<Tls11Session>[] Join(StepRow<Tls11Session>[] first, StepRow<Tls11Session>[] second)
        {
            StepRow<Tls11Session>[] all = new StepRow<Tls11Session>[first.Length + second.Length];
            first.CopyTo(all, 0);
            second.CopyTo(all, first.Length);
            return all;
        }

        // ---------------------------------------------------------------- both roles

        /// <summary>A close before the handshake ends is a failure, because the peer gave no protected channel.</summary>
        static StepDecision OnHandshakeAlert(Tls11Session s, InboundMessage m)
        {
            if (m.Body[1] == Tls11Messages.CloseNotify)
                return StepDecision.Fail(ErrorCodes.PeerClosedEarly, "peer stayed until the end", "the peer sent close_notify during the handshake");
            return OnFaultAlert(m);
        }

        /// <summary>A real stack answers close_notify with its own. This engine closes the link instead, because the peer may already be gone.</summary>
        static StepDecision OnOpenAlert(Tls11Session s, InboundMessage m)
        {
            if (m.Body[1] == Tls11Messages.CloseNotify) return StepDecision.Advance(Effect.Note("tls11.alert", "close_notify"));
            return OnFaultAlert(m);
        }

        static StepDecision OnFaultAlert(InboundMessage m)
        {
            int level = m.Body[0], description = m.Body[1];
            if (description == Tls11Messages.ProtocolVersionAlert)
                return StepDecision.Fail(Tls11Codes.AlertProtocolVersion, Tls11Checks.ProtocolVersionAlert, "the server refused TLS 1.1 with alert 70");
            if (level == Tls11Messages.FatalLevel)
                return StepDecision.Fail(Tls11Codes.Alert, Tls11Checks.PeerAlert, "the peer sent fatal alert " + description);
            return StepDecision.Stay(Effect.Note("tls11.alert", description.ToString()));
        }

        static StepDecision OnData(Tls11Session s, InboundMessage m)
        {
            // An empty chunk means a clean close to a channel reader, so an empty record delivers nothing.
            if (m.Body.Length == 0) return StepDecision.Stay(Effect.Check(Tls11Checks.RecordHmac, Tls11Codes.RecordMac));
            return StepDecision.Stay(Effect.Check(Tls11Checks.RecordHmac, Tls11Codes.RecordMac), Effect.Deliver(0, m.Body));
        }

        /// <summary>Compares in one pass with no early exit. The managed runtime gives no timing guarantee.</summary>
        static bool SameFinished(byte[] expected, byte[] received)
        {
            return expected.Length == received.Length && ConstantTime.Equal(expected, 0, received, 0, expected.Length);
        }

        /// <summary>RFC 4346 section 7.1: the body is one byte of value 1. Nothing else binds this byte, because the record is not in the transcript.</summary>
        static StepDecision RefuseCcsBody(InboundMessage m)
        {
            if (m.Body.Length == 1 && m.Body[0] == 1) return null;
            return StepDecision.Fail(Tls11Codes.CcsBody, Tls11Checks.MessageShape, "a ChangeCipherSpec body is not the one byte of value 1");
        }

        static StepEffect[] KeyEffects(string holder, byte[] premaster, byte[] master, Tls11KeyBlock keys)
        {
            return new StepEffect[]
            {
                Effect.Secret(holder, Tls11Session.Premaster, premaster),
                Effect.Secret(holder, Tls11Session.Master, master, Tls11Session.Premaster, "clientRandom", "serverRandom"),
                Effect.Secret(holder, Tls11Session.ClientWriteMac, keys.ClientMac, Tls11Session.Master),
                Effect.Secret(holder, Tls11Session.ServerWriteMac, keys.ServerMac, Tls11Session.Master),
                Effect.Secret(holder, Tls11Session.ClientWriteKey, keys.ClientKey, Tls11Session.Master),
                Effect.Secret(holder, Tls11Session.ServerWriteKey, keys.ServerKey, Tls11Session.Master),
            };
        }

        static StepEffect SendCcs()
        {
            byte[] ccs = Tls11Messages.BuildChangeCipherSpec();
            return Effect.Send(Tls11Messages.ChangeCipherSpecName, ccs, Tls11Messages.ClearFields(Tls11Messages.ChangeCipherSpecKey, ccs, null));
        }

        static StepEffect SendFinished(byte[] finished)
        {
            return Effect.Send(Tls11Messages.FinishedName, finished, Tls11Messages.ProtectedFields(finished.Length));
        }

        static StepEffect SendClear(int key, byte[] message, Tls11CipherSuite suite)
        {
            return Effect.Send(Tls11Messages.NameOf(key), message, Tls11Messages.ClearFields(key, message, suite));
        }

        static StepEffect InstallFromSecrets(Tls11Session s, Direction direction, string keyName, string macName)
        {
            return Effect.InstallKeys(direction, s.Options.Suite.Name, s.Secret(keyName), s.Secret(macName));
        }

        // ---------------------------------------------------------------- client

        static StepDecision ClientStart(Tls11Session s, InboundMessage m)
        {
            byte[] hello = Tls11Messages.BuildClientHello(s.Draw(Tls11Messages.RandomSize), s.Options.Suite);
            return StepDecision.Advance(SendClear(Tls11Messages.ClientHello, hello, s.Options.Suite), Effect.Absorb(hello));
        }

        /// <summary>A TLS 1.1 client never reads the last bytes of the server random. Only a client that speaks TLS 1.3 can use the downgrade sentinel.</summary>
        static StepDecision ClientServerHello(Tls11Session s, InboundMessage m)
        {
            Tls11Hello hello = Tls11Messages.ReadServerHello(new ByteReader(m.Bytes, 0, m.Bytes.Length, true));
            if (hello.Version != Tls11Messages.Version)
                return StepDecision.Fail(Tls11Codes.VersionRefused, Tls11Checks.VersionOffered, "the client offered TLS 1.1 and the server answered with version " + hello.Version);
            if (hello.Suites[0] != s.Options.Suite.Code)
                return StepDecision.Fail(Tls11Codes.SuiteRefused, Tls11Checks.SuiteOffered, "the server chose suite " + hello.Suites[0] + ", and the client did not offer it");
            if (hello.Compression[0] != 0)
                return StepDecision.Fail(Tls11Codes.CompressionRefused, Tls11Checks.CompressionOffered, "the server chose compression " + hello.Compression[0] + ", and the client offered only null");
            return StepDecision.Advance(Effect.Absorb(m.Bytes));
        }

        static StepDecision ClientCertificate(Tls11Session s, InboundMessage m)
        {
            byte[][] ders = Tls11Messages.ReadCertificates(new ByteReader(m.Bytes, 0, m.Bytes.Length, true));
            Certificate[] chain = new Certificate[ders.Length];
            for (int i = 0; i < ders.Length; i++) chain[i] = Certificate.Parse(ders[i]);
            ChainVerdict verdict = ChainCheck.Run(chain, s.Options.Anchors, s.Options.PeerName, s.Options.Now);
            if (!verdict.Passed) return StepDecision.Fail(verdict.Code, Tls11Checks.CertificateChain, verdict.Detail);

            string problem = chain[0].KeyIsEd25519 ? "the leaf key is Ed25519, and these suites need RSA" : null;
            if (problem == null) Tls11RsaKeys.TryReadPublic(chain[0].PublicKey, out problem);
            if (problem != null) return StepDecision.Fail(Tls11Codes.ServerKeyUnusable, Tls11Checks.ServerKeyShape, problem);
            return StepDecision.Advance(Effect.Absorb(m.Bytes), Effect.Check(Tls11Checks.CertificateChain, ChainCheck.NoAnchor));
        }

        static RsaPublic ServerPublic(Tls11Session s)
        {
            byte[][] ders = Tls11Messages.ReadCertificates(s.ReaderOf(Tls11Messages.Certificate));
            string problem;
            return Tls11RsaKeys.TryReadPublic(Certificate.Parse(ders[0]).PublicKey, out problem);
        }

        /// <summary>The server signs the randoms and its key share with MD5 and SHA-1 under RSA (RFC 4346 section 7.4.3, RFC 8422).</summary>
        static StepDecision ClientServerKeyExchange(Tls11Session s, InboundMessage m)
        {
            if (s.Options.Suite.KeyExchange != Tls11KeyExchange.Ecdhe)
                return StepDecision.Fail(ErrorCodes.UnexpectedMessage, "message allowed in this state", "an RSA key transport suite has no ServerKeyExchange");
            Tls11ServerKeyExchange ske = Tls11Messages.ReadServerKeyExchange(new ByteReader(m.Bytes, 0, m.Bytes.Length, true));
            if (ske.Curve != Tls11Messages.X25519Curve || ske.PublicKey.Length != X25519Size)
                return StepDecision.Fail(Tls11Codes.SkeSignature, Tls11Checks.SkeSignature, "the server key share is not X25519");
            byte[] signed = new ByteWriter().Put(s.ClientRandom).Put(s.ServerRandom).Put(ske.Params).ToArray();
            if (!Pkcs1.VerifyMd5Sha1(ServerPublic(s), Tls11Prf.Md5Sha1(signed), ske.Signature))
                return StepDecision.Fail(Tls11Codes.SkeSignature, Tls11Checks.SkeSignature, "the signature over the key share does not verify");
            return StepDecision.Advance(Effect.Absorb(m.Bytes), Effect.Check(Tls11Checks.SkeSignature, Tls11Codes.SkeSignature));
        }

        static StepDecision ClientDone(Tls11Session s, InboundMessage m)
        {
            bool ecdhe = s.Options.Suite.KeyExchange == Tls11KeyExchange.Ecdhe;
            if (ecdhe && s.Message(Tls11Messages.ServerKeyExchange) == null)
                return StepDecision.Fail(ErrorCodes.UnexpectedMessage, "message allowed in this state", "an ECDHE suite needs a ServerKeyExchange");
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(m.Bytes));

            byte[] premaster, keyExchange;
            if (ecdhe)
            {
                byte[] scalar = s.Draw(X25519Size);
                Tls11ServerKeyExchange ske = Tls11Messages.ReadServerKeyExchange(s.ReaderOf(Tls11Messages.ServerKeyExchange));
                premaster = X25519.Mult(scalar, ske.PublicKey);
                if (IsAllZero(premaster)) return StepDecision.Fail(Tls11Codes.EcdheZeroShared, Tls11Checks.EcdheShared, "the server share gave an all-zero secret");
                keyExchange = Tls11Messages.BuildEcdheClientKeyExchange(X25519.MultBase(scalar));
                effects.Add(Effect.Secret("client", Tls11Session.EcdhePrivate, scalar));
            }
            else
            {
                premaster = new ByteWriter().U16(Tls11Messages.Version).Put(s.Draw(PremasterSize - 2)).ToArray();
                keyExchange = Tls11Messages.BuildRsaClientKeyExchange(Pkcs1.EncryptV15(ServerPublic(s), new DrawnRandom(s), premaster));
            }

            byte[] clientRandom = s.ClientRandom, serverRandom = s.ServerRandom;
            byte[] master = Tls11Prf.MasterSecret(premaster, clientRandom, serverRandom);
            Tls11KeyBlock keys = Tls11Prf.KeyBlock(master, clientRandom, serverRandom);
            byte[] digest = s.TranscriptDigest(m.Bytes, keyExchange);
            byte[] finished = Tls11Messages.BuildFinished(Tls11Prf.FinishedData(master, Tls11Prf.ClientFinished, digest));

            effects.AddRange(KeyEffects("client", premaster, master, keys));
            effects.Add(SendClear(Tls11Messages.ClientKeyExchange, keyExchange, s.Options.Suite));
            effects.Add(Effect.Absorb(keyExchange));
            effects.Add(SendCcs());
            effects.Add(Effect.InstallKeys(Direction.Outbound, s.Options.Suite.Name, keys.ClientKey, keys.ClientMac));
            effects.Add(SendFinished(finished));
            effects.Add(Effect.Absorb(finished));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision ClientCcs(Tls11Session s, InboundMessage m)
        {
            return RefuseCcsBody(m) ?? StepDecision.Advance(InstallFromSecrets(s, Direction.Inbound, Tls11Session.ServerWriteKey, Tls11Session.ServerWriteMac));
        }

        static StepDecision ClientFinished(Tls11Session s, InboundMessage m)
        {
            byte[] expected = Tls11Prf.FinishedData(s.Secret(Tls11Session.Master), Tls11Prf.ServerFinished, s.TranscriptDigest());
            if (!SameFinished(expected, Tls11Messages.ReadFinished(new ByteReader(m.Bytes, 0, m.Bytes.Length, false))))
                return StepDecision.Fail(Tls11Codes.FinishedMismatch, Tls11Checks.FinishedCompare, "the server Finished does not match this transcript");
            return StepDecision.Advance(
                Effect.Check(Tls11Checks.RecordHmac, Tls11Codes.RecordMac),
                Effect.Absorb(m.Bytes),
                Effect.Check(Tls11Checks.FinishedCompare, Tls11Codes.FinishedMismatch));
        }

        static bool IsAllZero(byte[] bytes)
        {
            int all = 0;
            for (int i = 0; i < bytes.Length; i++) all |= bytes[i];
            return all == 0;
        }

        // ---------------------------------------------------------------- server

        static StepDecision ServerStart(Tls11Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        /// <summary>The ECDHE branch assumes the client can use X25519, because this client offers nothing else. A peer that cannot will fail on the key share.</summary>
        static StepDecision ServerClientHello(Tls11Session s, InboundMessage m)
        {
            Tls11Hello hello = Tls11Messages.ReadClientHello(new ByteReader(m.Bytes, 0, m.Bytes.Length, true));
            if (hello.Version < Tls11Messages.Version)
                return StepDecision.Fail(Tls11Codes.VersionRefused, Tls11Checks.VersionOffered, "the client offered version " + hello.Version + ", below TLS 1.1");
            if (Array.IndexOf(hello.Suites, s.Options.Suite.Code) < 0)
                return StepDecision.Fail(Tls11Codes.SuiteRefused, Tls11Checks.SuiteOffered, "the client did not offer " + s.Options.Suite.Name);
            if (Array.IndexOf(hello.Compression, (byte)0) < 0)
                return StepDecision.Fail(Tls11Codes.CompressionRefused, Tls11Checks.CompressionOffered, "the client did not offer null compression");

            byte[] random = s.Draw(Tls11Messages.RandomSize);
            if (s.Options.WriteDowngradeTail) Tls11Messages.WriteDowngradeTail(random);
            byte[] serverHello = Tls11Messages.BuildServerHello(random, s.Options.Suite, hello.SignalsSecureRenegotiation);
            byte[] certificate = Tls11Messages.BuildCertificate(s.Options.Chain);
            byte[] done = Tls11Messages.BuildServerHelloDone();
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(m.Bytes));
            AddSend(effects, Tls11Messages.ServerHello, serverHello, s);
            AddSend(effects, Tls11Messages.Certificate, certificate, s);
            if (s.Options.Suite.KeyExchange == Tls11KeyExchange.Ecdhe)
            {
                byte[] scalar = s.Draw(X25519Size);
                byte[] parameters = Tls11Messages.X25519Params(X25519.MultBase(scalar));
                byte[] signed = new ByteWriter().Put(hello.Random).Put(random).Put(parameters).ToArray();
                byte[] keyExchange = Tls11Messages.BuildServerKeyExchange(parameters, Pkcs1.SignMd5Sha1(s.Options.ServerKey, Tls11Prf.Md5Sha1(signed)));
                effects.Add(Effect.Secret("server", Tls11Session.EcdhePrivate, scalar));
                AddSend(effects, Tls11Messages.ServerKeyExchange, keyExchange, s);
            }
            AddSend(effects, Tls11Messages.ServerHelloDone, done, s);
            return StepDecision.Advance(effects.ToArray());
        }

        static void AddSend(List<StepEffect> effects, int key, byte[] message, Tls11Session s)
        {
            effects.Add(SendClear(key, message, s.Options.Suite));
            effects.Add(Effect.Absorb(message));
        }

        /// <summary>
        /// On a bad RSA block the server goes on with a random premaster, so the keys differ and the client's sealed Finished fails TLS11_RECORD_MAC. RFC 4346 section 7.4.7.1 asks for this,
        /// because an answer that differs on bad padding gives Bleichenbacher's attack its oracle. The first two bytes must repeat the version the client offered,
        /// which stops a rewrite of that version in the clear hello.
        /// </summary>
        static StepDecision ServerClientKeyExchange(Tls11Session s, InboundMessage m)
        {
            byte[] sent = Tls11Messages.ReadClientKeyExchange(new ByteReader(m.Bytes, 0, m.Bytes.Length, true), s.Options.Suite);
            byte[] premaster;
            if (s.Options.Suite.KeyExchange == Tls11KeyExchange.Ecdhe)
            {
                if (sent.Length != X25519Size) return StepDecision.Fail(Tls11Codes.EcdheZeroShared, Tls11Checks.EcdheShared, "the client share is not X25519");
                premaster = X25519.Mult(s.Secret(Tls11Session.EcdhePrivate), sent);
                if (IsAllZero(premaster)) return StepDecision.Fail(Tls11Codes.EcdheZeroShared, Tls11Checks.EcdheShared, "the client share gave an all-zero secret");
            }
            else
            {
                byte[] filler = s.Draw(PremasterSize);
                byte[] opened;
                bool good = Pkcs1.TryDecryptV15(s.Options.ServerKey, sent, out opened) && opened.Length == PremasterSize;
                premaster = good && ((opened[0] << 8) | opened[1]) == Tls11Messages.ReadClientHello(s.ReaderOf(Tls11Messages.ClientHello)).Version ? opened : filler;
            }
            byte[] clientRandom = s.ClientRandom, serverRandom = s.ServerRandom;
            byte[] master = Tls11Prf.MasterSecret(premaster, clientRandom, serverRandom);
            Tls11KeyBlock keys = Tls11Prf.KeyBlock(master, clientRandom, serverRandom);
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Absorb(m.Bytes));
            effects.AddRange(KeyEffects("server", premaster, master, keys));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision ServerCcs(Tls11Session s, InboundMessage m)
        {
            return RefuseCcsBody(m) ?? StepDecision.Advance(InstallFromSecrets(s, Direction.Inbound, Tls11Session.ClientWriteKey, Tls11Session.ClientWriteMac));
        }

        static StepDecision ServerFinished(Tls11Session s, InboundMessage m)
        {
            byte[] master = s.Secret(Tls11Session.Master);
            byte[] expected = Tls11Prf.FinishedData(master, Tls11Prf.ClientFinished, s.TranscriptDigest());
            if (!SameFinished(expected, Tls11Messages.ReadFinished(new ByteReader(m.Bytes, 0, m.Bytes.Length, false))))
                return StepDecision.Fail(Tls11Codes.FinishedMismatch, Tls11Checks.FinishedCompare, "the client Finished does not match this transcript");
            byte[] finished = Tls11Messages.BuildFinished(Tls11Prf.FinishedData(master, Tls11Prf.ServerFinished, s.TranscriptDigest(m.Bytes)));
            return StepDecision.Advance(
                Effect.Check(Tls11Checks.RecordHmac, Tls11Codes.RecordMac),
                Effect.Absorb(m.Bytes),
                Effect.Check(Tls11Checks.FinishedCompare, Tls11Codes.FinishedMismatch),
                SendCcs(),
                InstallFromSecrets(s, Direction.Outbound, Tls11Session.ServerWriteKey, Tls11Session.ServerWriteMac),
                SendFinished(finished),
                Effect.Absorb(finished));
        }

        /// <summary>Lets Pkcs1 draw its padding from the session's stream, in rule order.</summary>
        sealed class DrawnRandom : IRandomSource
        {
            readonly Tls11Session _session;
            public DrawnRandom(Tls11Session session) { _session = session; }
            public void Fill(byte[] b, int off, int n) { Buffer.BlockCopy(_session.Draw(n), 0, b, off, n); }
        }
    }
}
