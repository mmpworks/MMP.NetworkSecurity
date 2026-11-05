using System;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 3. Three rounds of agreeing on a secret in public: X25519, ML-KEM, and the hybrid of both. After each round the client
    /// proves it holds the secret, and the server checks. ML-KEM gives no error on a bad ciphertext, so only that check catches it.
    /// Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson03Kex : ILab
    {
        public const string ConfirmCheck = "key confirmation MAC";

        const int X25519Size = 32;
        const int MlKemSeedSize = 32;
        const int EkSize = 1184;
        const int CiphertextSize = 1088;
        const string Start0 = "Start";
        const string X25519Private = "x25519.private";
        const string MlKemDk = "mlkem.dk";
        const string X25519Shared = "x25519.shared";
        const string MlKemShared = "mlkem.shared";
        const string HybridShared = "hybrid.shared";

        const int XClient = 1, XServer = 2, XConfirm = 3, MEncaps = 4, MCipher = 5, MConfirm = 6, HClient = 7, HServer = 8, HConfirm = 9, KexDone = 10;

        static readonly string[] Names =
        {
            "", "X25519ClientShare", "X25519ServerShare", "X25519Confirm", "MlKemEncapsKey", "MlKemCiphertext", "MlKemConfirm",
            "HybridClientShare", "HybridServerShare", "HybridConfirm", "KexDone",
        };

        static readonly byte[] ConfirmLabel = Encoding.UTF8.GetBytes("client holds the secret");

        /// <summary>A whole frame an attacker puts in place of the server's share. Its scalar is public on purpose: this is a lesson.</summary>
        public static byte[] SwappedServerShare()
        {
            byte[] scalar = new byte[X25519Size];
            for (int i = 0; i < scalar.Length; i++) scalar[i] = 0x66;
            return Frame.Build(XServer, X25519.MultBase(scalar));
        }

        sealed class Session : FrameSession
        {
            public Session(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "kex"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }
        }

        public string LabId { get { return "lab-03-kex"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            ITamperHook plan = LabPair.Plan(c);
            FrameEngine<Session> client = new FrameEngine<Session>(ClientTable, new Session(LabPair.Fork(c)), Start0, LabPair.Stream(c, "client", "kex"), "server", plan);
            FrameEngine<Session> server = new FrameEngine<Session>(ServerTable, new Session(LabPair.Fork(c)), Start0, LabPair.Stream(c, "server", "kex"), "client", plan);
            return LabPair.Run(c, client, server, plan);
        }

        static readonly StepTable<Session> ClientTable = new StepTable<Session>(
            new StepRow<Session>("kex.c.x25519-share", Start0, InboundMessage.StartType, ClientX25519Share, "WaitX25519Server"),
            new StepRow<Session>("kex.c.x25519-secret", "WaitX25519Server", XServer, ClientX25519Secret, "WaitMlKemCipher"),
            new StepRow<Session>("kex.c.mlkem-secret", "WaitMlKemCipher", MCipher, ClientMlKemSecret, "WaitHybridServer"),
            new StepRow<Session>("kex.c.hybrid-secret", "WaitHybridServer", HServer, ClientHybridSecret, "WaitDone"),
            new StepRow<Session>("kex.c.done", "WaitDone", KexDone, ClientDone, MachineStates.Closed));

        static readonly StepTable<Session> ServerTable = new StepTable<Session>(
            new StepRow<Session>("kex.s.start", Start0, InboundMessage.StartType, ServerStart, "WaitX25519Client"),
            new StepRow<Session>("kex.s.x25519-share", "WaitX25519Client", XClient, ServerX25519Share, "WaitX25519Confirm"),
            new StepRow<Session>("kex.s.x25519-confirm", "WaitX25519Confirm", XConfirm, ServerX25519Confirm, "WaitMlKemEncaps"),
            new StepRow<Session>("kex.s.mlkem-encaps", "WaitMlKemEncaps", MEncaps, ServerMlKemEncaps, "WaitMlKemConfirm"),
            new StepRow<Session>("kex.s.mlkem-confirm", "WaitMlKemConfirm", MConfirm, ServerMlKemConfirm, "WaitHybridClient"),
            new StepRow<Session>("kex.s.hybrid-share", "WaitHybridClient", HClient, ServerHybridShare, "WaitHybridConfirm"),
            new StepRow<Session>("kex.s.hybrid-confirm", "WaitHybridConfirm", HConfirm, ServerHybridConfirm, MachineStates.Closed));

        // ---------------------------------------------------------------- client

        static StepDecision ClientX25519Share(Session s, InboundMessage m)
        {
            byte[] scalar = s.Draw(X25519Size);
            return StepDecision.Advance(
                Effect.SecretAs("kex.share.computed", Names[XClient], "client", X25519Private, scalar),
                Send(XClient, X25519.MultBase(scalar), new FieldSpan("x25519Share", "key", -1, 0, true)));
        }

        static StepDecision ClientX25519Secret(Session s, InboundMessage m)
        {
            byte[] shared = X25519.Mult(s.Secret(X25519Private), m.Body);
            MlKemPair pair = MlKem768.KeyGen(s.Draw(MlKemSeedSize), s.Draw(MlKemSeedSize));
            return StepDecision.Advance(
                Effect.SecretAs("kex.secret.computed", X25519Shared, "client", X25519Shared, shared, X25519Private, Names[XServer]),
                Confirm(XConfirm, shared),
                Effect.SecretAs("kex.share.computed", Names[MEncaps], "client", MlKemDk, pair.DecapsulationKey),
                Send(MEncaps, pair.EncapsulationKey, new FieldSpan("mlkemEncapsKey", "key", -1, 0, true)));
        }

        static StepDecision ClientMlKemSecret(Session s, InboundMessage m)
        {
            byte[] shared = MlKem768.Decaps(s.Secret(MlKemDk), m.Body);
            MlKemPair pair = MlKem768.KeyGen(s.Draw(MlKemSeedSize), s.Draw(MlKemSeedSize));
            byte[] scalar = s.Draw(X25519Size);
            byte[] share = new ByteWriter().Put(pair.EncapsulationKey).Put(X25519.MultBase(scalar)).ToArray();
            return StepDecision.Advance(
                Effect.SecretAs("kex.secret.computed", MlKemShared, "client", MlKemShared, shared, MlKemDk, Names[MCipher]),
                Confirm(MConfirm, shared),
                Effect.SecretAs("kex.share.computed", Names[HClient], "client", MlKemDk, pair.DecapsulationKey),
                Effect.SecretAs("kex.share.computed", Names[HClient], "client", X25519Private, scalar),
                Send(HClient, share, new FieldSpan("mlkemEncapsKey", "key", EkSize, 0, true), new FieldSpan("x25519Share", "key", -1, 0, true)));
        }

        static StepDecision ClientHybridSecret(Session s, InboundMessage m)
        {
            byte[] mlkem = MlKem768.Decaps(s.Secret(MlKemDk), Slice(m.Body, 0, CiphertextSize));
            byte[] x = X25519.Mult(s.Secret(X25519Private), Slice(m.Body, CiphertextSize, X25519Size));
            byte[] shared = new ByteWriter().Put(mlkem).Put(x).ToArray();
            return StepDecision.Advance(
                Effect.SecretAs("kex.secret.computed", HybridShared, "client", HybridShared, shared, MlKemDk, X25519Private, Names[HServer]),
                Confirm(HConfirm, shared));
        }

        static StepDecision ClientDone(Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        // ---------------------------------------------------------------- server

        static StepDecision ServerStart(Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        static StepDecision ServerX25519Share(Session s, InboundMessage m)
        {
            byte[] scalar = s.Draw(X25519Size);
            byte[] shared = X25519.Mult(scalar, m.Body);
            return StepDecision.Advance(
                Effect.SecretAs("kex.share.computed", Names[XServer], "server", X25519Private, scalar),
                Send(XServer, X25519.MultBase(scalar), new FieldSpan("x25519Share", "key", -1, 0, true)),
                Effect.SecretAs("kex.secret.computed", X25519Shared, "server", X25519Shared, shared, X25519Private, Names[XClient]));
        }

        static StepDecision ServerX25519Confirm(Session s, InboundMessage m)
        {
            return CheckConfirm(s, m, X25519Shared);
        }

        static StepDecision ServerMlKemEncaps(Session s, InboundMessage m)
        {
            MlKemSealed sealedKey = MlKem768.Encaps(m.Body, s.Draw(MlKemSeedSize));
            return StepDecision.Advance(
                Send(MCipher, sealedKey.Ciphertext, new FieldSpan("mlkemCiphertext", "key", -1, 0, true)),
                Effect.SecretAs("kex.secret.computed", MlKemShared, "server", MlKemShared, sealedKey.SharedSecret, Names[MEncaps]));
        }

        static StepDecision ServerMlKemConfirm(Session s, InboundMessage m)
        {
            return CheckConfirm(s, m, MlKemShared);
        }

        static StepDecision ServerHybridShare(Session s, InboundMessage m)
        {
            MlKemSealed sealedKey = MlKem768.Encaps(Slice(m.Body, 0, EkSize), s.Draw(MlKemSeedSize));
            byte[] scalar = s.Draw(X25519Size);
            byte[] x = X25519.Mult(scalar, Slice(m.Body, EkSize, X25519Size));
            byte[] share = new ByteWriter().Put(sealedKey.Ciphertext).Put(X25519.MultBase(scalar)).ToArray();
            byte[] shared = new ByteWriter().Put(sealedKey.SharedSecret).Put(x).ToArray();
            return StepDecision.Advance(
                Effect.SecretAs("kex.share.computed", Names[HServer], "server", X25519Private, scalar),
                Send(HServer, share, new FieldSpan("mlkemCiphertext", "key", CiphertextSize, 0, true), new FieldSpan("x25519Share", "key", -1, 0, true)),
                Effect.SecretAs("kex.secret.computed", HybridShared, "server", HybridShared, shared, X25519Private, Names[HClient]));
        }

        static StepDecision ServerHybridConfirm(Session s, InboundMessage m)
        {
            StepDecision checkedConfirm = CheckConfirm(s, m, HybridShared);
            if (checkedConfirm.Outcome == StepOutcome.Fail) return checkedConfirm;
            return StepDecision.Advance(checkedConfirm.Effects[0], Effect.SendProtected(Names[KexDone], new byte[0], Frame.Build(KexDone, new byte[0]), Frame.Fields(0)));
        }

        static StepDecision CheckConfirm(Session s, InboundMessage m, string secretName)
        {
            byte[] expected = Hmac.Compute(Hashes.Sha256, s.Secret(secretName), ConfirmLabel);
            bool same = expected.Length == m.Body.Length;
            for (int i = 0; same && i < expected.Length; i++) same = expected[i] == m.Body[i];
            if (!same) return StepDecision.Fail(ErrorCodes.KexConfirmMismatch, ConfirmCheck, m.Name + ": the two sides hold different secrets");
            return StepDecision.Advance(Effect.Check(ConfirmCheck, ErrorCodes.KexConfirmMismatch));
        }

        // ---------------------------------------------------------------- shared

        static StepEffect Confirm(int type, byte[] shared)
        {
            return Send(type, Hmac.Compute(Hashes.Sha256, shared, ConfirmLabel), new FieldSpan("confirmMac", "mac", -1, 0, true));
        }

        static StepEffect Send(int type, byte[] body, params FieldSpan[] spans)
        {
            return Effect.SendProtected(Names[type], body, Frame.Build(type, body), Frame.Fields(body.Length, spans));
        }

        static byte[] Slice(byte[] bytes, int offset, int count)
        {
            if (offset + count > bytes.Length)
                throw new ParseFailure(ErrorCodes.ParseTruncated, "the share holds " + bytes.Length + " bytes, and the layout needs " + (offset + count));
            byte[] part = new byte[count];
            Buffer.BlockCopy(bytes, offset, part, 0, count);
            return part;
        }
    }
}
