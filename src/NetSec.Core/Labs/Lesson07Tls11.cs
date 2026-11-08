using System;
using System.Collections.Generic;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Tls11;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 7. The old world beside the new: a TLS 1.1 pair and a TLS 1.3 pair start together. RFC 8996 retires TLS 1.1, and this lab exists to show what an old device has.
    /// The TLS 1.1 pair forces RSA key transport, because a default run picks the best case. What is weak here: an attacker can record the run and read it after a key theft,
    /// and CBC with MAC-then-encrypt leaves padding oracles. Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson07Tls11 : ILab
    {
        public const string ApplicationData = Tls11Messages.ApplicationDataName;
        public const string OptionScenario = "scenario";
        public const string ScenarioDowngrade = "downgrade", ScenarioModernServer = "modern-server", ScenarioDecryptRecording = "decrypt-recording";

        /// <summary>The check the decrypt-a-recording run ends on: ECDHE keeps a recorded session closed after the server key is stolen.</summary>
        public const string ForwardSecrecyCheck = "forward secrecy";

        /// <summary>Where the first cipher byte of a protected record sits.</summary>
        public const int CipherOffset = Tls11RecordCipher.HeaderSize + Tls11RecordCipher.IvSize;

        static readonly byte[] Greeting = System.Text.Encoding.UTF8.GetBytes("hello from the old world\n");

        /// <summary>A date inside the training certificates. A fixed date keeps a same-seed rerun the same.</summary>
        static readonly DateTime LabDate = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public string LabId { get { return "lab-07-tls11"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            string scenario = LabPair.Option(c, OptionScenario);
            if (scenario == ScenarioDowngrade) return Downgrade(c);
            if (scenario == ScenarioModernServer) return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return ModernServer(c, ret); });
            if (scenario == ScenarioDecryptRecording) return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return DecryptRecording(c, ret); });
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Race(c, ret); });
        }

        /// <summary>
        /// Each pair draws its own random stream before either starts, so a same-seed rerun gives the same bytes. Only the TLS 1.1 pair meets the attack plan.
        /// The first failure stands for the run: a failed 1.3 half would be a fault in the lab, and a flip attack hits the 1.1 half.
        /// </summary>
        static IEnumerable<IFuture> Race(LabContext c, Return<LabResult> ret)
        {
            ITrainingKeySource keys = LabCredentials.Of(c);
            ITamperHook plan = LabPair.Plan(c);
            LabContext modern = new LabContext();
            modern.Seed = c.Seed; modern.SessionId = c.SessionId; modern.TraceId = c.TraceId; modern.Transports = c.Transports; modern.Gate = c.Gate;
            modern.Sink = c.Sink; modern.Clock = c.Clock; modern.DeadlineMs = c.DeadlineMs; modern.Credentials = c.Credentials;
            modern.Random = LabPair.Fork(c);

            Tls11Engine client = Tls11Client(c, keys, plan);
            Tls11Engine server = Tls11Server(c, keys, plan, false);
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, Greeting, null));
            IFuture<LabResult> old = LabPair.Run(c, client, server, plan, Tls13Lab.EchoThenClose);
            IFuture<LabResult> current = Tls13Lab.Lesson5().Run(modern);
            yield return old;
            yield return current;
            ret.Value = old.Result.Completed ? current.Result : old.Result;
        }

        /// <summary>The attacker's rewrite is modelled by a client that offers only TLS 1.1. The server speaks TLS 1.3 too, so it writes DOWNGRD into its random when it agrees.</summary>
        static IFuture<LabResult> Downgrade(LabContext c)
        {
            ITrainingKeySource keys = LabCredentials.Of(c);
            ITamperHook plan = LabPair.Plan(c);
            return LabPair.Run(c, Tls13Lab.Lesson5().Client(c, plan, true), Tls11Server(c, keys, plan, true), plan);
        }

        /// <summary>The modern server names its own refusal. The lesson is what the old client sees: alert 70. So this run reports the client's check.</summary>
        static IEnumerable<IFuture> ModernServer(LabContext c, Return<LabResult> ret)
        {
            ITamperHook plan = LabPair.Plan(c);
            Tls11Engine client = Tls11Client(c, LabCredentials.Of(c), plan);
            IFuture<LabResult> run = LabPair.Run(c, client, Tls13Lab.Lesson5().Server(c, plan), plan);
            yield return run;
            LabResult result = run.Result;
            if (client.AlertReceived == Tls11Messages.ProtocolVersionAlert)
            {
                result.FailedCode = Tls11Codes.AlertProtocolVersion;
                result.FailedCheck = Tls11Checks.ProtocolVersionAlert;
            }
            ret.Value = result;
        }

        /// <summary>
        /// Record now, decrypt later (R8, attack run L7-decrypt-recording). An attacker records an RSA run and an ECDHE run, then steals the
        /// server's RSA key: the same tls11.server key both servers used, the learner's own when one is set. The RSA recording opens, and the
        /// client's line reads back. The ECDHE recording stays closed, so the run ends on the forward secrecy check. The recovered keys go out
        /// as trace secrets, so Show keys OFF hides their bytes; the recovered line goes out as plain text, because it is what the attack shows.
        /// </summary>
        static IEnumerable<IFuture> DecryptRecording(LabContext c, Return<LabResult> ret)
        {
            ITrainingKeySource keys = LabCredentials.Of(c);
            RecordingTap rsaTap = new RecordingTap(LabPair.Plan(c)), ecdheTap = new RecordingTap(LabPair.Plan(c));
            IFuture<LabResult> rsa = RecordedPair(c, keys, Tls11CipherSuite.RsaAes128CbcSha, "tls11", rsaTap);
            yield return rsa;
            if (!rsa.Result.Completed) { ret.Value = rsa.Result; yield break; }
            IFuture<LabResult> ecdhe = RecordedPair(c, keys, Tls11CipherSuite.EcdheRsaAes128CbcSha, "tls11-ecdhe", ecdheTap);
            yield return ecdhe;
            if (!ecdhe.Result.Completed) { ret.Value = ecdhe.Result; yield break; }

            RsaPrivate stolen = Tls11RsaKeys.ReadPrivate(keys.Find(KeyIds.ServerTls11Rsa).CopyMaterial());
            RecordingOpened rsaOpened = Tls11Recording.Open(rsaTap.ClientToServer, rsaTap.ServerToClient, stolen);
            if (!rsaOpened.Opened || !SameBytes(rsaOpened.ClientPlaintext, Greeting))
                throw new NetSecException(NetSecError.Of(Tls11Codes.EngineFault, "the stolen key did not open the recorded RSA run"));
            RecordingOpened ecdheOpened = Tls11Recording.Open(ecdheTap.ClientToServer, ecdheTap.ServerToClient, stolen);

            TraceStream attacker = LabPair.Stream(c, "attacker", "tls11");
            foreach (IFuture step in Emit(c, attacker, Opened(rsaOpened))) yield return step;
            foreach (IFuture step in Emit(c, attacker, StaysClosed(ecdheOpened))) yield return step;
            LabResult result = new LabResult();
            result.Completed = ecdheOpened.Opened;
            if (!ecdheOpened.Opened)
            {
                result.FailedCode = Tls11Codes.NoStoredKey;
                result.FailedCheck = ForwardSecrecyCheck;
            }
            ret.Value = result;
        }

        static IFuture<LabResult> RecordedPair(LabContext c, ITrainingKeySource keys, Tls11CipherSuite suite, string protocol, RecordingTap tap)
        {
            Tls11Options clientOptions = Common(c, "client", tap, suite, protocol);
            Tls11Training.TrustTrainingRoot(clientOptions, keys, LabDate);
            Tls11Engine client = Tls11Engine.CreateClient(clientOptions);
            Tls11Options serverOptions = Common(c, "server", tap, suite, protocol);
            Tls11Training.UseTrainingServerKey(serverOptions, keys);
            Tls11Engine server = Tls11Engine.CreateServer(serverOptions);
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, Greeting, null));
            return LabPair.Run(c, client, server, tap, Tls13Lab.EchoThenClose);
        }

        static TraceEventDraft Opened(RecordingOpened opened)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "attack.recording.opened";
            draft.Message = "The stolen server key decrypts the recorded pre-master, and every key of the RSA run follows";
            draft.Step = "decrypt";
            draft.Detail = opened.Suite;
            draft.Plain = opened.ClientPlaintext;
            draft.Secrets = new TraceSecret[]
            {
                Held("tls11.premaster", opened.Premaster), Held("tls11.master", opened.MasterSecret),
                Held("tls11.client_write_mac", opened.Keys.ClientMac), Held("tls11.client_write_key", opened.Keys.ClientKey),
            };
            return draft;
        }

        static TraceEventDraft StaysClosed(RecordingOpened opened)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "check.result";
            draft.Message = ForwardSecrecyCheck;
            draft.Step = "decrypt";
            draft.Detail = opened.Suite;
            TraceCheck check = new TraceCheck();
            check.Id = ForwardSecrecyCheck;
            check.Name = ForwardSecrecyCheck;
            check.Passed = opened.Opened;
            check.Code = opened.Opened ? null : Tls11Codes.NoStoredKey;
            check.Detail = opened.Opened
                ? "the stolen key opened the ECDHE recording"
                : "the ECDHE pre-master came from two X25519 shares that neither side stored, so the stolen RSA key opens nothing";
            draft.Check = check;
            return draft;
        }

        static TraceSecret Held(string name, byte[] bytes)
        {
            TraceSecret secret = new TraceSecret();
            secret.Holder = "attacker";
            secret.Name = name;
            secret.Bytes = bytes;
            return secret;
        }

        static IEnumerable<IFuture> Emit(LabContext c, TraceStream stream, TraceEventDraft draft)
        {
            TraceEvent e = stream.Stamp(draft);
            yield return c.Gate.Pass(e);
            c.Sink.Write(e);
        }

        static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static Tls11Engine Tls11Client(LabContext c, ITrainingKeySource keys, ITamperHook plan)
        {
            Tls11Options o = Common(c, "client", plan);
            Tls11Training.TrustTrainingRoot(o, keys, LabDate);
            return Tls11Engine.CreateClient(o);
        }

        static Tls11Engine Tls11Server(LabContext c, ITrainingKeySource keys, ITamperHook plan, bool writeDowngradeTail)
        {
            Tls11Options o = Common(c, "server", plan);
            Tls11Training.UseTrainingServerKey(o, keys);
            o.WriteDowngradeTail = writeDowngradeTail;
            return Tls11Engine.CreateServer(o);
        }

        static Tls11Options Common(LabContext c, string actor, ITamperHook plan)
        {
            return Common(c, actor, plan, Tls11CipherSuite.RsaAes128CbcSha, "tls11");
        }

        static Tls11Options Common(LabContext c, string actor, ITamperHook plan, Tls11CipherSuite suite, string protocol)
        {
            Tls11Options o = new Tls11Options();
            o.Suite = suite;
            o.Random = LabPair.Fork(c);
            o.Stream = LabPair.Stream(c, actor, protocol);
            o.Tamper = plan;
            return o;
        }
    }
}
