using System;
using System.Collections.Generic;
using MMP.AsyncProxy;
using NetSec.Crypto;
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
        public const string ScenarioDowngrade = "downgrade", ScenarioModernServer = "modern-server";

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
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Race(c, ret); });
        }

        /// <summary>
        /// Each pair draws its own random stream before either starts, so a same-seed rerun gives the same bytes. Only the TLS 1.1 pair meets the attack plan.
        /// The first failure stands for the run: a failed 1.3 half would be a fault in the lab, and a flip attack hits the 1.1 half.
        /// </summary>
        static IEnumerable<IFuture> Race(LabContext c, Return<LabResult> ret)
        {
            ITrainingKeySource keys = new TrainingKeySource();
            ITamperHook plan = LabPair.Plan(c);
            LabContext modern = new LabContext();
            modern.Seed = c.Seed; modern.SessionId = c.SessionId; modern.TraceId = c.TraceId; modern.Transports = c.Transports; modern.Gate = c.Gate;
            modern.Sink = c.Sink; modern.Clock = c.Clock; modern.DeadlineMs = c.DeadlineMs;
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
            ITrainingKeySource keys = new TrainingKeySource();
            ITamperHook plan = LabPair.Plan(c);
            return LabPair.Run(c, Tls13Lab.Lesson5().Client(c, plan, true), Tls11Server(c, keys, plan, true), plan);
        }

        /// <summary>The modern server names its own refusal. The lesson is what the old client sees: alert 70. So this run reports the client's check.</summary>
        static IEnumerable<IFuture> ModernServer(LabContext c, Return<LabResult> ret)
        {
            ITamperHook plan = LabPair.Plan(c);
            Tls11Engine client = Tls11Client(c, new TrainingKeySource(), plan);
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
            Tls11Options o = new Tls11Options();
            o.Suite = Tls11CipherSuite.RsaAes128CbcSha;
            o.Random = LabPair.Fork(c);
            o.Stream = LabPair.Stream(c, actor, "tls11");
            o.Tamper = plan;
            return o;
        }
    }
}
