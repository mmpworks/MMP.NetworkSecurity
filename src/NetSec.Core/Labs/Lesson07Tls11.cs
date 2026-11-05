using System;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Tls11;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 7. The old world: a TLS 1.1 client and server on loopback. RFC 8996 retires TLS 1.1, and this lab exists to show what an old device has.
    /// The lab forces RSA key transport, because a default run picks the best case. What is weak here: an attacker can record the run and read it after a key theft,
    /// and CBC with MAC-then-encrypt leaves padding oracles. Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson07Tls11 : ILab
    {
        public const string ApplicationData = Tls11Messages.ApplicationDataName;

        /// <summary>Where the first cipher byte of a protected record sits.</summary>
        public const int CipherOffset = Tls11RecordCipher.HeaderSize + Tls11RecordCipher.IvSize;

        static readonly byte[] Greeting = Encoding.UTF8.GetBytes("hello from the old world\n");

        /// <summary>A date inside the training certificates. A fixed date keeps a same-seed rerun the same.</summary>
        static readonly DateTime LabDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public string LabId { get { return "lab-07-tls11"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            ITrainingKeySource keys = new TrainingKeySource();
            ITamperHook plan = LabPair.Plan(c);
            return LabPair.Run(c, Tls11Client(c, keys, plan), Tls11Server(c, keys, plan), plan);
        }

        static Tls11Engine Tls11Client(LabContext c, ITrainingKeySource keys, ITamperHook plan)
        {
            Tls11Options o = Common(c, "client", plan);
            Tls11Training.TrustTrainingRoot(o, keys, LabDate);
            o.SendOnOpen = Greeting;
            o.CloseAfterReply = true;
            return Tls11Engine.CreateClient(o);
        }

        static Tls11Engine Tls11Server(LabContext c, ITrainingKeySource keys, ITamperHook plan)
        {
            Tls11Options o = Common(c, "server", plan);
            Tls11Training.UseTrainingServerKey(o, keys);
            o.EchoReceived = true;
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
