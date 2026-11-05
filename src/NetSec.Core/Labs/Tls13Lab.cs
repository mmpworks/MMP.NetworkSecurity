using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lessons 4 and 5: the glass TLS 1.3 client and server on loopback, each its own pump. The client sends one line, the server sends it back,
    /// and the client closes. Lesson 4 also shows the training CA issuing the certificates. Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Tls13Lab : ILab
    {
        public const string OptionServerCert = "server-cert";
        public const string CertExpired = "expired";
        public const string CertWrongName = "wrong-name";
        public const string CertUnknownCa = "unknown-ca";

        // Byte offsets the attack rows flip. A test pins each one beside a passing control.
        // Handshake header 4, context 1, list length 3, certificate length 3, outer SEQUENCE 4, TBS SEQUENCE 4, version 5, serial tag and length 2, then the serial.
        public const int CertSerialOffset = 28;
        // Handshake header 4, scheme 2, signature length 2, then the signature.
        public const int CertVerifySignatureOffset = 8;
        public const int VerifyDataOffset = 4;
        // Record header 5, then the sealed bytes.
        public const int RecordCipherOffset = 8;
        // Header 4, version 2, random 32, session id length 1, suites 2 + 4, compression 2, extensions length 2, server_name 18, versions 7, groups 8, signatures 8, key_share head 10, ek 1184.
        public const int ClientX25519ShareOffset = 1284;
        // Header 4, version 2, random 32, session id length 1, suite 2, compression 1, extensions length 2, versions 6, key_share head 8, then the ciphertext.
        public const int ServerMlKemCiphertextOffset = 68;

        static readonly DateTime LabNow = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        static readonly byte[] ClientLine = Encoding.UTF8.GetBytes("hello over TLS 1.3\n");
        const string OtherName = "other.example";
        const string AttackerRootName = "Attacker training root";

        readonly string _labId;
        readonly Tls13Group _group;
        readonly bool _showIssuing;

        Tls13Lab(string labId, Tls13Group group, bool showIssuing)
        {
            _labId = labId; _group = group; _showIssuing = showIssuing;
        }

        public static Tls13Lab Lesson4() { return new Tls13Lab("lab-04-certificates", Tls13Group.X25519, true); }
        public static Tls13Lab Lesson5() { return new Tls13Lab("lab-05-tls13", Tls13Group.X25519MlKem768, false); }

        public string LabId { get { return _labId; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, ret); });
        }

        IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            ITrainingKeySource keys = new TrainingKeySource();
            TrainingCa ca = new TrainingCa(keys);
            byte[] leaf = LeafFor(LabPair.Option(c, OptionServerCert), ca, keys);
            if (_showIssuing)
            {
                TraceStream caStream = LabPair.Stream(c, "ca", "pki");
                foreach (IFuture step in Publish(c, caStream, "RootCertificate", "client", ca.RootCertificateDer)) yield return step;
                foreach (IFuture step in Publish(c, caStream, "ServerCertificate", "server", leaf)) yield return step;
            }

            ITamperHook plan = LabPair.Plan(c);
            Tls13Engine client = Tls13Engine.CreateClient(ClientOptions(c, plan, ca));
            Tls13Engine server = Tls13Engine.CreateServer(ServerOptions(c, plan, leaf, keys));
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, ClientLine, null));

            IFuture<LabResult> run = LabPair.Run(c, client, server, plan, EchoThenClose);
            yield return run;
            ret.Value = run.Result;
        }

        /// <summary>The server sends each chunk back. The client closes when it has its line back.</summary>
        static void EchoThenClose(EnginePump client, EnginePump server)
        {
            server.OnApp = delegate(AppChunk chunk) { server.Enqueue(new EngineCommand(EngineCommandKind.Send, 0, chunk.Bytes, null)); };
            client.OnApp = delegate(AppChunk chunk) { client.Enqueue(EngineCommand.Close); };
        }

        static IEnumerable<IFuture> Publish(LabContext c, TraceStream stream, string message, string to, byte[] certificate)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "ca.certificate.issued";
            draft.Message = message;
            draft.From = "ca";
            draft.To = to;
            draft.Plain = certificate;
            draft.Fields = TraceField.From(Certificate.Parse(certificate).Marks(0, true));
            TraceEvent issued = stream.Stamp(draft);
            yield return c.Gate.Pass(issued);
            c.Sink.Write(issued);
        }

        static byte[] LeafFor(string scenario, TrainingCa ca, ITrainingKeySource keys)
        {
            byte[] spki = TrainingCa.Ed25519Spki(keys.Find(KeyIds.ServerTlsEd25519).CopyPublic());
            DateTime from = TrainingCa.DefaultNotBefore, until = TrainingCa.DefaultNotAfter;
            switch (scenario)
            {
                case CertExpired:
                    return ca.IssueServerCertificate(TrainingPki.ServerName, spki, new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc));
                case CertWrongName:
                    return ca.IssueServerCertificate(OtherName, spki, from, until);
                case CertUnknownCa:
                    return new TrainingCa(keys.Find(KeyIds.AttackerEd25519), AttackerRootName).IssueServerCertificate(TrainingPki.ServerName, spki, from, until);
                default:
                    return ca.IssueServerCertificate(TrainingPki.ServerName, spki, from, until);
            }
        }

        Tls13Options Common(LabContext c, ITamperHook plan, string actor, string peer)
        {
            Tls13Options o = new Tls13Options();
            o.Stream = LabPair.Stream(c, actor, "tls13");
            o.Peer = peer;
            o.Random = LabPair.Fork(c);
            o.Tamper = plan;
            o.Group = _group;
            o.ServerName = TrainingPki.ServerName;
            o.Now = LabNow;
            return o;
        }

        Tls13Options ClientOptions(LabContext c, ITamperHook plan, TrainingCa ca)
        {
            Tls13Options o = Common(c, plan, "client", "server");
            o.TrustAnchors = new byte[][] { ca.RootCertificateDer };
            return o;
        }

        Tls13Options ServerOptions(LabContext c, ITamperHook plan, byte[] leaf, ITrainingKeySource keys)
        {
            Tls13Options o = Common(c, plan, "server", "client");
            o.CertificateChain = new byte[][] { leaf };
            o.SigningSeed = keys.Find(KeyIds.ServerTlsEd25519).CopyMaterial();
            return o;
        }
    }
}
