using System;
using System.IO;
using NetSec.Io;
using NetSec.Pki;

namespace Acceptance
{
    /// <summary>
    /// The files TrainingPki.Export writes for the referees (design section 11, section 9 names). A missing file is a FAIL that names the file,
    /// because the export is the product's half of the contract.
    /// </summary>
    public sealed class PkiDir
    {
        public string Dir;
        public string Root { get { return Path.Combine(Dir, "root.pem"); } }
        public string Cert { get { return Path.Combine(Dir, "srv.pem"); } }
        public string Key { get { return Path.Combine(Dir, "srv.key"); } }
        public string RsaCert { get { return Path.Combine(Dir, "rsa.pem"); } }
        public string RsaKey { get { return Path.Combine(Dir, "rsa.key"); } }
        public string HostKey { get { return Path.Combine(Dir, "host.key"); } }
        public string RsaHostKey { get { return Path.Combine(Dir, "rsa-host.key"); } }
        public string UserPub { get { return Path.Combine(Dir, "user.pub"); } }
        public string UserKey { get { return Path.Combine(Dir, "user.key"); } }
        public string IssuerPub { get { return Path.Combine(Dir, "issuer.pub"); } }

        public static PkiDir Export(Ctx c, string name)
        {
            PkiDir p = new PkiDir();
            p.Dir = LivePki.Dir(c, name);
            TrainingPki.Export(p.Dir);
            foreach (string f in new string[] { p.Root, p.Cert, p.Key, p.RsaCert, p.RsaKey, p.HostKey, p.RsaHostKey, p.UserPub, p.UserKey, p.IssuerPub })
                if (!File.Exists(f)) throw new FailException("TrainingPki.Export wrote no " + Path.GetFileName(f) + " in " + p.Dir);
            return p;
        }
    }

    public static class ProbeKit
    {
        public static ProbeResult Connect(ProbeRequest r, string what) { return Futs.Get(Probe.Connect(r), 60000, what); }

        public static ProbeRequest Request(WireProtocol protocol, int port, string peerName)
        {
            ProbeRequest r = new ProbeRequest();
            r.Protocol = protocol; r.Host = "127.0.0.1"; r.Port = port; r.PeerName = peerName; r.Seed = 5001;
            return r;
        }
    }
}
