using System;
using NetSec.Keys;
using NetSec.Pki;

namespace NetSec.Tls11
{
    /// <summary>Fills engine options from the made-up training PKI. Every key here is public in this source, so these certificates prove nothing outside the labs.</summary>
    public static class Tls11Training
    {
        public static void TrustTrainingRoot(Tls11Options options, ITrainingKeySource keys, DateTime now)
        {
            options.Anchors = new Certificate[] { Certificate.Parse(new TrainingCa(keys).RootCertificateDer) };
            options.PeerName = options.PeerName ?? TrainingPki.ServerName;
            options.Now = now;
        }

        public static void UseTrainingServerKey(Tls11Options options, ITrainingKeySource keys)
        {
            ITrainingKey rsa = keys.Find(KeyIds.ServerTls11Rsa);
            byte[] leaf = new TrainingCa(keys).IssueServerCertificate(TrainingPki.ServerName, rsa.CopyPublic(), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
            options.Chain = new byte[][] { leaf };
            options.ServerKey = Tls11RsaKeys.ReadPrivate(rsa.CopyMaterial());
        }
    }
}
