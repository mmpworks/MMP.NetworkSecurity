using System.Security.Cryptography;
using NetSec.Keys;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>The outside check on the literal RSA keys: the .NET BCL reads them. The BCL import exists on net10.0 only, so this stays out of the suite that runs on both builds.</summary>
    public class TrainingKeyBclTests
    {
        [Theory]
        [InlineData(KeyIds.ServerTls11Rsa)]
        [InlineData(KeyIds.SshHostRsa)]
        public void The_bcl_imports_the_pkcs8_and_exports_the_same_spki(string id)
        {
            ITrainingKey key = new TrainingKeySource().Find(id);
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(key.CopyMaterial(), out int read);
                Assert.Equal(key.CopyMaterial().Length, read);
                Assert.Equal(2048, rsa.KeySize);
                Assert.Equal(rsa.ExportSubjectPublicKeyInfo(), key.CopyPublic());
            }
        }
    }
}
