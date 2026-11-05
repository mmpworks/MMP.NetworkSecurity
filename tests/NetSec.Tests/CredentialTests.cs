using System.Linq;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Pki;
using Xunit;

namespace NetSec.Tests
{
    public class CredentialTests
    {
        static readonly string CaSeedPem = SeedPem();

        static string SeedPem()
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = (byte)i;
            return TrainingPki.Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(seed));
        }

        static SecurityTypeState State(string typeId, CredentialMode mode, Readiness readiness)
        {
            return new SecurityTypeState { TypeId = typeId, FlowId = "flow-of-" + typeId, Mode = mode, Readiness = readiness };
        }

        [Fact]
        public void A_set_with_no_entries_gives_the_built_in_key()
        {
            CredentialSet set = CredentialSet.BuiltIn(new TrainingKeySource());
            Assert.Equal(new TrainingKeySource().Find(KeyIds.TokenIssuer).CopyMaterial(), set.Find(KeyIds.TokenIssuer).CopyMaterial());
            Assert.Null(set.MineOrNull(SecurityTypes.DeviceEnrolment));
        }

        [Fact]
        public void A_set_routes_each_key_of_a_mine_type_and_leaves_the_others_built_in()
        {
            ITrainingKey own = KeyFileReader.Parse(CaSeedPem, SecurityTypes.TokenIssuer);
            CredentialSet set = new CredentialSet(new TrainingKeySource(), new Credential[] { new Credential(SecurityTypes.TokenIssuer, CredentialMode.Mine, "file", 1, "fp", own) });
            Assert.Equal(own.CopyMaterial(), set.Find(KeyIds.TokenIssuer).CopyMaterial());
            Assert.Equal(new TrainingKeySource().Find(KeyIds.CaRoot).CopyMaterial(), set.Find(KeyIds.CaRoot).CopyMaterial());
        }

        [Fact]
        public void The_attackers_key_has_no_type_so_no_learner_key_can_replace_it()
        {
            Assert.Null(SecurityTypes.OfKey(KeyIds.AttackerEd25519));
        }

        [Fact]
        public void Every_type_a_lesson_reads_is_one_of_the_fifteen()
        {
            Assert.Equal(15, SecurityTypes.All.Length);
            for (int lesson = 0; lesson <= 11; lesson++)
                foreach (string typeId in LabCatalog.Needs(lesson))
                    Assert.Contains(typeId, SecurityTypes.All);
        }

        [Fact]
        public void All_built_in_may_run()
        {
            SecurityTypeState[] states = { State(SecurityTypes.TokenIssuer, CredentialMode.BuiltIn, Readiness.Ready) };
            Assert.True(SecurityReadiness.Decide(new string[] { SecurityTypes.TokenIssuer }, states).MayRun);
        }

        [Theory]
        [InlineData(Readiness.Unconfigured, ErrorCodes.SecurityTypeNotReady)]
        [InlineData(Readiness.Broken, ErrorCodes.SecurityTypeNotReady)]
        [InlineData(Readiness.Configured, ErrorCodes.SecurityTypeNotProven)]
        public void A_mine_type_that_is_not_ready_refuses_by_name(Readiness readiness, string code)
        {
            SecurityTypeState[] states = { State(SecurityTypes.TokenIssuer, CredentialMode.Mine, readiness) };
            LabDecision d = SecurityReadiness.Decide(new string[] { SecurityTypes.TokenIssuer }, states);
            Assert.False(d.MayRun);
            Assert.Equal(code, d.Problems[0].Code);
            Assert.Contains(SecurityTypes.TokenIssuer, d.Problems[0].Detail);
            Assert.Contains("flow-of-" + SecurityTypes.TokenIssuer, d.Problems[0].Detail);
        }

        [Fact]
        public void A_type_the_lab_does_not_read_cannot_stop_it()
        {
            SecurityTypeState[] states = { State(SecurityTypes.SshClient, CredentialMode.Mine, Readiness.Unconfigured) };
            Assert.True(SecurityReadiness.Decide(new string[] { SecurityTypes.TokenIssuer }, states).MayRun);
        }

        [Fact]
        public void A_mine_server_with_a_built_in_trust_list_disagrees_and_names_the_built_in_type()
        {
            SecurityTypeState[] states = { State(SecurityTypes.Tls13Server, CredentialMode.Mine, Readiness.Ready), State(SecurityTypes.TlsTrust, CredentialMode.BuiltIn, Readiness.Ready) };
            LabDecision d = SecurityReadiness.Decide(new string[] { SecurityTypes.Tls13Server, SecurityTypes.TlsTrust }, states);
            Assert.Equal(ErrorCodes.SecurityTypesDisagree, d.Problems.Single().Code);
            Assert.Equal(SecurityTypes.TlsTrust, d.Problems.Single().TypeId);
        }

        [Fact]
        public void An_ed25519_file_reads_to_its_seed_and_public_key()
        {
            ITrainingKey key = KeyFileReader.Parse(CaSeedPem, "k");
            Assert.Equal(KeyAlgorithm.Ed25519, key.Algorithm);
            Assert.Equal(32, key.CopyMaterial().Length);
            Assert.Equal(NetSec.Crypto.Ed25519.PublicFrom(key.CopyMaterial()), key.CopyPublic());
            Assert.Equal(0, key.CopyMaterial()[0]);
            Assert.Equal(31, key.CopyMaterial()[31]);
        }

        [Fact]
        public void A_training_rsa_key_reads_with_the_same_public_key_the_training_source_gives()
        {
            ITrainingKey training = new TrainingKeySource().Find(KeyIds.ServerTls11Rsa);
            ITrainingKey read = KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", training.CopyMaterial()), "k");
            Assert.Equal(KeyAlgorithm.Rsa2048, read.Algorithm);
            Assert.Equal(training.CopyMaterial(), read.CopyMaterial());
            Assert.Equal(training.CopyPublic(), read.CopyPublic());
        }

        [Theory]
        [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", ErrorCodes.KeyFileEncrypted)]
        [InlineData("just some words", ErrorCodes.KeyFileFormat)]
        [InlineData("-----BEGIN PRIVATE KEY-----\nnot base 64!\n-----END PRIVATE KEY-----\n", ErrorCodes.KeyFileFormat)]
        [InlineData("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ErrorCodes.KeyFileFormat)]
        public void A_bad_key_file_is_refused_by_name(string text, string code)
        {
            NetSecException e = Assert.Throws<NetSecException>(delegate { KeyFileReader.Parse(text, "k"); });
            Assert.Equal(code, e.Error.Code);
        }

        [Fact]
        public void A_file_that_is_not_there_is_refused_by_name()
        {
            NetSecException e = Assert.Throws<NetSecException>(delegate { KeyFileReader.ReadPrivateKey(@"Z:\no\such\file.pem", "k"); });
            Assert.Equal(ErrorCodes.KeyFileUnreadable, e.Error.Code);
        }
    }
}
