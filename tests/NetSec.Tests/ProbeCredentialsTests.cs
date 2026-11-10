using System;
using System.IO;
using System.Text;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Pki;
using NetSec.Ssh;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>ProbeRequest.Credentials on the SSH routes: a server and a client on the learner's keys reach each other, and the training keys do not.</summary>
    public class ProbeCredentialsTests
    {
        static CredentialSet Learner()
        {
            byte[] hostSeed = new byte[32], userSeed = new byte[32];
            for (int i = 0; i < 32; i++) { hostSeed[i] = (byte)(i + 40); userSeed[i] = (byte)(i + 90); }
            ITrainingKey host = KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(hostSeed)), KeyIds.SshHostEd25519);
            ITrainingKey user = KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(userSeed)), KeyIds.SshClient);
            return new CredentialSet(new TrainingKeySource(), new[]
            {
                new Credential(SecurityTypes.SshHostEd25519, CredentialMode.Mine, "test", 1, "", host),
                new Credential(SecurityTypes.SshClient, CredentialMode.Mine, "test", 1, "", user),
            });
        }

        static async System.Threading.Tasks.Task<ProbeResult> Run(CredentialSet server, CredentialSet client, ITrainingKeySource pinFrom)
        {
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", SshSuite = SshSuite.Modern, Seed = 31, Credentials = server });
            string pin = Path.Combine(Path.GetTempPath(), "netsec-pin-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(pin, SshSetup.KnownHostLine(pinFrom, SshSuite.Modern, "127.0.0.1", listener.Port));
            ProbeRequest connect = new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", Port = listener.Port, SshSuite = SshSuite.Modern, Seed = 32,
                KnownHostsFile = pin, ClientKeyId = KeyIds.SshClient, ExecCommand = "echo hello", Credentials = client };
            ProbeResult result = Probe.Connect(connect).Result;
            await FutureWaits.Within(listener.Result, TimeSpan.FromMilliseconds(30000));
            return result;
        }

        [Fact]
        public async System.Threading.Tasks.Task A_server_and_a_client_on_the_learners_keys_reach_each_other()
        {
            CredentialSet mine = Learner();
            ProbeResult r = await Run(mine, mine, mine);
            Assert.True(r.Completed, r.CheckName + " [" + r.Code + "]");
            Assert.Contains("hello", Encoding.ASCII.GetString(r.Received));
        }

        [Fact]
        public async System.Threading.Tasks.Task The_training_keys_do_not_reach_a_server_on_the_learners_keys()
        {
            CredentialSet mine = Learner();
            ProbeResult userKey = await Run(mine, null, mine), hostKey = await Run(mine, mine, new TrainingKeySource());
            Assert.False(userKey.Completed, "the training user key was accepted by a server that holds the learner's set");
            Assert.False(hostKey.Completed, "a pin of the training host key accepted the learner's host key");
            // A timeout or a port clash also ends a probe early, so each refusal must carry its own code.
            Assert.Equal(SshCodes.AuthRefused, userKey.Code);
            Assert.Equal(SshCodes.HostKeyChanged, hostKey.Code);
        }

        [Fact]
        public void A_tls_probe_refuses_a_credential_set_by_name()
        {
            ProbeRequest r = new ProbeRequest { Protocol = WireProtocol.Tls13, Host = "127.0.0.1", Credentials = CredentialSet.BuiltIn(new TrainingKeySource()) };
            Assert.Equal(ErrorCodes.FileRowNotBuilt, Assert.Throws<NetSecException>(() => Probe.Listen(r)).Error.Code);
            Assert.Equal(ErrorCodes.FileRowNotBuilt, Assert.Throws<NetSecException>(() => Probe.Connect(r)).Error.Code);
        }
    }
}
