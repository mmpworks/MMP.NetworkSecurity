using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Slice P4b's TLS 1.1 key-schedule walk. Referees: the engine's own key log line (the walk checks it too), and OpenSSL, run here.
    /// OpenSSL decrypts the pre-master with the same training key, and its TLS1-PRF derives the master secret and the key block.
    /// OpenSSL shares no code with the engine.
    /// </summary>
    public class Tls11KeyScheduleWalkTests
    {
        static readonly Tls11KeyScheduleWalk W = Tls11KeyScheduleWalks.TeachingRun();

        static string OpenSsl(string args, string dir)
        {
            ProcessStartInfo start = new ProcessStartInfo("openssl", args)
            {
                WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using Process p = Process.Start(start);
            string output = p.StandardOutput.ReadToEnd(), error = p.StandardError.ReadToEnd();
            Assert.True(p.WaitForExit(30_000), "openssl did not finish in 30 s: " + args);
            Assert.True(p.ExitCode == 0, "openssl " + args + " failed: " + error);
            return output.Trim();
        }

        /// <summary>openssl kdf TLS1-PRF with MD5-SHA1, as Tls11Tests' known answers use. Returns lower-case hex.</summary>
        static string Prf(byte[] secret, string label, byte[] seed, int length, string dir) =>
            OpenSsl("kdf -keylen " + length + " -kdfopt digest:MD5-SHA1 -kdfopt hexsecret:" + Hex.Encode(secret)
                + " -kdfopt hexseed:" + Hex.Encode(Encoding.ASCII.GetBytes(label).Concat(seed).ToArray()) + " TLS1-PRF", dir).Replace(":", "").ToLowerInvariant();

        [Fact]
        public void The_walk_runs_on_the_built_in_training_key_and_its_sizes_are_right()
        {
            Assert.Equal(KeyIds.ServerTls11Rsa, W.ServerKeyId);
            Assert.Equal(Hex.Encode(new TrainingKeySource().Find(KeyIds.ServerTls11Rsa).CopyPublic()), Hex.Encode(W.ServerPublicKey));
            Assert.Equal("TLS_RSA_WITH_AES_128_CBC_SHA", W.Suite);
            Assert.Equal(32, W.ClientRandom.Length);
            Assert.Equal(32, W.ServerRandom.Length);
            Assert.Equal(256, W.EncryptedPremaster.Length);
            Assert.Equal(48, W.Premaster.Length);
            Assert.Equal(0x0302, W.PremasterVersion);
            Assert.Equal(48, W.MasterSecret.Length);
            Assert.Equal(72, W.KeyBlock.Length);
            Assert.Equal(new[] { 20, 20, 16, 16 }, new[] { W.ClientMacKey.Length, W.ServerMacKey.Length, W.ClientKey.Length, W.ServerKey.Length });
            Assert.Equal("CLIENT_RANDOM " + Hex.Encode(W.ClientRandom) + " " + Hex.Encode(W.MasterSecret), W.KeyLogLine);
        }

        [Fact]
        public void The_run_is_fixed_so_a_second_build_gives_the_same_bytes()
        {
            Tls11KeyScheduleWalk again = Tls11KeyScheduleWalks.TeachingRun();
            Assert.Equal(W.KeyLogLine, again.KeyLogLine);
            Assert.Equal(Hex.Encode(W.EncryptedPremaster), Hex.Encode(again.EncryptedPremaster));
        }

        [Fact]
        public void OpenSsl_decrypts_the_same_premaster_and_derives_the_same_master_secret_and_key_block()
        {
            string dir = Path.Combine(Path.GetTempPath(), "netsec-p4b-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                File.WriteAllBytes(Path.Combine(dir, "server.der"), new TrainingKeySource().Find(KeyIds.ServerTls11Rsa).CopyMaterial());
                File.WriteAllBytes(Path.Combine(dir, "premaster.enc"), W.EncryptedPremaster);
                OpenSsl("pkeyutl -decrypt -keyform DER -inkey server.der -pkeyopt rsa_padding_mode:pkcs1 -in premaster.enc -out premaster.bin", dir);
                Assert.Equal(Hex.Encode(W.Premaster), Hex.Encode(File.ReadAllBytes(Path.Combine(dir, "premaster.bin"))));

                Assert.Equal(Hex.Encode(W.MasterSecret), Prf(W.Premaster, "master secret", W.ClientRandom.Concat(W.ServerRandom).ToArray(), 48, dir));
                Assert.Equal(Hex.Encode(W.KeyBlock), Prf(W.MasterSecret, "key expansion", W.ServerRandom.Concat(W.ClientRandom).ToArray(), 72, dir));
            }
            finally
            {
                // The test removes only the fresh folder it made.
                Directory.Delete(dir, true);
            }
        }

        [Fact]
        public void The_guard_names_its_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => Tls11KeyScheduleWalks.Require(false));
            Assert.Equal(ErrorCodes.Tls11WalkDiverged, e.Error.Code);
        }
    }
}
