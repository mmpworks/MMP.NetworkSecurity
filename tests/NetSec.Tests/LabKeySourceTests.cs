using System;
using System.Collections.Generic;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>A lab that holds a learner's key must use it everywhere. One run that mixes key sources still completes, so these tests look at the bytes.</summary>
    public class LabKeySourceTests
    {
        static readonly ITrainingKeySource Training = new TrainingKeySource();

        sealed class Spy : ITrainingKeySource
        {
            public readonly List<string> Asked = new List<string>();

            public ITrainingKey Find(string keyId)
            {
                lock (Asked) Asked.Add(keyId);
                return Training.Find(keyId);
            }
        }

        static ITrainingKey OwnEd25519(int fill)
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(fill + i);
            return KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(seed)), "own-" + fill);
        }

        static Credential Own(string typeId, ITrainingKey key)
        {
            return new Credential(typeId, CredentialMode.Mine, "test", 1, "fp", key);
        }

        // The two training RSA keys trade places, so each type holds a sound RSA key that is not its own built-in one.
        static CredentialSet AllOwn()
        {
            List<Credential> own = new List<Credential>
            {
                Own(SecurityTypes.RootCa, OwnEd25519(1)),
                Own(SecurityTypes.Tls13Server, OwnEd25519(40)),
                Own(SecurityTypes.Tls13Client, OwnEd25519(80)),
                Own(SecurityTypes.SshHostEd25519, OwnEd25519(120)),
                Own(SecurityTypes.SshClient, OwnEd25519(160)),
                Own(SecurityTypes.TokenIssuer, OwnEd25519(200)),
                Own(SecurityTypes.Tls11Server, Training.Find(KeyIds.SshHostRsa)),
                Own(SecurityTypes.SshHostRsa, Training.Find(KeyIds.ServerTls11Rsa)),
            };
            return new CredentialSet(Training, own.ToArray());
        }

        static TraceEvent[] Run(int lesson, CredentialSet set)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "own", TraceId = "own", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7), Credentials = set };
            IFuture<LabResult> run = LabCatalog.Find(lesson).Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            Assert.True(run.Result.Completed, "lesson " + lesson + " stopped at " + run.Result.FailedCode);
            return sink.Events;
        }

        /// <summary>The bytes of a built-in key's public half that a trace would carry: 32 bytes for Ed25519, the modulus for RSA.</summary>
        static byte[] Footprint(string keyId)
        {
            ITrainingKey key = Training.Find(keyId);
            if (key.Algorithm != KeyAlgorithm.Rsa2048) return key.CopyPublic();
            byte[] n = RsaPkcs8.Parse(key.CopyMaterial()).N;
            byte[] tail = new byte[64];
            Buffer.BlockCopy(n, n.Length - tail.Length, tail, 0, tail.Length);
            return tail;
        }

        static bool Holds(byte[] hay, byte[] needle)
        {
            if (hay == null) return false;
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }

        static string[] KeysInTrace(TraceEvent[] events, string[] keyIds)
        {
            List<string> found = new List<string>();
            foreach (string keyId in keyIds)
            {
                byte[] print = Footprint(keyId);
                foreach (TraceEvent e in events)
                {
                    bool inSecrets = e.Secrets != null && e.Secrets.Any(s => Holds(s.Bytes, print));
                    if (Holds(e.Wire, print) || Holds(e.Plain, print) || inSecrets)
                    {
                        found.Add(keyId);
                        break;
                    }
                }
            }
            return found.ToArray();
        }

        static readonly string[] RoutedPublicKeys = { KeyIds.ServerTlsEd25519, KeyIds.ClientTlsEd25519, KeyIds.ServerTls11Rsa, KeyIds.SshHostEd25519, KeyIds.SshHostRsa, KeyIds.SshClient, KeyIds.CaRoot };

        [Theory]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(7)]
        [InlineData(8)]
        [InlineData(9)]
        [InlineData(10)]
        public void A_lab_on_own_keys_shows_no_built_in_key(int lesson)
        {
            string[] read = RoutedPublicKeys.Where(k => Array.IndexOf(LabCatalog.Needs(lesson), SecurityTypes.OfKey(k)) >= 0).ToArray();
            string[] hits = KeysInTrace(Run(lesson, AllOwn()), read);
            Assert.True(hits.Length == 0, "lesson " + lesson + " on own keys shows these built-in keys: " + string.Join(", ", hits));
        }

        sealed class BytesKey : ITrainingKey
        {
            readonly byte[] _key;
            public BytesKey(byte[] key) { _key = key; }
            public string KeyId { get { return "bytes"; } }
            public KeyAlgorithm Algorithm { get { return KeyAlgorithm.Raw; } }
            public byte[] CopyMaterial() { return (byte[])_key.Clone(); }
            public byte[] CopyPublic() { return new byte[0]; }
        }

        static LabContext LessonContext(ITrainingKey own, string typeId)
        {
            Credential[] mine = own == null ? new Credential[0] : new[] { Own(typeId, own) };
            return new LabContext { Seed = 7, Random = new SeededRandom(7), Credentials = new CredentialSet(Training, mine) };
        }

        [Fact]
        public void A_lesson_key_is_drawn_when_the_learner_has_none_and_the_learners_when_they_do()
        {
            byte[] own = new byte[LabCredentials.LessonKeyBytes];
            own[0] = 9;
            byte[] seeded = new byte[LabCredentials.LessonKeyBytes];
            new SeededRandom(7).Fill(seeded, 0, seeded.Length);
            Assert.Equal(seeded, LabCredentials.LessonKey(LessonContext(null, SecurityTypes.LabAesKey), SecurityTypes.LabAesKey));
            Assert.Equal(own, LabCredentials.LessonKey(LessonContext(new BytesKey(own), SecurityTypes.LabAesKey), SecurityTypes.LabAesKey));
        }

        /// <summary>The rest of a run reads the same random bytes on own keys, so its nonces and IVs stay comparable.</summary>
        [Fact]
        public void A_lesson_key_draws_even_when_the_learner_has_one()
        {
            LabContext builtIn = LessonContext(null, SecurityTypes.LabSealKey);
            LabContext own = LessonContext(new BytesKey(new byte[LabCredentials.LessonKeyBytes]), SecurityTypes.LabSealKey);
            LabCredentials.LessonKey(builtIn, SecurityTypes.LabSealKey);
            LabCredentials.LessonKey(own, SecurityTypes.LabSealKey);
            byte[] next = new byte[8], nextOwn = new byte[8];
            builtIn.Random.Fill(next, 0, next.Length);
            own.Random.Fill(nextOwn, 0, nextOwn.Length);
            Assert.Equal(next, nextOwn);
        }

        [Fact]
        public void A_lesson_key_of_another_length_is_refused_by_name()
        {
            LabContext c = LessonContext(new BytesKey(new byte[24]), SecurityTypes.LabAesKey);
            NetSec.Errors.NetSecException e = Assert.Throws<NetSec.Errors.NetSecException>(() => LabCredentials.LessonKey(c, SecurityTypes.LabAesKey));
            Assert.Equal(NetSec.Errors.ErrorCodes.SecurityTypeNotReady, e.Error.Code);
        }

        [Fact]
        public void The_scan_sees_a_built_in_key_when_one_is_there()
        {
            string[] hits = KeysInTrace(Run(7, CredentialSet.BuiltIn(Training)), RoutedPublicKeys);
            Assert.Contains(KeyIds.ServerTlsEd25519, hits);
            Assert.Contains(KeyIds.ServerTls11Rsa, hits);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        [InlineData(9)]
        [InlineData(10)]
        public void A_lab_reads_only_keys_of_the_types_it_declares(int lesson)
        {
            Spy spy = new Spy();
            Run(lesson, CredentialSet.BuiltIn(spy));
            string[] needs = LabCatalog.Needs(lesson);
            foreach (string keyId in spy.Asked.Distinct())
            {
                string typeId = SecurityTypes.OfKey(keyId);
                if (typeId != null) Assert.True(Array.IndexOf(needs, typeId) >= 0, "lesson " + lesson + " reads " + keyId + ", and LabCatalog.Needs does not list " + typeId);
            }
        }
    }
}
