using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Tls11;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// TLS 1.1 RSA key transport, step by step (docs/sections-plan.md, R8 and slice P4b). The client encrypts a 48-byte pre-master to the
    /// server's RSA key. Whoever holds that key decrypts the pre-master, and the pre-master and the two randoms give every session key.
    /// </summary>
    public sealed class Tls11KeyScheduleWalk
    {
        public string Suite, ServerKeyId;

        /// <summary>The server's RSA public key (SubjectPublicKeyInfo DER), so a reader can see which key the pre-master went to.</summary>
        public byte[] ServerPublicKey;

        /// <summary>From the ClientHello and the ServerHello on the wire.</summary>
        public byte[] ClientRandom, ServerRandom;

        /// <summary>The ClientKeyExchange body on the wire, and its RSA PKCS#1 v1.5 decryption with the server's private key.</summary>
        public byte[] EncryptedPremaster, Premaster;

        /// <summary>The first 2 pre-master bytes: the version the client offered (0x0302 for TLS 1.1).</summary>
        public int PremasterVersion;

        /// <summary>PRF(pre-master, "master secret", client random + server random), 48 bytes.</summary>
        public byte[] MasterSecret;

        /// <summary>PRF(master, "key expansion", server random + client random), 72 bytes, then split in this order.</summary>
        public byte[] KeyBlock, ClientMacKey, ServerMacKey, ClientKey, ServerKey;

        /// <summary>The engine's own NSS key log line for the run, which Wireshark reads: CLIENT_RANDOM, then the master secret.</summary>
        public string KeyLogLine;
    }

    /// <summary>
    /// Builds the walk from one fixed teaching run on the course's built-in training key (KeyIds.ServerTls11Rsa, public in this source),
    /// never a learner's key. Pure: the run is two engines in memory with seeded randoms and a fixed date. Each step uses the engine's own
    /// functions, and the result is compared with the engine's key log line, so a walk that differs throws TLS11_WALK_DIVERGED.
    /// </summary>
    public static class Tls11KeyScheduleWalks
    {
        const string MasterLabel = "master secret", ExpansionLabel = "key expansion";
        const int ClientSeed = 1101, ServerSeed = 1102;
        static readonly byte[] Greeting = System.Text.Encoding.UTF8.GetBytes("hello from the old world\n");

        /// <summary>A date inside the training certificates, as lesson 7 uses.</summary>
        static readonly DateTime RunDate = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static string MasterSecretLabel { get { return MasterLabel; } }
        public static string KeyExpansionLabel { get { return ExpansionLabel; } }

        public static Tls11KeyScheduleWalk TeachingRun()
        {
            ITrainingKeySource keys = LabCredentials.BuiltInOnly();
            ITrainingKey serverKey = keys.Find(KeyIds.ServerTls11Rsa);
            Tls11Engine client = Engine(true, keys, ClientSeed);
            Tls11Engine server = Engine(false, keys, ServerSeed);
            List<byte> toServer = new List<byte>(), toClient = new List<byte>();
            Drive(client, server, toServer, toClient);

            Tls11KeyScheduleWalk w = new Tls11KeyScheduleWalk();
            w.Suite = Tls11CipherSuite.RsaAes128CbcSha.Name;
            w.ServerKeyId = KeyIds.ServerTls11Rsa;
            w.ServerPublicKey = serverKey.CopyPublic();
            byte[][] clientMessages = Tls11Recording.HandshakeMessages(toServer.ToArray()), serverMessages = Tls11Recording.HandshakeMessages(toClient.ToArray());
            w.ClientRandom = Tls11Messages.ReadClientHello(Reader(Find(clientMessages, Tls11Messages.ClientHello))).Random;
            w.ServerRandom = Tls11Messages.ReadServerHello(Reader(Find(serverMessages, Tls11Messages.ServerHello))).Random;
            w.EncryptedPremaster = Tls11Messages.ReadClientKeyExchange(Reader(Find(clientMessages, Tls11Messages.ClientKeyExchange)), Tls11CipherSuite.RsaAes128CbcSha);

            byte[] premaster;
            Require(Pkcs1.TryDecryptV15(Tls11RsaKeys.ReadPrivate(serverKey.CopyMaterial()), w.EncryptedPremaster, out premaster));
            w.Premaster = premaster;
            w.PremasterVersion = (premaster[0] << 8) | premaster[1];
            w.MasterSecret = Tls11Prf.MasterSecret(premaster, w.ClientRandom, w.ServerRandom);
            w.KeyBlock = Tls11Prf.Derive(w.MasterSecret, ExpansionLabel, new ByteWriter().Put(w.ServerRandom).Put(w.ClientRandom).ToArray(), 2 * (Tls11KeyBlock.MacSize + Tls11KeyBlock.KeySize));
            Tls11KeyBlock split = Tls11Prf.KeyBlock(w.MasterSecret, w.ClientRandom, w.ServerRandom);
            w.ClientMacKey = split.ClientMac;
            w.ServerMacKey = split.ServerMac;
            w.ClientKey = split.ClientKey;
            w.ServerKey = split.ServerKey;

            string[] lines = client.KeyLogLines;
            Require(lines.Length == 1 && Same(lines, server.KeyLogLines));
            w.KeyLogLine = lines[0];
            Require(w.KeyLogLine == "CLIENT_RANDOM " + Hex.Encode(w.ClientRandom) + " " + Hex.Encode(w.MasterSecret));
            Require(Hex.Encode(w.KeyBlock) == Hex.Encode(new ByteWriter().Put(w.ClientMacKey).Put(w.ServerMacKey).Put(w.ClientKey).Put(w.ServerKey).ToArray()));
            return w;
        }

        static Tls11Engine Engine(bool isClient, ITrainingKeySource keys, int seed)
        {
            string actor = isClient ? "client" : "server";
            Tls11Options o = new Tls11Options();
            o.Suite = Tls11CipherSuite.RsaAes128CbcSha;
            o.Random = new SeededRandom(seed);
            o.Stream = new TraceStream("walk/" + actor + "/tls11", "walk", "walk", null, actor, new FixedClock(0));
            if (isClient)
            {
                Tls11Training.TrustTrainingRoot(o, keys, RunDate);
                return Tls11Engine.CreateClient(o);
            }
            Tls11Training.UseTrainingServerKey(o, keys);
            return Tls11Engine.CreateServer(o);
        }

        /// <summary>
        /// The client sends one line, the server echoes it, and the client closes. Bytes pass in a plain loop, and each direction is kept,
        /// as a recorder on the wire would keep them.
        /// </summary>
        static void Drive(Tls11Engine client, Tls11Engine server, List<byte> toServerLog, List<byte> toClientLog)
        {
            server.Start();
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, Greeting, null));
            byte[] toServer = client.Start().Wire;
            for (int round = 0; toServer.Length > 0 && round < 16; round++)
            {
                toServerLog.AddRange(toServer);
                EngineOutput fromServer = server.Feed(toServer, 0, toServer.Length);
                List<byte> toClient = new List<byte>(fromServer.Wire);
                foreach (DeliveredChunk chunk in fromServer.App)
                    toClient.AddRange(server.Command(new EngineCommand(EngineCommandKind.Send, 0, chunk.Bytes, null)).Wire);
                if (toClient.Count == 0) break;
                toClientLog.AddRange(toClient);
                EngineOutput fromClient = client.Feed(toClient.ToArray(), 0, toClient.Count);
                List<byte> next = new List<byte>(fromClient.Wire);
                if (fromClient.App.Length > 0) next.AddRange(client.Command(EngineCommand.Close).Wire);
                toServer = next.ToArray();
            }
            Require(client.ReachedOpen && server.ReachedOpen);
        }

        static byte[] Find(byte[][] messages, int type)
        {
            byte[] found = Tls11Recording.Find(messages, type);
            if (found == null) throw Diverged("the run has no handshake message of type " + type);
            return found;
        }

        static ByteReader Reader(byte[] message) { return Tls11Recording.Reader(message); }

        static bool Same(string[] a, string[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static NetSecException Diverged(string detail)
        {
            return new NetSecException(NetSecError.Of(ErrorCodes.Tls11WalkDiverged, "The walk differs from the real TLS 1.1 key schedule: " + detail + "."));
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw Diverged("a step does not match the engine");
        }
    }
}
