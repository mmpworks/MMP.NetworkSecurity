using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Tls11;

namespace NetSec.Labs
{
    /// <summary>
    /// Keeps the wire bytes of one TLS 1.1 run, as an attacker who records the network would. It changes nothing: it passes each call to the
    /// lab's own plan, if any, and keeps the bytes that leave. Two pumps call it from their own threads, so the lists sit behind a lock.
    /// </summary>
    public sealed class RecordingTap : ITamperHook
    {
        readonly ITamperHook _inner;
        readonly object _gate = new object();
        readonly List<byte> _toServer = new List<byte>(), _toClient = new List<byte>();

        public RecordingTap(ITamperHook inner) { _inner = inner; }

        public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
        {
            TamperResult result = _inner == null ? TamperResult.Unchanged : _inner.Apply(point, streamId, streamSeq, message, bytes);
            if (point != TamperPoint.Wire) return result;
            byte[] sent = result != null && result.Bytes != null ? result.Bytes : bytes;
            lock (_gate) (streamId.IndexOf("/client/") >= 0 ? _toServer : _toClient).AddRange(sent);
            return result;
        }

        public byte[] ClientToServer { get { lock (_gate) return _toServer.ToArray(); } }

        public byte[] ServerToClient { get { lock (_gate) return _toClient.ToArray(); } }
    }

    /// <summary>What a stolen server key gets from one recorded run. Opened is false when no stored key made the session keys (ECDHE).</summary>
    public sealed class RecordingOpened
    {
        public string Suite;
        public bool Opened;
        public byte[] Premaster, MasterSecret, ClientPlaintext;
        public Tls11KeyBlock Keys;
    }

    /// <summary>Reads a recorded TLS 1.1 run from its wire bytes alone. Pure. The key schedule walk and the decrypt-a-recording attack share it.</summary>
    public static class Tls11Recording
    {
        /// <summary>The clear handshake messages in one direction: the handshake records before the first ChangeCipherSpec.</summary>
        public static byte[][] HandshakeMessages(byte[] wire)
        {
            Tls11RecordReader records = new Tls11RecordReader();
            records.Append(wire, 0, wire.Length);
            Tls11HandshakeReader handshakes = new Tls11HandshakeReader();
            List<byte[]> messages = new List<byte[]>();
            for (Tls11RawRecord r = records.Next(); r != null && r.Type != Tls11Content.ChangeCipherSpec; r = records.Next())
            {
                if (r.Type != Tls11Content.Handshake) continue;
                handshakes.Append(r.Payload);
                for (byte[] m = handshakes.Next(); m != null; m = handshakes.Next()) messages.Add(m);
            }
            return messages.ToArray();
        }

        /// <summary>The records in one direction after its ChangeCipherSpec, in order. Each one is sealed with that direction's keys.</summary>
        public static Tls11RawRecord[] ProtectedRecords(byte[] wire)
        {
            Tls11RecordReader records = new Tls11RecordReader();
            records.Append(wire, 0, wire.Length);
            List<Tls11RawRecord> sealedRecords = new List<Tls11RawRecord>();
            bool afterCcs = false;
            for (Tls11RawRecord r = records.Next(); r != null; r = records.Next())
            {
                if (afterCcs) sealedRecords.Add(r);
                else if (r.Type == Tls11Content.ChangeCipherSpec) afterCcs = true;
            }
            return sealedRecords.ToArray();
        }

        /// <summary>The first message of a type, or null.</summary>
        public static byte[] Find(byte[][] messages, int type)
        {
            foreach (byte[] m in messages) if (m[0] == type) return m;
            return null;
        }

        public static ByteReader Reader(byte[] message) { return new ByteReader(message, 0, message.Length, true); }

        /// <summary>
        /// Plays the attacker who recorded the run and later stole the server's RSA key. On the RSA suite, the key decrypts the pre-master,
        /// and the pre-master and the two randoms from the recording give every session key, so the client's records open. On the ECDHE suite
        /// the pre-master came from two X25519 shares that neither side stored, so the stolen key opens nothing.
        /// </summary>
        public static RecordingOpened Open(byte[] clientToServer, byte[] serverToClient, RsaPrivate stolenServerKey)
        {
            byte[][] client = HandshakeMessages(clientToServer), server = HandshakeMessages(serverToClient);
            byte[] clientHello = Find(client, Tls11Messages.ClientHello), serverHello = Find(server, Tls11Messages.ServerHello);
            byte[] keyExchange = Find(client, Tls11Messages.ClientKeyExchange);
            if (clientHello == null || serverHello == null || keyExchange == null)
                throw new NetSecException(NetSecError.Of(Tls11Codes.EngineFault, "the recording holds no full handshake"));
            Tls11Hello sh = Tls11Messages.ReadServerHello(Reader(serverHello));
            Tls11CipherSuite suite = sh.Suites[0] == Tls11CipherSuite.EcdheRsaAes128CbcSha.Code ? Tls11CipherSuite.EcdheRsaAes128CbcSha : Tls11CipherSuite.RsaAes128CbcSha;
            RecordingOpened opened = new RecordingOpened();
            opened.Suite = suite.Name;
            if (suite.KeyExchange != Tls11KeyExchange.Rsa) return opened;

            byte[] premaster;
            if (!Pkcs1.TryDecryptV15(stolenServerKey, Tls11Messages.ReadClientKeyExchange(Reader(keyExchange), suite), out premaster)) return opened;
            byte[] clientRandom = Tls11Messages.ReadClientHello(Reader(clientHello)).Random;
            opened.Premaster = premaster;
            opened.MasterSecret = Tls11Prf.MasterSecret(premaster, clientRandom, sh.Random);
            opened.Keys = Tls11Prf.KeyBlock(opened.MasterSecret, clientRandom, sh.Random);
            opened.ClientPlaintext = ApplicationData(ProtectedRecords(clientToServer), opened.Keys);
            opened.Opened = opened.ClientPlaintext != null;
            return opened;
        }

        /// <summary>The client's application data, joined, or null when a record fails to open. The record cipher counts sequence numbers from the client's Finished.</summary>
        static byte[] ApplicationData(Tls11RawRecord[] records, Tls11KeyBlock keys)
        {
            Tls11RecordCipher cipher = new Tls11RecordCipher(keys.ClientKey, keys.ClientMac, null);
            ByteWriter data = new ByteWriter();
            foreach (Tls11RawRecord r in records)
            {
                byte[] content;
                if (!cipher.TryOpen(r.Type, r.Version, r.Payload, out content)) return null;
                if (r.Type == Tls11Content.ApplicationData) data.Put(content);
            }
            return data.ToArray();
        }
    }
}
