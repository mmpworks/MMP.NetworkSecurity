using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Ssh
{
    public sealed class SshClientOptions
    {
        public SshAlgorithms Algorithms;
        public IRandomSource Random;
        public string Host;
        public int Port;

        /// <summary>known_hosts text. The engine holds no file, so the caller reads it.</summary>
        public string KnownHosts;

        /// <summary>
        /// Off by default, so a missing pin ends in SSH_HOST_KEY_UNKNOWN. On, a host with no known_hosts line is accepted and ssh.hostkey.first-use
        /// shows it. That connect has no proof at all. The caller must store the line the session returns, or every connect is a first use.
        /// </summary>
        public bool TrustFirstUse;

        public string User;
        public ITrainingKey UserKey;

        /// <summary>Stands in for an old peer: this side leaves the strict KEX marker out of its KexInit.</summary>
        public bool NoStrictKex;

        /// <summary>The attack hook: sign with this key while naming UserKey. Null signs with UserKey.</summary>
        public ITrainingKey SignWith;
    }

    public sealed class SshServerOptions
    {
        public SshAlgorithms Algorithms;
        public IRandomSource Random;
        public ITrainingKey HostKey;
        public byte[][] AuthorizedKeys;

        /// <summary>Decides each direct-tcpip target. Null refuses every tunnel.</summary>
        public Func<string, int, bool> AllowTunnel;

        /// <summary>Stands in for an old peer: this side leaves the strict KEX marker out of its KexInit.</summary>
        public bool NoStrictKex;

        /// <summary>The attack hook: send an all-zero X25519 share.</summary>
        public bool SendZeroShare;
    }

    /// <summary>One open channel, as RFC 4254 section 5 counts it. Each side keeps its own numbers and its own window.</summary>
    public sealed class SshChannel
    {
        public int Local, Remote;
        public long PeerWindow, PeerMaxPacket, OurWindow;
        public string ExecCommand;
        public long ReadSinceGrant;
        public bool Confirmed, SentEof, SentClose, CloseWhenDrained, WaitingForWindow, IsSession, ExecDone;
        public readonly List<byte[]> Queue = new List<byte[]>();
    }

    /// <summary>A control note from the engine to the code above it, sent in the app chunk stream on a channel number no real channel uses.</summary>
    public static class SshControl
    {
        public const int Channel = -1;
        public const int Authenticated = 1, ChannelReady = 2, TunnelRequested = 3, PeerEof = 4, HostKeyLearned = 5, WindowFull = 6, WindowOpen = 7, ChannelRefused = 8;

        public static byte[] Encode(int kind, int channel, string text)
        {
            return new ByteWriter().U8(kind).U32(channel).Put(Encoding.UTF8.GetBytes(text)).ToArray();
        }

        public static int Kind(byte[] note) { return note[0]; }

        public static int ChannelOf(byte[] note)
        {
            return (note[1] << 24) | (note[2] << 16) | (note[3] << 8) | note[4];
        }

        public static string Text(byte[] note)
        {
            return Encoding.UTF8.GetString(note, 5, note.Length - 5);
        }
    }

    /// <summary>
    /// What the SSH rules read and keep. A rule changes only this object and returns all else as effects. One more thing happens outside
    /// the rule's return value: Draw takes bytes from the side's random stream, in rule order, as in the labs of lessons 1 to 3.
    /// </summary>
    public sealed class SshSession : IMachineSession
    {
        const string SoftwareVersion = "SSH-2.0-MMPNetSec_training";
        const int EncKeySize = 16;

        public readonly SshAlgorithms Algorithms;
        public readonly IRandomSource Random;
        public readonly SshClientOptions Client;
        public readonly SshServerOptions Server;
        public readonly string Holder;
        public readonly SshPacketReader Reader = new SshPacketReader();
        readonly SshPacketWriter _writer = new SshPacketWriter();
        public readonly Dictionary<int, SshChannel> Channels = new Dictionary<int, SshChannel>();

        public readonly byte[] OurVersion = Encoding.UTF8.GetBytes(SoftwareVersion);
        public byte[] PeerVersion, OurKexInit, PeerKexInit;
        public byte[] EphemeralPrivate, ClientShare;
        public byte[] SessionId;
        public SshKeyBlock Keys;
        public EngineCommand Pending;
        public string User;
        public int NextLocalChannel, AuthRequests;
        public bool PeerVersionSeen, ReaderArmed, IsOpen, StrictKex, MacPassShown;

        public SshSession(SshClientOptions client, string holder)
        {
            Client = client; Algorithms = client.Algorithms; Random = client.Random; Holder = holder;
        }

        public SshSession(SshServerOptions server, string holder)
        {
            Server = server; Algorithms = server.Algorithms; Random = server.Random; Holder = holder;
        }

        public bool IsClient { get { return Client != null; } }
        public bool OffersStrictKex { get { return IsClient ? !Client.NoStrictKex : !Server.NoStrictKex; } }

        public string SentType { get { return "ssh.message.sent"; } }
        public string ReceivedType { get { return "ssh.message.received"; } }
        public void Absorb(byte[] message) { }
        public void Remember(string name, byte[] value) { }
        public byte[] PlainOf(InboundMessage message) { return message.Body; }
        public byte[] Protect(string message, byte[] body) { return _writer.Seal(body, Random); }

        /// <summary>The key argument holds the cipher key, then the MAC key. The interpreter's effect has one slot for key bytes.</summary>
        public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv)
        {
            byte[] encKey = new byte[EncKeySize];
            byte[] macKey = new byte[key.Length - EncKeySize];
            Buffer.BlockCopy(key, 0, encKey, 0, EncKeySize);
            Buffer.BlockCopy(key, EncKeySize, macKey, 0, macKey.Length);
            bool encrypt = direction == Direction.Outbound;
            ISshCipher cipher = SshPacketForm.CipherFor(Algorithms.Cipher, encKey, iv, encrypt);
            if (encrypt)
            {
                _writer.Arm(cipher, macKey, Algorithms.MacHash);
                if (StrictKex) _writer.ResetSequence();
                return;
            }
            Reader.Arm(cipher, macKey, Algorithms.MacHash, Algorithms.MacSize);
            if (StrictKex) Reader.ResetSequence();
            ReaderArmed = true;
        }

        public byte[] Draw(int count)
        {
            byte[] bytes = new byte[count];
            Random.Fill(bytes, 0, count);
            return bytes;
        }

        public StepEffect ClearPacket(string name, byte[] payload)
        {
            int padding = SshPacketForm.PaddingFor(payload.Length, SshPacketForm.ClearBlock);
            return Effect.Send(name, payload, SshFields.Clear(payload, padding, Algorithms.IsLegacy));
        }

        public StepEffect SealedPacket(string name, byte[] payload)
        {
            return Effect.Send(name, payload, SshFields.Protected(payload.Length, Algorithms.MacSize));
        }

        public StepEffect VersionLineEffect()
        {
            byte[] wire = new ByteWriter().Put(OurVersion).U8(13).U8(10).ToArray();
            return Effect.SendProtected(SshNames.VersionLine, OurVersion, wire, SshFields.VersionLine(wire.Length));
        }
    }
}
