using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Machine;

namespace NetSec.Ssh
{
    /// <summary>The steps of the key exchange that both roles run the same way.</summary>
    internal static class SshKex
    {
        const int CookieSize = 16;
        const int X25519PrivateSize = 32;

        /// <summary>The design's DH exponent: 512 random bits. It cuts a device's work about 4 times compared with a full-size exponent.</summary>
        public const int DhPrivateSize = 64;

        const string None = "none";

        // The pre-standard names of draft-miller-sshm-strict-kex section 3.1. OpenSSH 9.6 on and Go x/crypto use these, and both sides must offer them.
        const string StrictClient = "kex-strict-c-v00@openssh.com", StrictServer = "kex-strict-s-v00@openssh.com";

        public const string PrivateName = "ssh.ephemeral.private", SharedName = "ssh.shared.K", HashName = "ssh.exchange.H", SessionName = "ssh.session.id";

        public static byte[] BuildKexInit(SshSession s)
        {
            SshAlgorithms a = s.Algorithms;
            return new ByteWriter().U8(SshMsg.KexInit).Put(s.Draw(CookieSize))
                .Prefixed(!s.OffersStrictKex ? a.Kex : a.Kex + "," + (s.IsClient ? StrictClient : StrictServer)).Prefixed(a.HostKey)
                .Prefixed(a.Cipher).Prefixed(a.Cipher)
                .Prefixed(a.Mac).Prefixed(a.Mac)
                .Prefixed(None).Prefixed(None)
                .Prefixed(new byte[0]).Prefixed(new byte[0])
                .U8(0).U32(0).ToArray();
        }

        /// <summary>
        /// Null when the peer's list holds our one name in each slot. A lab offers one name per slot, so the RFC's "first client name the
        /// server also has" comes down to this. The peer's guess flag is refused, because the lab never guesses and never skips a packet.
        /// </summary>
        public static StepDecision RefuseKexInit(SshSession s, byte[] peerKexInit)
        {
            ByteReader r = new ByteReader(peerKexInit, 1, peerKexInit.Length - 1, true);
            SshAlgorithms a = s.Algorithms;
            r.Take("cookie", "random", CookieSize);
            string[] want = { a.Kex, a.HostKey, a.Cipher, a.Cipher, a.Mac, a.Mac, None, None };
            for (int i = 0; i < want.Length; i++)
            {
                byte[] list = r.Prefixed("list", "data");
                if (!SshExchange.ListHas(list, want[i]))
                    return StepDecision.Fail(SshCodes.NoCommonAlg, SshChecks.Algorithm, "the peer does not list " + want[i]);
                if (i == 0) s.StrictKex = s.OffersStrictKex && SshExchange.ListHas(list, s.IsClient ? StrictServer : StrictClient);
            }
            r.Prefixed("languages", "data");
            r.Prefixed("languages", "data");
            if (r.U8("guess", "data") != 0)
                return StepDecision.Fail(SshCodes.NoCommonAlg, SshChecks.Algorithm, "the peer sent a guessed key exchange packet, and this lab takes none");
            if (s.StrictKex && s.Reader.Sequence != 1)
                return StepDecision.Fail(SshCodes.KexStrict, SshChecks.StrictKex, "strict KEX needs KexInit first, and " + (s.Reader.Sequence - 1) + " packets came before it");
            return null;
        }

        /// <summary>
        /// Off when the peer does not offer it, because an old device must still connect. The Terrapin prefix attack (CVE-2023-48795) still fails then on
        /// these two suites: the MAC covers the plain text, and a deleted packet moves the cipher stream. Adding chacha20-poly1305 or an -etm MAC would need it on.
        /// </summary>
        public static StepEffect StrictNote(SshSession s)
        {
            return Effect.Note("ssh.kex.strict", s.StrictKex ? "on" : "off");
        }

        public static StepEffect[] WeakNotes(SshSession s)
        {
            if (!s.Algorithms.IsLegacy) return new StepEffect[0];
            return new StepEffect[]
            {
                Effect.Note("ssh.weak.exchange-hash", "diffie-hellman-group14-sha1 builds its exchange hash with SHA-1, which has known collision attacks."),
                Effect.Note("ssh.weak.host-signature", "ssh-rsa signs with SHA-1, so OpenSSH turned it off by default in version 8.8."),
                Effect.Note("ssh.weak.cipher-mode", "aes128-cbc with a MAC over the plain text has a published plaintext recovery attack (Albrecht, Paterson and Watson, 2009)."),
            };
        }

        public static byte[] NewPrivate(SshSession s)
        {
            return s.Draw(s.Algorithms.IsLegacy ? DhPrivateSize : X25519PrivateSize);
        }

        /// <summary>Records K, H and the session id, and derives the six key values. The first H is the session id for the whole session.</summary>
        public static void AddSecrets(SshSession s, List<StepEffect> effects, byte[] k, byte[] h)
        {
            bool first = s.SessionId == null;
            if (first) s.SessionId = h;
            SshKeyBlock keys = SshExchange.DeriveKeys(s.Algorithms.ExchangeHash, k, h, s.SessionId, s.Algorithms.MacSize);
            s.Keys = keys;
            effects.Add(Effect.Secret(s.Holder, SharedName, k, PrivateName));
            effects.Add(Effect.Secret(s.Holder, HashName, h, SharedName));
            if (first) effects.Add(Effect.Secret(s.Holder, SessionName, h, HashName));
            AddKey(s, effects, "ssh.iv.c2s", keys.IvC2S);
            AddKey(s, effects, "ssh.iv.s2c", keys.IvS2C);
            AddKey(s, effects, "ssh.key.c2s", keys.KeyC2S);
            AddKey(s, effects, "ssh.key.s2c", keys.KeyS2C);
            AddKey(s, effects, "ssh.mac.c2s", keys.MacC2S);
            AddKey(s, effects, "ssh.mac.s2c", keys.MacS2C);
        }

        static void AddKey(SshSession s, List<StepEffect> effects, string name, byte[] value)
        {
            effects.Add(Effect.Secret(s.Holder, name, value, SharedName, HashName, SessionName));
        }

        /// <summary>A side's sending keys go on right after its NewKeys. Its receiving keys wait for the peer's NewKeys.</summary>
        public static StepEffect Install(SshSession s, Direction direction)
        {
            SshKeyBlock k = s.Keys;
            bool clientToServer = (direction == Direction.Outbound) == s.IsClient;
            byte[] key = clientToServer ? k.KeyC2S : k.KeyS2C;
            byte[] mac = clientToServer ? k.MacC2S : k.MacS2C;
            byte[] iv = clientToServer ? k.IvC2S : k.IvS2C;
            byte[] both = new ByteWriter().Put(key).Put(mac).ToArray();
            return Effect.InstallKeys(direction, s.Algorithms.CipherAndMac + (clientToServer ? ",c2s" : ",s2c"), both, iv);
        }

        public static byte[] NewKeysPayload() { return new byte[] { (byte)SshMsg.NewKeys }; }
    }
}
