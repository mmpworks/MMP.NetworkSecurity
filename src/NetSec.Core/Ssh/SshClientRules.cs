using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;
using NetSec.Pki;

namespace NetSec.Ssh
{
    /// <summary>The client table, rows ssh.c.* of docs/program-design.md section 2.6.</summary>
    internal static class SshClientRules
    {
        public const string Start = "Start";
        const string WaitVersion = "WaitVersion", WaitKexInit = "WaitKexInit", WaitKexReply = "WaitKexReply", WaitNewKeys = "WaitNewKeys";
        const string WaitService = "WaitService", WaitPkOk = "WaitPkOk", WaitAuth = "WaitAuth";

        const string ServiceUserauth = "ssh-userauth", ServiceConnection = "ssh-connection", MethodPublicKey = "publickey";

        public static readonly StepTable<SshSession> Table = Build();

        static StepTable<SshSession> Build()
        {
            string open = MachineStates.Open;
            List<StepRow<SshSession>> rows = new List<StepRow<SshSession>>();
            rows.Add(new StepRow<SshSession>("ssh.c.start", Start, InboundMessage.StartType, SendVersion, WaitVersion));
            rows.Add(new StepRow<SshSession>("ssh.c.version", WaitVersion, SshMsg.VersionLine, ReadVersion, WaitKexInit));
            rows.Add(new StepRow<SshSession>("ssh.c.kexinit", WaitKexInit, SshMsg.KexInit, ReadKexInit, WaitKexReply));
            rows.Add(new StepRow<SshSession>("ssh.c.kexreply", WaitKexReply, SshMsg.KexReply, ReadKexReply, WaitNewKeys));
            rows.Add(new StepRow<SshSession>("ssh.c.newkeys", WaitNewKeys, SshMsg.NewKeys, ReadNewKeys, WaitService));
            rows.Add(new StepRow<SshSession>("ssh.c.service", WaitService, SshMsg.ServiceAccept, ReadServiceAccept, WaitPkOk));
            rows.Add(new StepRow<SshSession>("ssh.c.auth-ok", WaitPkOk, SshMsg.UserauthPkOk, ReadPkOk, WaitAuth));
            rows.Add(new StepRow<SshSession>("ssh.c.auth-refused", WaitPkOk, SshMsg.UserauthFailure, Refused, WaitAuth));
            rows.Add(new StepRow<SshSession>("ssh.c.auth-refused", WaitAuth, SshMsg.UserauthFailure, Refused, open));
            rows.Add(new StepRow<SshSession>("ssh.c.auth", WaitAuth, SshMsg.UserauthSuccess, ReadSuccess, open));
            rows.Add(new StepRow<SshSession>("ssh.c.banner", WaitPkOk, SshMsg.UserauthBanner, Skip, WaitPkOk));
            rows.Add(new StepRow<SshSession>("ssh.c.banner", WaitAuth, SshMsg.UserauthBanner, Skip, WaitAuth));
            rows.Add(new StepRow<SshSession>("chan.confirm", open, SshMsg.ChannelConfirmation, ReadConfirmation, open));
            rows.Add(new StepRow<SshSession>("chan.refused", open, SshMsg.ChannelOpenFailure, ReadOpenFailure, open));
            rows.Add(new StepRow<SshSession>("chan.exec-ok", open, SshMsg.ChannelSuccess, ReadExecOk, open));
            rows.Add(new StepRow<SshSession>("chan.exec-refused", open, SshMsg.ChannelFailure, ReadExecRefused, open));
            rows.Add(new StepRow<SshSession>("chan.request", open, SshMsg.ChannelRequest, ReadChannelRequest, open));
            SshRows.AddConnection(rows, "ssh.c");
            SshRows.AddAnyTime(rows, "ssh.c", WaitKexInit, WaitKexReply, WaitNewKeys, WaitService, WaitPkOk, WaitAuth, open);
            return new StepTable<SshSession>(rows.ToArray());
        }

        static StepDecision Skip(SshSession s, InboundMessage m) { return StepDecision.Stay(); }

        static StepDecision SendVersion(SshSession s, InboundMessage m)
        {
            return StepDecision.Advance(s.VersionLineEffect());
        }

        static StepDecision ReadVersion(SshSession s, InboundMessage m)
        {
            StepDecision refused = SshVersionRule.Refuse(m.Body);
            if (refused != null) return refused;
            s.PeerVersion = m.Body;
            s.OurKexInit = SshKex.BuildKexInit(s);
            return StepDecision.Advance(Effect.Check(SshChecks.Version, SshCodes.Version), s.ClearPacket(SshNames.KexInit, s.OurKexInit));
        }

        static StepDecision ReadKexInit(SshSession s, InboundMessage m)
        {
            StepDecision refused = SshKex.RefuseKexInit(s, m.Body);
            if (refused != null) return refused;
            s.PeerKexInit = m.Body;
            s.EphemeralPrivate = SshKex.NewPrivate(s);
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Check(SshChecks.Algorithm, SshCodes.NoCommonAlg));
            effects.AddRange(SshKex.WeakNotes(s));
            effects.Add(Effect.Secret(s.Holder, SshKex.PrivateName, s.EphemeralPrivate));
            bool legacy = s.Algorithms.IsLegacy;
            s.ClientShare = legacy ? DhGroup14.Public(s.EphemeralPrivate) : X25519.MultBase(s.EphemeralPrivate);
            ByteWriter payload = new ByteWriter().U8(SshMsg.KexClientShare);
            if (legacy) payload.Mpint(s.ClientShare);
            else payload.Prefixed(s.ClientShare);
            effects.Add(s.ClearPacket(legacy ? SshNames.KexdhInit : SshNames.KexEcdhInit, payload.ToArray()));
            return StepDecision.Advance(effects.ToArray());
        }

        /// <summary>The order of the checks is the lesson: first whose key this is, then whether the secret is sound, then whether that key signed this exchange.</summary>
        static StepDecision ReadKexReply(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            byte[] hostBlob = r.Prefixed("hostKey", "key");
            byte[] serverShare = r.Prefixed("serverShare", "key");
            byte[] signature = r.Prefixed("exchangeSignature", "mac");

            SshHostKey key = SshHostKey.Parse(hostBlob);
            if (key.Algorithm != s.Algorithms.HostKey)
                return StepDecision.Fail(SshCodes.HostKeyBad, SshChecks.HostKeyShape, "the server sent a " + key.Algorithm + " key, and the suite names " + s.Algorithms.HostKey);

            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Note("ssh.hostkey.seen", key.Fingerprint()));
            StepDecision hostRefused = CheckKnownHost(s, key, effects);
            if (hostRefused != null) return hostRefused;

            byte[] k, h;
            if (s.Algorithms.IsLegacy)
            {
                k = DhGroup14.Shared(s.EphemeralPrivate, serverShare);
                h = SshExchange.Group14Hash(s.Algorithms.ExchangeHash, s.OurVersion, s.PeerVersion, s.OurKexInit, s.PeerKexInit, hostBlob, s.ClientShare, serverShare, k);
            }
            else
            {
                k = X25519.Mult(s.EphemeralPrivate, serverShare);
                if (SshExchange.IsAllZero(k))
                    return StepDecision.Fail(SshCodes.KexZeroSecret, SshChecks.ZeroSecret, "the server's share gives an all-zero secret, so anyone could compute the keys");
                effects.Add(Effect.Check(SshChecks.ZeroSecret, SshCodes.KexZeroSecret));
                h = SshExchange.Curve25519Hash(s.Algorithms.ExchangeHash, s.OurVersion, s.PeerVersion, s.OurKexInit, s.PeerKexInit, hostBlob, s.ClientShare, serverShare, k);
            }
            if (!key.Verify(h, signature))
                return StepDecision.Fail(SshCodes.ExchangeSignature, SshChecks.ExchangeSignature, "the host key did not sign this exchange");

            SshKex.AddSecrets(s, effects, k, h);
            effects.Add(Effect.Check(SshChecks.ExchangeSignature, SshCodes.ExchangeSignature));
            effects.Add(s.ClearPacket(SshNames.NewKeys, SshKex.NewKeysPayload()));
            effects.Add(SshKex.Install(s, Direction.Outbound));
            effects.Add(s.SealedPacket(SshNames.ServiceRequest, new ByteWriter().U8(SshMsg.ServiceRequest).Prefixed(ServiceUserauth).ToArray()));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision CheckKnownHost(SshSession s, SshHostKey key, List<StepEffect> effects)
        {
            switch (SshKnownHosts.Check(s.Client.KnownHosts, s.Client.Host, s.Client.Port, key.Blob))
            {
                case HostKeyMatch.Match:
                    effects.Add(Effect.Check(SshChecks.KnownHosts, SshCodes.HostKeyChanged));
                    return null;
                case HostKeyMatch.Changed:
                    return StepDecision.Fail(SshCodes.HostKeyChanged, SshChecks.KnownHosts, "the server's host key is not the one pinned for " + s.Client.Host + ". It offered " + key.Fingerprint());
                default:
                    if (!s.Client.TrustFirstUse)
                        return StepDecision.Fail(SshCodes.HostKeyUnknown, SshChecks.KnownHosts, "no known_hosts line names " + s.Client.Host + ". It offered " + key.Fingerprint());
                    effects.Add(Effect.Note("ssh.hostkey.first-use", key.Fingerprint()));
                    return null;
            }
        }

        static StepDecision ReadNewKeys(SshSession s, InboundMessage m)
        {
            return StepDecision.Advance(SshKex.Install(s, Direction.Inbound));
        }

        /// <summary>The query asks whether the server takes this key, before the client spends a signature on it.</summary>
        static StepDecision ReadServiceAccept(SshSession s, InboundMessage m)
        {
            byte[] blob = OpenSshKeyFile.Ed25519Blob(s.Client.UserKey.CopyPublic());
            byte[] payload = UserauthBody(s.Client.User, 0, blob).ToArray();
            return StepDecision.Advance(s.SealedPacket(SshNames.UserauthQuery, payload));
        }

        static ByteWriter UserauthBody(string user, int signedFlag, byte[] blob)
        {
            return new ByteWriter().U8(SshMsg.UserauthRequest).Prefixed(user).Prefixed(ServiceConnection).Prefixed(MethodPublicKey)
                .U8(signedFlag).Prefixed(OpenSshKeyFile.Ed25519Name).Prefixed(blob);
        }

        /// <summary>RFC 4252 section 7: the signature covers the session id and this whole request, so it cannot be replayed into another session.</summary>
        static StepDecision ReadPkOk(SshSession s, InboundMessage m)
        {
            byte[] blob = OpenSshKeyFile.Ed25519Blob(s.Client.UserKey.CopyPublic());
            byte[] request = UserauthBody(s.Client.User, 1, blob).ToArray();
            byte[] signed = new ByteWriter().Prefixed(s.SessionId).Put(request).ToArray();
            byte[] seed = (s.Client.SignWith ?? s.Client.UserKey).CopyMaterial();
            byte[] signatureBlob = new ByteWriter().Prefixed(OpenSshKeyFile.Ed25519Name).Prefixed(Ed25519.Sign(seed, signed)).ToArray();
            byte[] payload = new ByteWriter().Put(request).Prefixed(signatureBlob).ToArray();
            return StepDecision.Advance(s.SealedPacket(SshNames.UserauthSigned, payload));
        }

        static StepDecision Refused(SshSession s, InboundMessage m)
        {
            return StepDecision.Fail(SshCodes.AuthRefused, SshChecks.AuthAccepted, "the server refused the key for user " + s.Client.User);
        }

        static StepDecision ReadSuccess(SshSession s, InboundMessage m)
        {
            s.IsOpen = true;
            return StepDecision.Advance(Effect.Check(SshChecks.AuthAccepted, SshCodes.AuthRefused), Effect.Deliver(SshControl.Channel, SshControl.Encode(SshControl.Authenticated, 0, "")));
        }

        // ---------------------------------------------------------------- channels the client opened

        static StepDecision ReadConfirmation(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            StepDecision refused;
            SshChannel channel = SshRows.Find(s, r.U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            channel.Remote = (int)r.U32("sender", "id");
            channel.PeerWindow = r.U32("window", "length");
            channel.PeerMaxPacket = r.U32("maxPacket", "length");
            channel.Confirmed = true;

            List<StepEffect> effects = new List<StepEffect>();
            if (channel.ExecCommand != null)
                effects.Add(s.SealedPacket(SshNames.ChannelRequestExec, new ByteWriter().U8(SshMsg.ChannelRequest).U32(channel.Remote).Prefixed("exec").U8(1).Prefixed(channel.ExecCommand).ToArray()));
            else
            {
                effects.Add(Effect.Check(SshChecks.TunnelAllowList, SshCodes.TunnelRefused));
                effects.Add(Effect.Deliver(SshControl.Channel, SshControl.Encode(SshControl.ChannelReady, channel.Local, "")));
            }
            SshRows.Drain(s, channel, effects);
            return StepDecision.Stay(effects.ToArray());
        }

        /// <summary>The lab ends the session on a refused tunnel, so the refusal has one name for the learner.</summary>
        static StepDecision ReadOpenFailure(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            StepDecision refused;
            SshChannel channel = SshRows.Find(s, r.U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            string description = "reason " + r.U32("reason", "id") + ": " + SshFields.Text(r.Prefixed("description", "data"));
            return StepDecision.Fail(SshCodes.TunnelRefused, SshChecks.TunnelAllowList, "the server refused channel " + channel.Local + ", " + description);
        }

        static StepDecision ReadExecOk(SshSession s, InboundMessage m)
        {
            StepDecision refused;
            SshChannel channel = SshRows.Find(s, new ByteReader(m.Body, 1, m.Body.Length - 1, true).U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            return StepDecision.Stay(Effect.Check(SshChecks.ExecAccepted, SshCodes.ExecRefused), Effect.Deliver(SshControl.Channel, SshControl.Encode(SshControl.ChannelReady, channel.Local, "")));
        }

        static StepDecision ReadExecRefused(SshSession s, InboundMessage m)
        {
            return StepDecision.Fail(SshCodes.ExecRefused, SshChecks.ExecAccepted, "the server refused the command");
        }

        /// <summary>The server's exit status has no answer. Any other request that wants an answer gets a no.</summary>
        static StepDecision ReadChannelRequest(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            StepDecision refused;
            SshChannel channel = SshRows.Find(s, r.U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            string request = SshFields.Text(r.Prefixed("request", "id"));
            bool wantReply = r.U8("wantReply", "data") != 0;
            if (request == "exit-status") return StepDecision.Stay(Effect.Note("ssh.exec.exit", r.U32("status", "data").ToString()));
            if (!wantReply) return StepDecision.Stay();
            return StepDecision.Stay(s.SealedPacket(SshNames.ChannelFailure, new ByteWriter().U8(SshMsg.ChannelFailure).U32(channel.Remote).ToArray()));
        }
    }

    internal static class SshVersionRule
    {
        const string Modern = "SSH-2.0-", Compatible = "SSH-1.99-";

        /// <summary>RFC 4253 section 5.1: 1.99 means a peer that also speaks 2.0. Null means this line passes.</summary>
        public static StepDecision Refuse(byte[] line)
        {
            string text = SshFields.Text(line);
            if (text.StartsWith(Modern) || text.StartsWith(Compatible)) return null;
            return StepDecision.Fail(SshCodes.Version, SshChecks.Version, "the peer's version line reads '" + text + "', and this lab speaks SSH 2.0");
        }
    }
}
