using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Machine;
using NetSec.Pki;

namespace NetSec.Ssh
{
    /// <summary>
    /// The server table, rows ssh.s.*. It mirrors the client. Our SSH server starts no process: exec answers from a fixed table, and a
    /// tunnel opens only when the allow list says yes.
    /// </summary>
    internal static class SshServerRules
    {
        public const string Start = "Start";
        const string WaitVersion = "WaitVersion", WaitKexInit = "WaitKexInit", WaitKexShare = "WaitKexShare", WaitNewKeys = "WaitNewKeys";
        const string WaitService = "WaitService", WaitAuth = "WaitAuth";

        const string ServiceUserauth = "ssh-userauth", ServiceConnection = "ssh-connection", MethodPublicKey = "publickey";
        const int X25519Size = 32;
        const int OpenAdministrativelyProhibited = 1, OpenUnknownType = 3, OpenResourceShortage = 4;

        /// <summary>Counts each request: a normal login takes 3 (none, query, signed). A query also answers "is this key allowed", so queries count too.</summary>
        const int MaxAuthRequests = 10;

        public static readonly StepTable<SshSession> Table = Build();

        static StepTable<SshSession> Build()
        {
            string open = MachineStates.Open;
            List<StepRow<SshSession>> rows = new List<StepRow<SshSession>>();
            rows.Add(new StepRow<SshSession>("ssh.s.start", Start, InboundMessage.StartType, SendVersion, WaitVersion));
            rows.Add(new StepRow<SshSession>("ssh.s.version", WaitVersion, SshMsg.VersionLine, ReadVersion, WaitKexInit));
            rows.Add(new StepRow<SshSession>("ssh.s.kexinit", WaitKexInit, SshMsg.KexInit, ReadKexInit, WaitKexShare));
            rows.Add(new StepRow<SshSession>("ssh.s.kexshare", WaitKexShare, SshMsg.KexClientShare, ReadKexShare, WaitNewKeys));
            rows.Add(new StepRow<SshSession>("ssh.s.newkeys", WaitNewKeys, SshMsg.NewKeys, ReadNewKeys, WaitService));
            rows.Add(new StepRow<SshSession>("ssh.s.service", WaitService, SshMsg.ServiceRequest, ReadServiceRequest, WaitAuth));
            rows.Add(new StepRow<SshSession>("ssh.s.auth", WaitAuth, SshMsg.UserauthRequest, ReadUserauth, open));
            rows.Add(new StepRow<SshSession>("chan.open", open, SshMsg.ChannelOpen, ReadChannelOpen, open));
            rows.Add(new StepRow<SshSession>("chan.request", open, SshMsg.ChannelRequest, ReadChannelRequest, open));
            SshRows.AddConnection(rows, "ssh.s");
            SshRows.AddAnyTime(rows, "ssh.s", WaitKexInit, WaitKexShare, WaitNewKeys, WaitService, WaitAuth, open);
            return new StepTable<SshSession>(rows.ToArray());
        }

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
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Check(SshChecks.Algorithm, SshCodes.NoCommonAlg));
            effects.Add(SshKex.StrictNote(s));
            effects.AddRange(SshKex.WeakNotes(s));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision ReadKexShare(SshSession s, InboundMessage m)
        {
            byte[] clientShare = new ByteReader(m.Body, 1, m.Body.Length - 1, true).Prefixed("clientShare", "key");
            s.EphemeralPrivate = SshKex.NewPrivate(s);
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Secret(s.Holder, SshKex.PrivateName, s.EphemeralPrivate));

            SshHostSigner signer = new SshHostSigner(s.Server.HostKey);
            byte[] serverShare, k, h;
            ByteWriter payload = new ByteWriter().U8(SshMsg.KexReply).Prefixed(signer.Blob);
            if (s.Algorithms.IsLegacy)
            {
                serverShare = DhGroup14.Public(s.EphemeralPrivate);
                k = DhGroup14.Shared(s.EphemeralPrivate, clientShare);
                h = SshExchange.Group14Hash(s.Algorithms.ExchangeHash, s.PeerVersion, s.OurVersion, s.PeerKexInit, s.OurKexInit, signer.Blob, clientShare, serverShare, k);
                payload.Mpint(serverShare);
            }
            else
            {
                k = X25519.Mult(s.EphemeralPrivate, clientShare);
                if (SshExchange.IsAllZero(k))
                    return StepDecision.Fail(SshCodes.KexZeroSecret, SshChecks.ZeroSecret, "the client's share gives an all-zero secret, so anyone could compute the keys");
                effects.Add(Effect.Check(SshChecks.ZeroSecret, SshCodes.KexZeroSecret));
                serverShare = s.Server.SendZeroShare ? new byte[X25519Size] : X25519.MultBase(s.EphemeralPrivate);
                h = SshExchange.Curve25519Hash(s.Algorithms.ExchangeHash, s.PeerVersion, s.OurVersion, s.PeerKexInit, s.OurKexInit, signer.Blob, clientShare, serverShare, k);
                payload.Prefixed(serverShare);
            }
            payload.Prefixed(signer.Sign(h));

            SshKex.AddSecrets(s, effects, k, h);
            effects.Add(s.ClearPacket(s.Algorithms.IsLegacy ? SshNames.KexdhReply : SshNames.KexEcdhReply, payload.ToArray()));
            effects.Add(s.ClearPacket(SshNames.NewKeys, SshKex.NewKeysPayload()));
            effects.Add(SshKex.Install(s, Direction.Outbound));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision ReadNewKeys(SshSession s, InboundMessage m)
        {
            return StepDecision.Advance(SshKex.Install(s, Direction.Inbound));
        }

        static StepDecision ReadServiceRequest(SshSession s, InboundMessage m)
        {
            string service = SshFields.Text(new ByteReader(m.Body, 1, m.Body.Length - 1, true).Prefixed("service", "id"));
            if (service != ServiceUserauth)
                return StepDecision.Fail(SshCodes.AuthRefused, SshChecks.AuthAccepted, "the client asked for service '" + service + "'");
            return StepDecision.Advance(s.SealedPacket(SshNames.ServiceAccept, new ByteWriter().U8(SshMsg.ServiceAccept).Prefixed(ServiceUserauth).ToArray()));
        }

        /// <summary>
        /// Three answers. A method or key this server does not take gets a failure, and the client may try again. A query for an allowed key
        /// gets PkOk. A signed request gets verified, and a bad signature ends the session with a named check, so the learner sees the catch.
        /// </summary>
        static StepDecision ReadUserauth(SshSession s, InboundMessage m)
        {
            if (++s.AuthRequests > MaxAuthRequests)
                return StepDecision.Fail(SshCodes.AuthTries, SshChecks.AuthTries, "the client sent " + s.AuthRequests + " userauth requests, and this server takes " + MaxAuthRequests);
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            string user = SshFields.Text(r.Prefixed("user", "id"));
            string service = SshFields.Text(r.Prefixed("service", "id"));
            string method = SshFields.Text(r.Prefixed("method", "id"));
            if (service != ServiceConnection || method != MethodPublicKey) return StepDecision.Stay(Failure(s));

            bool signed = r.U8("signed", "data") != 0;
            string algorithm = SshFields.Text(r.Prefixed("algorithm", "id"));
            byte[] blob = r.Prefixed("key", "key");
            if (algorithm != SshKeyBlob.Ed25519Name || !IsAuthorized(s, blob)) return StepDecision.Stay(Failure(s));
            if (!signed)
                return StepDecision.Stay(s.SealedPacket(SshNames.UserauthPkOk, new ByteWriter().U8(SshMsg.UserauthPkOk).Prefixed(algorithm).Prefixed(blob).ToArray()));

            byte[] signature = r.Prefixed("signature", "mac");
            int requestLength = m.Body.Length - 4 - signature.Length;
            byte[] request = new byte[requestLength];
            System.Buffer.BlockCopy(m.Body, 0, request, 0, requestLength);
            byte[] message = new ByteWriter().Prefixed(s.SessionId).Put(request).ToArray();
            if (!SshHostKey.Parse(blob).Verify(message, signature))
                return StepDecision.Fail(SshCodes.AuthRefused, SshChecks.AuthSignature, "user " + user + " named an allowed key and signed with another");

            s.User = user;
            s.IsOpen = true;
            return StepDecision.Advance(
                Effect.Check(SshChecks.AuthSignature, SshCodes.AuthRefused),
                s.SealedPacket(SshNames.UserauthSuccess, new byte[] { (byte)SshMsg.UserauthSuccess }),
                Effect.Deliver(SshControl.Channel, SshControl.Encode(SshControl.Authenticated, 0, "")));
        }

        static StepEffect Failure(SshSession s)
        {
            return s.SealedPacket(SshNames.UserauthFailure, new ByteWriter().U8(SshMsg.UserauthFailure).Prefixed(MethodPublicKey).U8(0).ToArray());
        }

        static bool IsAuthorized(SshSession s, byte[] blob)
        {
            string offered = System.Convert.ToBase64String(blob);
            for (int i = 0; i < s.Server.AuthorizedKeys.Length; i++)
                if (System.Convert.ToBase64String(SshKeyBlob.Ed25519(s.Server.AuthorizedKeys[i])) == offered) return true;
            return false;
        }

        // ---------------------------------------------------------------- channels

        static StepDecision ReadChannelOpen(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            string kind = SshFields.Text(r.Prefixed("type", "id"));
            long sender = r.U32("sender", "id");
            long window = r.U32("window", "length");
            long maxPacket = r.U32("maxPacket", "length");
            if (s.Channels.Count >= SshRows.MaxChannels)
                return StepDecision.Stay(
                    Effect.CheckFailed(SshChecks.ChannelLimit, SshCodes.ChannelLimit, "this side holds " + s.Channels.Count + " open channels, the limit"),
                    OpenFailure(s, sender, OpenResourceShortage, "too many open channels"));
            if (kind == "session")
            {
                SshChannel session = SshRows.AddRemote(s, sender, window, maxPacket);
                session.IsSession = true;
                return StepDecision.Stay(s.SealedPacket(SshNames.ChannelOpenConfirmation, SshRows.Confirmation(session)));
            }
            if (kind != "direct-tcpip")
                return StepDecision.Stay(OpenFailure(s, sender, OpenUnknownType, "this server opens session and direct-tcpip channels"));

            string host = SshFields.Text(r.Prefixed("host", "id"));
            int port = (int)r.U32("port", "id");
            // RFC 4254 section 7.2: the side that receives the request decides. A refusal costs one channel, so the session stays open.
            string target = host + ":" + port;
            if (s.Server.AllowTunnel == null || !s.Server.AllowTunnel(host, port))
                return StepDecision.Stay(
                    Effect.CheckFailed(SshChecks.TunnelAllowList, SshCodes.TunnelRefused, target + " is off the allow list"),
                    OpenFailure(s, sender, OpenAdministrativelyProhibited, target + " is off the allow list"));
            SshChannel channel = SshRows.AddRemote(s, sender, window, maxPacket);
            return StepDecision.Stay(
                Effect.Check(SshChecks.TunnelAllowList, SshCodes.TunnelRefused),
                s.SealedPacket(SshNames.ChannelOpenConfirmation, SshRows.Confirmation(channel)),
                Effect.Deliver(SshControl.Channel, SshControl.Encode(SshControl.TunnelRequested, channel.Local, host + ":" + port)));
        }

        static StepEffect OpenFailure(SshSession s, long sender, int reason, string description)
        {
            return s.SealedPacket(SshNames.ChannelOpenFailure, new ByteWriter().U8(SshMsg.ChannelOpenFailure).U32(sender).U32(reason).Prefixed(description).Prefixed("").ToArray());
        }

        static StepDecision ReadChannelRequest(SshSession s, InboundMessage m)
        {
            ByteReader r = new ByteReader(m.Body, 1, m.Body.Length - 1, true);
            StepDecision refused;
            SshChannel channel = SshRows.Find(s, r.U32("recipient", "id"), out refused);
            if (channel == null) return refused;
            string request = SshFields.Text(r.Prefixed("request", "id"));
            bool wantReply = r.U8("wantReply", "data") != 0;
            if (request == "exec" && channel.IsSession && !channel.ExecDone) return StepDecision.Stay(RunExec(s, channel, SshFields.Text(r.Prefixed("command", "data")), wantReply));
            if (!wantReply) return StepDecision.Stay();
            return StepDecision.Stay(s.SealedPacket(SshNames.ChannelFailure, new ByteWriter().U8(SshMsg.ChannelFailure).U32(channel.Remote).ToArray()));
        }

        static StepEffect[] RunExec(SshSession s, SshChannel channel, string command, bool wantReply)
        {
            channel.ExecDone = true;
            int exitCode;
            byte[] output = SshRows.RunExec(command, s.User, out exitCode);
            List<StepEffect> effects = new List<StepEffect>();
            if (wantReply) effects.Add(s.SealedPacket(SshNames.ChannelSuccess, new ByteWriter().U8(SshMsg.ChannelSuccess).U32(channel.Remote).ToArray()));
            if (output.Length > 0) channel.Queue.Add(output);
            SshRows.Drain(s, channel, effects);
            effects.Add(s.SealedPacket(SshNames.ChannelRequestExitStatus, new ByteWriter().U8(SshMsg.ChannelRequest).U32(channel.Remote).Prefixed("exit-status").U8(0).U32(exitCode).ToArray()));
            SshRows.End(s, channel, effects);
            return effects.ToArray();
        }
    }
}
