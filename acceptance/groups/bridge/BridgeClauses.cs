using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A10 and A10a: the whole lab as separate processes, run from outside. PIN pad, CE (built from CF binaries), gateway, server and
    /// bank HSM; a locked PIN block travels through SSH, then TLS 1.3 hybrid, and the bank recovers it. The evidence is the bytes the
    /// tap relays saw, the NDJSON trace files the processes wrote, and the RESULT lines the bank and the PIN pad printed.
    /// Process command lines: design section 11, with the additions listed in CONTRACT.md. Referee programs: acceptance/referees/README.md.
    /// </summary>
    public static class BridgeClauses
    {
        const ulong ControlSeed = 1010;
        const string Pan = "4111111111111111";

        static BridgeOutcome Control(Ctx c) { return BridgeRun.Get(c, Topology.Glass, null, ControlSeed, true, 0); }

        // ---------------------------------------------------------------- shared checks

        static string Str(Dictionary<string, object> d, string k)
        {
            object v;
            return d != null && d.TryGetValue(k, out v) ? v as string : null;
        }

        static void CommonRun(BridgeOutcome o, bool sshLinkOurs)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(o.CeReady ?? "", @"^CE-READY pool=(?<w>\d+)/(?<c>\d+) ptr=(?<ptr>\d+) clr=(?<clr>\S+)");
            Check.True(m.Success, "CE ready line is '" + o.CeReady + "'; expected 'CE-READY pool=<w>/<c> ptr=<n> clr=<v>'");
            Check.Equal("CE thread pool cap (workers)", "25", m.Groups["w"].Value);
            Check.True(o.Trace.Length > 0, "no trace lines arrived. Unparsed: " + (o.Output.ContainsKey("unparsed-trace-lines") ? o.Output["unparsed-trace-lines"] : "none"));
            Check.True(o.FailedCodes.Length == 0, "the control run has failed checks: " + o.FailedCodes);
            Check.True(o.Bank != null, "bank HSM reported nothing");
            Check.True(o.BankOk, "bank RESULT code is '" + Str(o.Bank, "code") + "' and check '" + Str(o.Bank, "check") + "'; the control run must recover the PIN block");
            Check.True(o.PinPad != null && Str(o.PinPad, "pinBlockHex") != null, "the PIN pad RESULT has no pinBlockHex (the clear PIN block it locked; ASSUMED name, see CONTRACT.md)");
            Check.Equal("clear PIN block, bank against pin pad", Str(o.PinPad, "pinBlockHex").ToLowerInvariant(), (Str(o.Bank, "pinBlockHex") ?? "").ToLowerInvariant());
            // one trace id across both hops
            Dictionary<string, bool> ids = new Dictionary<string, bool>();
            bool hop1 = false, hop2 = false;
            foreach (TraceLine t in o.Trace)
            {
                if (!string.IsNullOrEmpty(t.TraceId)) ids[t.TraceId] = true;
                if (t.Hop == "hop1") hop1 = true;
                if (t.Hop == "hop2") hop2 = true;
            }
            Check.True(ids.Count == 1, "trace ids in the lab: " + string.Join(",", new List<string>(ids.Keys).ToArray()) + "; expected exactly one across all five processes");
            Check.True(hop1 && hop2, "the trace does not label both hops (hop1 seen: " + hop1 + ", hop2 seen: " + hop2 + ")");
            // the bytes: nothing the PIN pad locked is readable on either hop
            byte[] clearField = Hex.Decode(Str(o.PinPad, "pinBlockHex"));
            Check.True(!Contains(o.Hop1.ClientToServer, clearField) && !Contains(o.Hop1.ServerToClient, clearField), "the clear PIN block is on hop 1");
            Check.True(!Contains(o.Hop2.ClientToServer, clearField) && !Contains(o.Hop2.ServerToClient, clearField), "the clear PIN block is on hop 2");
            // hop 2 is TLS 1.3 with the hybrid group, read from the ClientHello bytes
            ClientHelloInfo ch = TlsWire.ClientHello(o.Hop2.ClientToServer);
            Check.True(ch != null, "hop 2 does not start with a TLS ClientHello");
            Check.True(ch.SupportedGroups.Contains(0x11EC) && ch.KeyShareGroups.Contains(0x11EC), "hop 2 ClientHello does not carry group 0x11EC (X25519MLKEM768) in supported_groups and key_share");
        }

        static bool Contains(byte[] hay, byte[] needle)
        {
            if (needle.Length == 0 || hay.Length < needle.Length) return false;
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }

        // ---------------------------------------------------------------- A10: the three topologies

        [Clause("A10.run.go-referee-hops")]
        public static string RunGoReferees(Ctx c)
        {
            BridgeOutcome o = BridgeRun.Get(c, Topology.GoReferees, null, ControlSeed, true, 0);
            CommonRun(o, false);
            Check.True(SshWire.StartsWithVersion(o.Hop1.ClientToServer), "hop 1 client-to-server does not start with SSH-2.0-");
            return "Go x/crypto/ssh gateway and Go crypto/tls server: PIN block recovered by the bank, " + o.Trace.Length + " trace lines";
        }

        [Clause("A10.run.glass-hops")]
        public static string RunGlass(Ctx c)
        {
            BridgeOutcome o = Control(c);
            CommonRun(o, true);
            Check.True(SshWire.StartsWithVersion(o.Hop1.ClientToServer), "hop 1 client-to-server does not start with SSH-2.0-");
            return "our Gateway and Server: PIN block recovered by the bank, " + o.Trace.Length + " trace lines";
        }

        [Clause("A10.run.ssh-exe-forward")]
        public static string RunSshExeForward(Ctx c)
        {
            BridgeOutcome o = BridgeRun.Get(c, Topology.GlassSshExeForward, null, ControlSeed, true, 0);
            CommonRun(o, false);
            string first = Encoding.ASCII.GetString(o.Hop1.ClientToServer, 0, Math.Min(40, o.Hop1.ClientToServer.Length));
            Check.True(first.StartsWith("SSH-2.0-OpenSSH_for_Windows"), "hop 1 does not start with the version line of ssh.exe: '" + first.Trim() + "'");
            foreach (TraceLine t in o.Trace)
                if (t.Actor == "ce" && t.Type != null && t.Type.StartsWith("ssh."))
                    throw new FailException("the CE emitted SSH events (" + t.Type + ") on the external-forward path; ssh.exe must carry the SSH there");
            return "ssh.exe -L carried hop 1; the CE spoke plain bytes only";
        }

        // ---------------------------------------------------------------- A10: a tamper at each hop, beside the control

        static void AttackNeverReaches(BridgeOutcome attack, string expectedCode)
        {
            Check.True(attack.FailedCodes.Split(',').Length > 0 && ("," + attack.FailedCodes + ",").Contains("," + expectedCode + ","),
                "expected failed check " + expectedCode + ", the run reported [" + attack.FailedCodes + "]");
            Check.True(!attack.BankOk, "the bank recovered a PIN block although the run was tampered");
        }

        [Clause("A10.tamper.hop1-ssh-packet-mac")]
        public static string TamperHop1(Ctx c)
        {
            BridgeOutcome control = Control(c);
            CommonRun(control, true);                                              // the passing control
            List<SshPacket> clear;
            int firstEnc = SshWire.FirstEncryptedPacket(control.Hop1.ClientToServer, out clear);
            Check.True(firstEnc > 0, "hop 1 control capture has no NEWKEYS; cannot place the flip");
            Tamper t = new Tamper(); t.Hop1Flip = true; t.Hop1Offset = firstEnc + 8;          // inside the first encrypted client packet
            BridgeOutcome attack = BridgeRun.Get(c, Topology.Glass, t, ControlSeed, true, 0);
            AttackNeverReaches(attack, "SSH_PACKET_MAC");
            return "control passes; one flipped bit at hop 1 offset " + t.Hop1Offset + " gives SSH_PACKET_MAC";
        }

        [Clause("A10.tamper.hop2-tls13-aead-tag")]
        public static string TamperHop2(Ctx c)
        {
            BridgeOutcome control = Control(c);
            CommonRun(control, true);
            int rec = TlsWire.FirstProtectedRecord(control.Hop2.ClientToServer);
            Check.True(rec >= 0, "hop 2 control capture has no protected client record; cannot place the flip");
            Tamper t = new Tamper(); t.Hop2Flip = true; t.Hop2Offset = rec + 5 + 2;
            BridgeOutcome attack = BridgeRun.Get(c, Topology.Glass, t, ControlSeed, true, 0);
            AttackNeverReaches(attack, "TLS13_AEAD_TAG");
            return "control passes; one flipped bit at hop 2 offset " + t.Hop2Offset + " gives TLS13_AEAD_TAG";
        }

        [Clause("A10.tamper.envelope-dukpt-mac-mismatch")]
        public static string TamperEnvelope(Ctx c)
        {
            BridgeOutcome control = Control(c);
            CommonRun(control, true);
            Tamper t = new Tamper(); t.EnvelopeFlip = true;
            BridgeOutcome attack = BridgeRun.Get(c, Topology.Glass, t, ControlSeed, true, 0);
            AttackNeverReaches(attack, "DUKPT_MAC_MISMATCH");
            Check.Equal("bank result code", "DUKPT_MAC_MISMATCH", Str(attack.Bank, "code"));
            return "control passes; a flipped envelope byte at the gateway gives DUKPT_MAC_MISMATCH at the bank";
        }

        // ---------------------------------------------------------------- A10: no DUKPT secret in the CE or gateway trace

        [Clause("A10.privacy.no-dukpt-secrets-in-ce-and-gateway-traces")]
        public static string Privacy(Ctx c)
        {
            BridgeOutcome o = Control(c);
            CommonRun(o, true);
            Check.True(o.Ksn != null && o.Ksn.Length == 12, "the PIN pad RESULT has no 12 byte ksn");
            byte[] ikid = Hex.Slice(o.Ksn, 0, 8);
            uint counter = (uint)((o.Ksn[8] << 24) | (o.Ksn[9] << 16) | (o.Ksn[10] << 8) | o.Ksn[11]);
            byte[] bdk = new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial();
            Dictionary<string, byte[]> needles = new Dictionary<string, byte[]>();
            needles["base derivation key"] = bdk;
            needles["initial key"] = DukptReference.InitialKey(bdk, ikid);
            needles["derivation key"] = DukptReference.DerivationKey(bdk, ikid, counter);
            needles["PIN encryption key"] = DukptReference.WorkingKey(bdk, ikid, counter, 0x1000, 16);
            needles["MAC key"] = DukptReference.WorkingKey(bdk, ikid, counter, 0x2000, 16);
            needles["data key"] = DukptReference.WorkingKey(bdk, ikid, counter, 0x3000, 16);
            needles["clear PIN block"] = Hex.Decode(Str(o.PinPad, "pinBlockHex"));

            // Positive control first: the scan can see a secret when one is there. The bank derives the PIN key and shows it.
            string bankText = Joined(o.Trace, "bank").ToLowerInvariant();
            Check.True(bankText.Contains(Hex.Encode(needles["PIN encryption key"])),
                "positive control failed: the bank trace does not show the PIN encryption key it derived, so a scan of the CE and gateway traces cannot prove absence");
            // Hop keys stay visible on purpose. If the CE trace shows none, the scan is blind.
            int ceSecrets = 0;
            foreach (TraceLine t in o.Trace) if (t.Actor == "ce") ceSecrets += t.Secrets.Count;
            Check.True(ceSecrets > 0, "the CE trace shows no secrets at all; hop keys are visible by design, so the trace is incomplete");

            foreach (string who in new string[] { "ce", "gateway" })
            {
                string text = Joined(o.Trace, who).ToLowerInvariant();
                Check.True(text.Length > 0, "no trace lines from the " + who);
                foreach (KeyValuePair<string, byte[]> n in needles)
                    Check.True(!text.Contains(Hex.Encode(n.Value)), "the " + who + " trace holds the " + n.Key);
            }
            return "CE and gateway traces hold none of 7 DUKPT secrets; the scan sees the bank's key and the CE's hop keys";
        }

        static string Joined(TraceLine[] lines, string actor)
        {
            StringBuilder sb = new StringBuilder();
            foreach (TraceLine t in lines) if (t.Actor == actor) sb.Append(t.Json).Append('\n');
            return sb.ToString();
        }

        // ---------------------------------------------------------------- A10a

        /// <summary>
        /// A10a (design section 2.1): each process writes a wire.sent event for the bytes it put on the socket, after tamper. For one hop,
        /// the client side's wire.sent bytes joined must equal the tap's client-to-server log, and the server side's must equal server-to-client.
        /// </summary>
        static void TapEqualsWireSent(BridgeOutcome o, string hop, string clientActor, string serverActor, TapLog tap)
        {
            Check.True(o.WireSentEvents(hop, clientActor) > 0 && o.WireSentEvents(hop, serverActor) > 0,
                hop + ": wire.sent events from " + clientActor + " = " + o.WireSentEvents(hop, clientActor) + " and from " + serverActor + " = " + o.WireSentEvents(hop, serverActor));
            Check.Bytes(hop + " client-to-server: wire.sent vs tap", tap.ClientToServer, o.WireSent(hop, clientActor));
            Check.Bytes(hop + " server-to-client: wire.sent vs tap", tap.ServerToClient, o.WireSent(hop, serverActor));
        }

        [Clause("A10a.tap-equals-trace.hop1")]
        public static string TapTraceHop1(Ctx c)
        {
            BridgeOutcome o = Control(c);
            TapEqualsWireSent(o, "hop1", "ce", "gateway", o.Hop1);
            return "hop 1: " + o.Hop1.ClientToServer.Length + " bytes up, " + o.Hop1.ServerToClient.Length + " bytes down, equal to the wire.sent events";
        }

        [Clause("A10a.tap-equals-trace.hop2")]
        public static string TapTraceHop2(Ctx c)
        {
            BridgeOutcome o = Control(c);
            TapEqualsWireSent(o, "hop2", "gateway", "server", o.Hop2);
            return "hop 2: " + o.Hop2.ClientToServer.Length + " bytes up, " + o.Hop2.ServerToClient.Length + " bytes down, equal to the wire.sent events";
        }

        static byte[] KexCookie(byte[] c2s)
        {
            List<SshPacket> clear;
            SshWire.FirstEncryptedPacket(c2s, out clear);
            foreach (SshPacket p in clear) if (p.Type == 20) return Hex.Slice(c2s, p.Offset + 6, 16);
            return null;
        }

        [Clause("A10a.randoms-differ")]
        public static string RandomsDiffer(Ctx c)
        {
            BridgeOutcome a = BridgeRun.Get(c, Topology.Glass, null, 0, false, 1);
            BridgeOutcome b = BridgeRun.Get(c, Topology.Glass, null, 0, false, 2);
            CommonRun(a, true); CommonRun(b, true);
            byte[] ca = KexCookie(a.Hop1.ClientToServer), cb = KexCookie(b.Hop1.ClientToServer);
            Check.True(ca != null && cb != null, "no SSH KEXINIT in a hop 1 capture");
            Check.True(!Hex.Eq(ca, cb), "two runs sent the same SSH KEXINIT cookie " + Hex.Encode(ca));
            byte[] ra = TlsWire.ClientHello(a.Hop2.ClientToServer).Random, rb = TlsWire.ClientHello(b.Hop2.ClientToServer).Random;
            Check.True(!Hex.Eq(ra, rb), "two runs sent the same TLS ClientHello random " + Hex.Encode(ra));
            byte[] sa = TlsWire.ServerHelloRandom(a.Hop2.ServerToClient), sb = TlsWire.ServerHelloRandom(b.Hop2.ServerToClient);
            Check.True(sa != null && sb != null && !Hex.Eq(sa, sb), "two runs got the same TLS ServerHello random");
            return "KEXINIT cookie, ClientHello random and ServerHello random differ across two unseeded runs";
        }
    }
}
