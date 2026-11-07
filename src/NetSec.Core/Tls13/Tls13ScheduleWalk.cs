using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Tls13
{
    /// <summary>What one step of the TLS 1.3 key schedule does.</summary>
    public enum Tls13StepKind
    {
        /// <summary>A hash over handshake messages. Messages names them.</summary>
        TranscriptHash,
        /// <summary>X25519: Secret is the private key, Context the peer's public key.</summary>
        KeyAgreement,
        /// <summary>HKDF-Extract: Salt and Ikm.</summary>
        Extract,
        /// <summary>Derive-Secret: HKDF-Expand-Label of Secret with Label and the transcript hash in Context, digest-sized.</summary>
        DeriveSecret,
        /// <summary>HKDF-Expand-Label for a traffic key, IV or Finished key: Secret, Label, an empty Context.</summary>
        ExpandLabel,
        /// <summary>The Finished verify_data: HMAC under Secret (the Finished key) of the transcript hash in Context.</summary>
        VerifyData
    }

    /// <summary>One step of the walk. A field a step's kind does not use is null.</summary>
    public sealed class Tls13ScheduleStep
    {
        public string Name;
        public Tls13StepKind Kind;
        public string Label;
        public string[] Messages;
        public byte[] Salt, Ikm, Secret, Context;

        /// <summary>The HkdfLabel bytes that HKDF-Expand took as info. Null for a step that runs no Expand-Label.</summary>
        public byte[] HkdfLabel;
        public byte[] Output;
    }

    public sealed class Tls13ScheduleWalk
    {
        public string Source, Suite;
        public Tls13ScheduleStep[] Steps;
    }

    /// <summary>
    /// The TLS 1.3 key schedule (RFC 8446 section 7.1), step by step, on the public inputs of RFC 8448 section 3 (docs/sections-plan.md,
    /// section 4, slice P4). Pure. Each step runs the engine's own function. The ladder's rungs are then compared with Tls13KeySchedule.Derive,
    /// so a walk that wires a step differently from the real path throws TLS13_WALK_DIVERGED and shows nothing.
    /// </summary>
    public static class Tls13ScheduleWalks
    {
        const int KeyLength = 16, HashLength = 32;

        public static Tls13ScheduleWalk Rfc8448()
        {
            Func<IHash> h = Hashes.Sha256;
            List<Tls13ScheduleStep> steps = new List<Tls13ScheduleStep>();
            byte[] zeros = new byte[HashLength];

            byte[] helloHash = Transcript(steps, h, "hash_client_hello_to_server_hello", new string[] { "ClientHello", "ServerHello" },
                Rfc8448Trace.ClientHello, Rfc8448Trace.ServerHello);
            byte[] shared = Add(steps, new Tls13ScheduleStep { Name = "ecdhe_shared", Kind = Tls13StepKind.KeyAgreement, Secret = Rfc8448Trace.ClientPrivate,
                Context = Rfc8448Trace.ServerPublic, Output = X25519.Mult(Rfc8448Trace.ClientPrivate, Rfc8448Trace.ServerPublic) });

            byte[] early = Extract(steps, h, "early_secret", zeros, zeros);
            byte[] emptyHash = Tls13KeySchedule.HashOf(h, new byte[0]);
            byte[] derivedHs = Derive(steps, h, "derived_for_handshake", early, "derived", emptyHash);
            byte[] handshake = Extract(steps, h, "handshake_secret", derivedHs, shared);
            byte[] cHs = Derive(steps, h, "c_hs_traffic", handshake, "c hs traffic", helloHash);
            byte[] sHs = Derive(steps, h, "s_hs_traffic", handshake, "s hs traffic", helloHash);
            Expand(steps, h, "s_hs_key", sHs, "key", KeyLength);
            Expand(steps, h, "s_hs_iv", sHs, "iv", 12);
            byte[] derivedMs = Derive(steps, h, "derived_for_master", handshake, "derived", emptyHash);
            byte[] master = Extract(steps, h, "master_secret", derivedMs, zeros);

            byte[] serverFinishedHash = Transcript(steps, h, "hash_to_server_finished",
                new string[] { "ClientHello", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateVerify", "Finished (server)" },
                Rfc8448Trace.ClientHello, Rfc8448Trace.ServerHello, Rfc8448Trace.EncryptedExtensions, Rfc8448Trace.Certificate,
                Rfc8448Trace.CertificateVerify, Rfc8448Trace.ServerFinished);
            byte[] beforeServerFinished = Tls13KeySchedule.HashOf(h, Concat(Rfc8448Trace.ClientHello, Rfc8448Trace.ServerHello,
                Rfc8448Trace.EncryptedExtensions, Rfc8448Trace.Certificate, Rfc8448Trace.CertificateVerify));
            byte[] sFinishedKey = Expand(steps, h, "s_finished_key", sHs, "finished", HashLength);
            Add(steps, new Tls13ScheduleStep { Name = "s_finished_verify_data", Kind = Tls13StepKind.VerifyData, Secret = sFinishedKey,
                Context = beforeServerFinished, Output = Tls13KeySchedule.VerifyData(h, sHs, beforeServerFinished) });

            byte[] cAp = Derive(steps, h, "c_ap_traffic", master, "c ap traffic", serverFinishedHash);
            byte[] sAp = Derive(steps, h, "s_ap_traffic", master, "s ap traffic", serverFinishedHash);
            byte[] exporter = Derive(steps, h, "exp_master", master, "exp master", serverFinishedHash);
            Expand(steps, h, "s_ap_key", sAp, "key", KeyLength);
            Expand(steps, h, "s_ap_iv", sAp, "iv", 12);
            byte[] cFinishedKey = Expand(steps, h, "c_finished_key", cHs, "finished", HashLength);
            Add(steps, new Tls13ScheduleStep { Name = "c_finished_verify_data", Kind = Tls13StepKind.VerifyData, Secret = cFinishedKey,
                Context = serverFinishedHash, Output = Tls13KeySchedule.VerifyData(h, cHs, serverFinishedHash) });

            // The guard: the walk's rungs must equal the real path's.
            Tls13Secrets real = Tls13KeySchedule.Derive(h, shared, helloHash, serverFinishedHash);
            RequireSame(real.EarlySecret, early);
            RequireSame(real.HandshakeSecret, handshake);
            RequireSame(real.ClientHandshakeTrafficSecret, cHs);
            RequireSame(real.ServerHandshakeTrafficSecret, sHs);
            RequireSame(real.MasterSecret, master);
            RequireSame(real.ClientApplicationTrafficSecret0, cAp);
            RequireSame(real.ServerApplicationTrafficSecret0, sAp);
            RequireSame(real.ExporterMasterSecret, exporter);

            Tls13ScheduleWalk walk = new Tls13ScheduleWalk();
            walk.Source = "RFC 8448 section 3";
            walk.Suite = "TLS_AES_128_GCM_SHA256, X25519";
            walk.Steps = steps.ToArray();
            return walk;
        }

        static byte[] Add(List<Tls13ScheduleStep> steps, Tls13ScheduleStep step)
        {
            steps.Add(step);
            return step.Output;
        }

        static byte[] Transcript(List<Tls13ScheduleStep> steps, Func<IHash> h, string name, string[] messages, params byte[][] parts)
        {
            return Add(steps, new Tls13ScheduleStep { Name = name, Kind = Tls13StepKind.TranscriptHash, Messages = messages,
                Output = Tls13KeySchedule.HashOf(h, Concat(parts)) });
        }

        static byte[] Extract(List<Tls13ScheduleStep> steps, Func<IHash> h, string name, byte[] salt, byte[] ikm)
        {
            return Add(steps, new Tls13ScheduleStep { Name = name, Kind = Tls13StepKind.Extract, Salt = salt, Ikm = ikm, Output = Hkdf.Extract(h, salt, ikm) });
        }

        static byte[] Derive(List<Tls13ScheduleStep> steps, Func<IHash> h, string name, byte[] secret, string label, byte[] transcriptHash)
        {
            return Add(steps, new Tls13ScheduleStep { Name = name, Kind = Tls13StepKind.DeriveSecret, Label = label, Secret = secret, Context = transcriptHash,
                HkdfLabel = Tls13KeySchedule.HkdfLabel(label, transcriptHash, HashLength), Output = Tls13KeySchedule.DeriveSecret(h, secret, label, transcriptHash) });
        }

        static byte[] Expand(List<Tls13ScheduleStep> steps, Func<IHash> h, string name, byte[] secret, string label, int length)
        {
            byte[] empty = new byte[0];
            return Add(steps, new Tls13ScheduleStep { Name = name, Kind = Tls13StepKind.ExpandLabel, Label = label, Secret = secret, Context = empty,
                HkdfLabel = Tls13KeySchedule.HkdfLabel(label, empty, length), Output = Tls13KeySchedule.ExpandLabel(h, secret, label, empty, length) });
        }

        static byte[] Concat(params byte[][] parts)
        {
            ByteWriter w = new ByteWriter();
            for (int i = 0; i < parts.Length; i++) w.Put(parts[i]);
            return w.ToArray();
        }

        internal static void RequireSame(byte[] real, byte[] walked)
        {
            bool same = real != null && walked != null && real.Length == walked.Length;
            for (int i = 0; same && i < real.Length; i++) same = real[i] == walked[i];
            if (!same) throw new NetSecException(NetSecError.Of(ErrorCodes.Tls13WalkDiverged, "The walk differs from the real key schedule."));
        }
    }
}
