using System;
using System.Collections.Generic;
using NetSec.Errors;

namespace NetSec.Keys
{
    public enum CredentialMode { BuiltIn, Mine }

    /// <summary>The 15 security types (docs/modes-design.md section 1.7). A learner's own test key can stand in for the built-in one in each.</summary>
    public static class SecurityTypes
    {
        public const string RootCa = "pki.root-ca";
        public const string TlsTrust = "tls.trust";
        public const string Tls13Server = "tls13.server";
        public const string Tls13Client = "tls13.client";
        public const string Tls11Server = "tls11.server";
        public const string SshHostEd25519 = "ssh.host-ed25519";
        public const string SshHostRsa = "ssh.host-rsa";
        public const string SshKnownHosts = "ssh.known-hosts";
        public const string SshClient = "ssh.client";
        public const string DukptBdk = "dukpt.bdk";
        public const string DukptPad = "dukpt.pad";
        public const string TokenIssuer = "token.issuer";
        public const string DeviceEnrolment = "device.enrolment";
        public const string LabAesKey = "lab.aes-key";
        public const string LabSealKey = "lab.seal-key";

        static readonly string[] Everything =
        {
            RootCa, TlsTrust, Tls13Server, Tls13Client, Tls11Server,
            SshHostEd25519, SshHostRsa, SshKnownHosts, SshClient,
            DukptBdk, DukptPad, TokenIssuer, DeviceEnrolment, LabAesKey, LabSealKey,
        };

        public static string[] All { get { return (string[])Everything.Clone(); } }

        /// <summary>The type that holds a KeyIds key. Null for a key with no type: the attacker's key has no owner to replace it.</summary>
        public static string OfKey(string keyId)
        {
            switch (keyId)
            {
                case KeyIds.CaRoot: return RootCa;
                case KeyIds.ServerTlsEd25519: return Tls13Server;
                case KeyIds.ClientTlsEd25519: return Tls13Client;
                case KeyIds.ServerTls11Rsa: return Tls11Server;
                case KeyIds.SshHostEd25519: return SshHostEd25519;
                case KeyIds.SshHostRsa: return SshHostRsa;
                case KeyIds.SshClient: return SshClient;
                case KeyIds.DukptBdk128:
                case KeyIds.DukptBdk256: return DukptBdk;
                case KeyIds.TokenIssuer: return TokenIssuer;
                default: return null;
            }
        }
    }

    /// <summary>One security type, resolved for a session. Immutable.</summary>
    public sealed class Credential
    {
        public readonly string TypeId, ProviderKind, Fingerprint;
        public readonly CredentialMode Mode;
        public readonly int Version;

        /// <summary>A key the labs read as bytes (O1, option C). Null for a type with no private half of its own, such as a trust list that follows its root.</summary>
        public readonly ITrainingKey Key;

        public Credential(string typeId, CredentialMode mode, string providerKind, int version, string fingerprint, ITrainingKey key)
        {
            TypeId = typeId;
            Mode = mode;
            ProviderKind = providerKind;
            Version = version;
            Fingerprint = fingerprint;
            Key = key;
        }
    }

    /// <summary>
    /// What a lab holds: a snapshot of each type, taken at session.start. A fork reuses its parent's set. It is an ITrainingKeySource, so the engines
    /// and GlassTransportFactory read a learner's key the way they read a training key. A type with no entry here is built-in.
    /// </summary>
    public sealed class CredentialSet : ITrainingKeySource
    {
        readonly ITrainingKeySource _builtIn;
        readonly Dictionary<string, Credential> _mine = new Dictionary<string, Credential>();

        public CredentialSet(ITrainingKeySource builtIn, Credential[] mine)
        {
            if (builtIn == null) throw new ArgumentNullException("builtIn");
            _builtIn = builtIn;
            if (mine == null) return;
            foreach (Credential c in mine) _mine[c.TypeId] = c;
        }

        public static CredentialSet BuiltIn(ITrainingKeySource keys) { return new CredentialSet(keys, null); }

        public ITrainingKey Find(string keyId)
        {
            string typeId = SecurityTypes.OfKey(keyId);
            Credential mine;
            if (typeId != null && _mine.TryGetValue(typeId, out mine) && mine.Key != null) return mine.Key;
            return _builtIn.Find(keyId);
        }

        /// <summary>The learner's key for a type with no KeyIds entry, such as a device key. Null means the lab uses its built-in behaviour.</summary>
        public ITrainingKey MineOrNull(string typeId)
        {
            Credential mine;
            return _mine.TryGetValue(typeId, out mine) ? mine.Key : null;
        }

        /// <summary>The learner's entries only. Each holds public facts and a key, so a caller picks what it shows.</summary>
        public Credential[] Mine()
        {
            Credential[] all = new Credential[_mine.Count];
            _mine.Values.CopyTo(all, 0);
            return all;
        }
    }

    public sealed class TypeProblem
    {
        public readonly string TypeId, Code, Detail;

        public TypeProblem(string typeId, string code, string detail)
        {
            TypeId = typeId;
            Code = code;
            Detail = detail;
        }
    }

    public sealed class LabDecision
    {
        public readonly TypeProblem[] Problems;
        public LabDecision(TypeProblem[] problems) { Problems = problems; }
        public bool MayRun { get { return Problems.Length == 0; } }
    }

    public enum Readiness { Ready, Unconfigured, Configured, Broken }

    public sealed class SecurityTypeState
    {
        public string TypeId, FlowId;
        public CredentialMode Mode;
        public Readiness Readiness;
    }

    /// <summary>The rule for whether a lab may run on the types as they stand. Pure: same input, same answer. A lab never falls back to built-in keys in silence.</summary>
    public static class SecurityReadiness
    {
        // Types whose keys must come from one side. A learner's server certificate cannot reach a built-in anchor, and the same holds for a host key and its pin.
        static readonly string[][] MustAgree =
        {
            new string[] { SecurityTypes.RootCa, SecurityTypes.TlsTrust, SecurityTypes.Tls13Server, SecurityTypes.Tls13Client, SecurityTypes.Tls11Server },
            new string[] { SecurityTypes.SshHostEd25519, SecurityTypes.SshHostRsa, SecurityTypes.SshKnownHosts },
            new string[] { SecurityTypes.DukptBdk, SecurityTypes.DukptPad },
        };

        public static LabDecision Decide(string[] typesTheLabReads, SecurityTypeState[] states)
        {
            Dictionary<string, SecurityTypeState> byId = new Dictionary<string, SecurityTypeState>();
            foreach (SecurityTypeState s in states) byId[s.TypeId] = s;

            List<TypeProblem> problems = new List<TypeProblem>();
            foreach (string typeId in typesTheLabReads)
            {
                SecurityTypeState s;
                if (byId.TryGetValue(typeId, out s) && s.Mode == CredentialMode.Mine) AddState(problems, s);
            }
            foreach (string[] group in MustAgree) AddDisagreement(problems, group, typesTheLabReads, byId);
            return new LabDecision(problems.ToArray());
        }

        static void AddState(List<TypeProblem> problems, SecurityTypeState s)
        {
            switch (s.Readiness)
            {
                case Readiness.Unconfigured:
                    problems.Add(new TypeProblem(s.TypeId, ErrorCodes.SecurityTypeNotReady, s.TypeId + " has no key yet. Run the flow " + s.FlowId + "."));
                    break;
                case Readiness.Broken:
                    problems.Add(new TypeProblem(s.TypeId, ErrorCodes.SecurityTypeNotReady, s.TypeId + " changed since its check. Run the flow " + s.FlowId + " again."));
                    break;
                case Readiness.Configured:
                    problems.Add(new TypeProblem(s.TypeId, ErrorCodes.SecurityTypeNotProven, s.TypeId + " has not passed its check. Finish the flow " + s.FlowId + "."));
                    break;
            }
        }

        static void AddDisagreement(List<TypeProblem> problems, string[] group, string[] read, Dictionary<string, SecurityTypeState> byId)
        {
            List<SecurityTypeState> present = new List<SecurityTypeState>();
            bool anyMine = false, anyBuiltIn = false;
            foreach (string typeId in group)
            {
                SecurityTypeState s;
                if (Array.IndexOf(read, typeId) < 0 || !byId.TryGetValue(typeId, out s)) continue;
                present.Add(s);
                if (s.Mode == CredentialMode.Mine) anyMine = true; else anyBuiltIn = true;
            }
            if (!anyMine || !anyBuiltIn) return;
            foreach (SecurityTypeState s in present)
                if (s.Mode == CredentialMode.BuiltIn)
                    problems.Add(new TypeProblem(s.TypeId, ErrorCodes.SecurityTypesDisagree, s.TypeId + " is built-in, and another type this lesson reads is your own. Set both the same way, or run the flow " + s.FlowId + "."));
        }
    }
}
