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

        /// <summary>The built-in training key a type runs on when its mode is BuiltIn. Null for a type with no long-term key (a trust list, a lab's per-run key).
        /// The inverse of OfKey; the DUKPT type runs on the 128-bit base key.</summary>
        public static string BuiltInKeyOf(string typeId)
        {
            switch (typeId)
            {
                case RootCa: return KeyIds.CaRoot;
                case Tls13Server: return KeyIds.ServerTlsEd25519;
                case Tls13Client: return KeyIds.ClientTlsEd25519;
                case Tls11Server: return KeyIds.ServerTls11Rsa;
                case SshHostEd25519: return KeyIds.SshHostEd25519;
                case SshHostRsa: return KeyIds.SshHostRsa;
                case SshClient: return KeyIds.SshClient;
                case DukptBdk: return KeyIds.DukptBdk128;
                case TokenIssuer: return KeyIds.TokenIssuer;
                default: return null;
            }
        }

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

        const string ProviderFile = "file";

        // modes-design.md section 3.3. Rows this build does not read yet. A file of one is refused by name, so a run never mixes in a built-in key in silence.
        static readonly string[] RowsNotBuilt =
        {
            "root.pem", "root.key", "anchors.pem", "srv.pem", "srv.key", "client.pem", "client.key", "rsa.pem", "rsa.key",
            "issuer.key", "device.key", "bdk.hex", "aes.hex", "seal.hex",
        };

        /// <summary>
        /// The learner's keys from a folder named as modes-design.md section 3.3 names them, for a probe or a test. Labs never use this call. A missing
        /// file leaves that one type built-in. user.pub, when present, must name the key in user.key. known_hosts, when present, is read
        /// and not parsed: it marks the pin as the learner's, and the client reads its pin from the file the caller names.
        /// </summary>
        public static CredentialSet FromFiles(string directory)
        {
            if (directory == null) throw new ArgumentNullException("directory");
            if (!System.IO.Directory.Exists(directory)) throw Refuse(ErrorCodes.KeyFileUnreadable, "The folder " + directory + " does not exist.");
            foreach (string name in RowsNotBuilt)
                if (System.IO.File.Exists(System.IO.Path.Combine(directory, name)))
                    throw Refuse(ErrorCodes.FileRowNotBuilt, "This build does not read " + name + " yet. Take it out of the folder, or wait for that slice.");
            List<Credential> mine = new List<Credential>();
            AddKey(mine, directory, "host.key", SecurityTypes.SshHostEd25519, KeyIds.SshHostEd25519, NetSec.Pki.OpenSshKeyReader.Ed25519Type);
            AddKey(mine, directory, "rsa-host.key", SecurityTypes.SshHostRsa, KeyIds.SshHostRsa, NetSec.Pki.OpenSshKeyReader.RsaType);
            ITrainingKey user = AddKey(mine, directory, "user.key", SecurityTypes.SshClient, KeyIds.SshClient, NetSec.Pki.OpenSshKeyReader.Ed25519Type);
            CheckUserPub(directory, user);
            string pin = System.IO.Path.Combine(directory, "known_hosts");
            if (System.IO.File.Exists(pin))
            {
                NetSec.Pki.OpenSshKeyReader.ReadText(pin);
                mine.Add(new Credential(SecurityTypes.SshKnownHosts, CredentialMode.Mine, ProviderFile, 1, "", null));
            }
            return new CredentialSet(new TrainingKeySource(), mine.ToArray());
        }

        static ITrainingKey AddKey(List<Credential> mine, string directory, string file, string typeId, string keyId, string sshType)
        {
            string path = System.IO.Path.Combine(directory, file);
            if (!System.IO.File.Exists(path)) return null;
            ITrainingKey key = NetSec.Pki.OpenSshKeyReader.Read(path, keyId, sshType);
            mine.Add(new Credential(typeId, CredentialMode.Mine, ProviderFile, 1, "", key));
            return key;
        }

        static void CheckUserPub(string directory, ITrainingKey user)
        {
            string path = System.IO.Path.Combine(directory, "user.pub");
            if (!System.IO.File.Exists(path)) return;
            if (user == null) throw Refuse(ErrorCodes.KeyFileFormat, "The folder holds user.pub and no user.key. The client needs its private key.");
            byte[] blob = NetSec.Pki.OpenSshKeyReader.PublicBlobOfLine(NetSec.Pki.OpenSshKeyReader.ReadText(path));
            byte[] want = NetSec.Pki.OpenSshKeyReader.Ed25519BlobOf(user.CopyPublic());
            bool same = blob.Length == want.Length;
            for (int i = 0; same && i < want.Length; i++) same = blob[i] == want[i];
            if (!same) throw Refuse(ErrorCodes.KeyFileFormat, "user.pub names another key than user.key.");
        }

        static NetSecException Refuse(string code, string message) { return new NetSecException(NetSecError.Of(code, message)); }

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
