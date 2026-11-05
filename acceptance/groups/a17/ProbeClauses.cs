using System;
using System.IO;

namespace Acceptance
{
    /// <summary>
    /// The five referee clauses of slices V4 and V5 that put an outside program (OpenSSL, Go crypto/tls, ssh.exe) in front of a glass TLS or SSH server that runs on a
    /// LEARNER's key. modes-design.md section 3.3 leaves Probe and SshProbe on training keys, so acceptance/ has no way to start such a server.
    /// Until the design gives one, each clause reads NOT RUN PROBE_HAS_NO_CREDENTIALS, never PASS. The question is with the plan owner (acceptance/CONTRACT.md section 5,
    /// "Open questions"). Recommended answer: ProbeRequest gains an optional Credentials (a CredentialSet), and the suite builds one from its own files.
    /// </summary>
    public static class ProbeClauses
    {
        static void Blocked(Ctx c, string what)
        {
            if (string.IsNullOrEmpty(c.Prop("a17.attach", "")) && (string.IsNullOrEmpty(c.Prop("host", "")) || !File.Exists(c.Prop("host", ""))))
                throw new NotRunException("PRODUCT_MISSING", "NetSec.Host is not built (host=" + c.Prop("host", "") + ")");
            throw new NotRunException("PROBE_HAS_NO_CREDENTIALS", what + ". Probe and SshProbe run on training keys only (modes-design.md section 3.3), so acceptance/ cannot start a glass server on the learner's key for an outside program to judge");
        }

        [Clause("A17.referee.tls13-server-openssl")]
        public static string Tls13ServerOpenssl(Ctx c) { Blocked(c, "OpenSSL s_client against a glass TLS 1.3 server holding the learner's tls13.server key"); return ""; }

        [Clause("A17.referee.tls13-client-go-with-intermediate")]
        public static string Tls13ClientGoWithIntermediate(Ctx c) { Blocked(c, "Go crypto/tls as the server against the glass client holding the learner's tls13.client key, with its intermediate sent and a leaf-only control"); return ""; }

        [Clause("A17.referee.tls11-server-openssl")]
        public static string Tls11ServerOpenssl(Ctx c) { Blocked(c, "OpenSSL s_client -tls1_1 against a glass TLS 1.1 server holding the learner's tls11.server key"); return ""; }

        [Clause("A17.referee.ssh-host-ssh-exe")]
        public static string SshHostSshExe(Ctx c) { Blocked(c, "ssh.exe against a glass SSH server holding the learner's ssh.host key, with the pinned known_hosts line"); return ""; }

        [Clause("A17.referee.ssh-client-go")]
        public static string SshClientGo(Ctx c) { Blocked(c, "Go x/crypto/ssh as the server against the glass SSH client holding the learner's ssh.client key"); return ""; }
    }
}
