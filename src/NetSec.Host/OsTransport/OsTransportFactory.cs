using System.Net;
using System.Security.Cryptography.X509Certificates;
using NetSec.Errors;
using NetSec.Labs;

namespace NetSec.Host.OsTransport;

/// <summary>
/// The lab a lesson runs on when the learner picks the OS transport (docs/modes-design.md section 7.1).
/// The OS transport is the code Windows ships: SslStream speaks TLS 1.3, and the course only watches what it is told.
/// Only lesson 5 has an OS path. Every other lesson is refused by name, before any session exists.
/// </summary>
public sealed class OsTransportFactory(Func<string, string?> env)
{
    public const string Kind = "os";

    public const string Glass = "glass";

    const int OsLesson = 5;

    /// <summary>The transports session.start takes. No value means glass. Any other value, such as the old name real, is refused by name.</summary>
    public static bool IsKnown(string? transport) => transport is null or Glass or Kind;

    public ILab? LabFor(int lesson, out NetSecError? error)
    {
        if (lesson != OsLesson)
            return Refuse(out error, ErrorCodes.OsTransportNotBuilt, $"Lesson {lesson} has no OS transport path. Only lesson 5 runs on the OS transport.");
        if (Peer(env("NETSEC_OS_PEER")) is not { } peer)
            return Refuse(out error, ErrorCodes.OsTransportNoPeer, "Set NETSEC_OS_PEER to host:port of a TLS 1.3 server, such as 127.0.0.1:4433. The OS transport needs a server outside the course to talk to.");
        X509Certificate2Collection? trust = Trust(env("SSL_CERT_FILE"), out string? trustProblem);
        if (trustProblem is not null) return Refuse(out error, ErrorCodes.OsTransportFailed, trustProblem);
        error = null;
        return new OsTls13Lab(peer.Host, peer.Port, NameToCheck(peer.Host), trust);
    }

    static ILab? Refuse(out NetSecError? error, string code, string message)
    {
        error = NetSecError.Of(code, message);
        return null;
    }

    static (string Host, int Port)? Peer(string? value)
    {
        int colon = value?.LastIndexOf(':') ?? -1;
        if (colon <= 0 || !int.TryParse(value![(colon + 1)..], out int port) || port is < 1 or > 65535) return null;
        return (value[..colon], port);
    }

    /// <summary>A peer named by a loopback address is checked against the name localhost, as a test certificate on this machine carries.</summary>
    static string NameToCheck(string host) => IPAddress.TryParse(host, out IPAddress? ip) && IPAddress.IsLoopback(ip) ? "localhost" : host;

    /// <summary>SSL_CERT_FILE, when set, is the only trust: its certificates are the roots, and the Windows store is not asked. Unset, the Windows store decides.</summary>
    static X509Certificate2Collection? Trust(string? path, out string? problem)
    {
        problem = null;
        if (string.IsNullOrEmpty(path)) return null;
        X509Certificate2Collection roots = [];
        try { roots.ImportFromPemFile(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            problem = $"SSL_CERT_FILE names {path}, and no certificate could be read from it: {e.Message}";
            return null;
        }
        if (roots.Count == 0) problem = $"SSL_CERT_FILE names {path}, and it holds no certificate.";
        return roots;
    }
}
