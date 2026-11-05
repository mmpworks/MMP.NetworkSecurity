using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Labs;
using NetSec.Trace;

namespace NetSec.Host.OsTransport;

/// <summary>
/// Lesson 5 on the OS transport: one TLS 1.3 client, Windows SslStream, against a server outside the course.
/// The course never holds a key or a secret of this session, so every event is metadata, and none carries a secret.
/// It sends one line and reads one line back, so a learner sees data move after the handshake.
/// </summary>
public sealed class OsTls13Lab(string host, int port, string nameToCheck, X509Certificate2Collection? trust) : ILab
{
    const string Line = "hello from lesson 5\n";
    const int TimeoutMs = 10_000, MaxReply = 4096;

    public string LabId => "os-tls13";

    public IFuture<LabResult> Run(LabContext context) => Futures.Run(() => Talk(context));

    LabResult Talk(LabContext c)
    {
        TraceStream stream = new(c.SessionId + "/os", c.SessionId, c.TraceId, null, "client", c.Clock);
        void Emit(string type, string message, string? detail = null, byte[]? plain = null)
        {
            TraceEvent e = stream.Stamp(new TraceEventDraft { Type = type, Message = message, Detail = detail, Plain = plain });
            c.Gate.Pass(e).Wait();
            c.Sink.Write(e);
        }

        string? refusal = null;
        try
        {
            using TcpClient tcp = new();
            if (!tcp.ConnectAsync(host, port).Wait(TimeoutMs)) throw new IOException($"No answer from {host}:{port} in {TimeoutMs / 1000} s.");
            Emit("os.tcp.connected", $"Connected to {host}:{port}.", $"{host}:{port}");

            using SslStream tls = new(tcp.GetStream(), false, (_, cert, chain, errors) => (refusal = Judge(cert, errors)) is null);
            tls.ReadTimeout = tls.WriteTimeout = TimeoutMs;
            tls.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = nameToCheck,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            });
            X509Certificate2? server = tls.RemoteCertificate as X509Certificate2;
            Emit("os.tls.handshake", $"Windows finished a {tls.SslProtocol} handshake with {nameToCheck}.",
                $"protocol {tls.SslProtocol}; cipher suite {tls.NegotiatedCipherSuite}; server {server?.Subject}; SHA-256 {server?.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)}; trust {(trust is null ? "Windows store" : "SSL_CERT_FILE")}");

            byte[] sent = Encoding.UTF8.GetBytes(Line);
            tls.Write(sent);
            Emit("os.app.sent", $"Sent {sent.Length} bytes inside TLS.", null, sent);
            byte[] reply = ReadLine(tls);
            Emit("os.app.received", $"Read {reply.Length} bytes inside TLS.", null, reply);
            Emit("os.closed", "Closed the connection.");
            return new LabResult { Completed = true };
        }
        catch (Exception e) when (e is IOException or SocketException or AuthenticationException or AggregateException)
        {
            Emit("os.failed", "The OS transport stopped.", refusal ?? (e.InnerException ?? e).Message);
            return new LabResult { Completed = false, FailedCode = ErrorCodes.OsTransportFailed, FailedCheck = refusal is null ? "os.connect" : "os.tls.trust" };
        }
    }

    /// <summary>Null when the server's certificate is fit to trust. With SSL_CERT_FILE set, the chain must end at one of its certificates and the name must fit.</summary>
    string? Judge(X509Certificate? cert, SslPolicyErrors errors)
    {
        if (cert is null) return "The server sent no certificate.";
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)) return $"The server's certificate does not name {nameToCheck}.";
        if (trust is null) return errors == SslPolicyErrors.None ? null : $"Windows does not trust the server's certificate ({errors}).";
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(trust);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(new X509Certificate2(cert)) ? null : "The server's certificate does not chain to a certificate in SSL_CERT_FILE.";
    }

    static byte[] ReadLine(SslStream tls)
    {
        using MemoryStream got = new();
        int b;
        while (got.Length < MaxReply && (b = tls.ReadByte()) >= 0)
        {
            got.WriteByte((byte)b);
            if (b == '\n') break;
        }
        return got.ToArray();
    }
}
