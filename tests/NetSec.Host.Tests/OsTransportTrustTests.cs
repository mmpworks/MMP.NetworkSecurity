#nullable enable
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using Peer = NetSec.Host.Tests.OsTransportLiveTests.Peer;

namespace NetSec.Host.Tests;

/// <summary>
/// What lesson 5 on the OS transport accepts as a server certificate when SSL_CERT_FILE is the trust (Jared's 9 cases on #129, plus a
/// missing intermediate). The rule is the one Windows applies to a TLS server: the chain ends at a trusted root, every date fits,
/// every issuer is a CA, and the leaf is made for server authentication. All keys are P-256, made for each run.
/// </summary>
public sealed class OsTransportTrustTests
{
    const string Leaf = "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n";
    const string Ca = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";

    static void Key(string openssl, string dir, string name) =>
        OsTransportLiveTests.Run(openssl, "genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out " + name + ".key", dir);

    static void Root(string openssl, string dir, string name)
    {
        Key(openssl, dir, name);
        OsTransportLiveTests.Run(openssl, "req -x509 -new -key " + name + ".key -subj \"/CN=" + name + "\" -days 3 -addext \"basicConstraints=critical,CA:TRUE\" -addext \"keyUsage=critical,keyCertSign,cRLSign\" -out " + name + ".pem", dir);
    }

    /// <summary>A certificate for name, signed by issuer, with the extensions given. dates is extra x509 arguments, such as a past window.</summary>
    static void Issue(string openssl, string dir, string name, string subject, string issuer, string extensions, string dates = "-days 2")
    {
        Key(openssl, dir, name);
        File.WriteAllText(Path.Combine(dir, name + ".ext"), "[v]\n" + extensions);
        OsTransportLiveTests.Run(openssl, "req -new -key " + name + ".key -subj \"/CN=" + subject + "\" -out " + name + ".csr", dir);
        OsTransportLiveTests.Run(openssl, "x509 -req -in " + name + ".csr -CA " + issuer + ".pem -CAkey " + issuer + ".key -set_serial " + (System.Math.Abs(name.GetHashCode()) + 1)
            + " " + dates + " -extfile " + name + ".ext -extensions v -out " + name + ".pem", dir);
    }

    sealed record Case(string Name, bool Accept, string? Status, string Trust, string ServerFiles, System.Action<string, string> Make);

    static readonly string LeafFiles = "-cert leaf.pem -key leaf.key";

    static Case Of(string name) => name switch
    {
        "control-serverauth" => new(name, true, null, "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "eku-clientauth-only" => new(name, false, "NotValidForUsage", "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=clientAuth\n"); }),
        "eku-codesigning-only" => new(name, false, "NotValidForUsage", "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=codeSigning\n"); }),
        "no-eku" => new(name, true, null, "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "leaf", "localhost", "root", Leaf); }),
        "expired" => new(name, false, "NotTimeValid", "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=serverAuth\n", "-not_before 20200101000000Z -not_after 20200201000000Z"); }),
        // Jared's shape: the leaf is under a root the trust file does not hold, and the server sends no root. Windows reads PartialChain,
        // the status a missing intermediate gives too, so the words must fit both causes.
        "other-root-not-sent" => new(name, false, "PartialChain", "other.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Root(o, d, "other"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "other-root" => new(name, false, "UntrustedRoot", "other.pem", LeafFiles + " -cert_chain root.pem", (o, d) => { Root(o, d, "root"); Root(o, d, "other"); Issue(o, d, "leaf", "localhost", "root", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "via-intermediate-sent" => new(name, true, null, "root.pem", LeafFiles + " -cert_chain inter.pem", (o, d) => { Root(o, d, "root"); Issue(o, d, "inter", "Test Intermediate", "root", Ca); Issue(o, d, "leaf", "localhost", "inter", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "via-intermediate-not-sent" => new(name, false, "PartialChain", "root.pem", LeafFiles, (o, d) => { Root(o, d, "root"); Issue(o, d, "inter", "Test Intermediate", "root", Ca); Issue(o, d, "leaf", "localhost", "inter", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "via-non-ca-issuer-sent" => new(name, false, null, "root.pem", LeafFiles + " -cert_chain inter.pem", (o, d) => { Root(o, d, "root"); Issue(o, d, "inter", "Not A CA", "root", "basicConstraints=CA:FALSE\n"); Issue(o, d, "leaf", "localhost", "inter", Leaf + "extendedKeyUsage=serverAuth\n"); }),
        "self-signed-leaf-as-trust" => new(name, true, null, "cert.pem", "-cert cert.pem -key key.pem", (o, d) =>
        {
            Key(o, d, "key");
            OsTransportLiveTests.Run(o, "req -x509 -new -key key.key -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -addext \"extendedKeyUsage=serverAuth\" -out cert.pem", d);
            File.Copy(Path.Combine(d, "key.key"), Path.Combine(d, "key.pem"));
        }),
        _ => throw new System.ArgumentException(name),
    };

    [Theory]
    [InlineData("control-serverauth")]
    [InlineData("eku-clientauth-only")]
    [InlineData("eku-codesigning-only")]
    [InlineData("no-eku")]
    [InlineData("expired")]
    [InlineData("other-root")]
    [InlineData("via-intermediate-sent")]
    [InlineData("via-intermediate-not-sent")]
    [InlineData("via-non-ca-issuer-sent")]
    [InlineData("self-signed-leaf-as-trust")]
    [InlineData("other-root-not-sent")]
    public async Task Lesson_5_trusts_a_server_only_as_windows_would(string name)
    {
        Case c = Of(name);
        using Peer peer = await Peer.StartAsync(c.Make, c.ServerFiles);
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync(new() { ["NETSEC_OS_PEER"] = "127.0.0.1:" + peer.Port, ["SSL_CERT_FILE"] = Path.Combine(peer.Dir, c.Trust) });
        List<JsonElement> frames = await host.Session(5, "os");
        JsonElement finished = frames[^1];
        Assert.Equal("session.finished", finished.GetProperty("type").GetString());
        string outcome = finished.GetProperty("outcome").GetString()!;
        string detail = string.Join(" | ", frames.Where(f => f.GetProperty("type").GetString() == "trace")
            .Select(f => f.GetProperty("event")).Where(e => e.GetProperty("type").GetString() == "os.failed")
            .Select(e => e.TryGetProperty("detail", out JsonElement d) ? d.GetString() : ""));
        if (c.Accept)
        {
            Assert.True(outcome == "completed", name + " was refused: " + detail);
            return;
        }
        Assert.True(outcome == "caught", name + " was accepted");
        Assert.Equal("OS_TRANSPORT_FAILED", finished.GetProperty("code").GetString());
        Assert.Equal("os.tls.trust", finished.GetProperty("check").GetString());
        if (c.Status is not null) Assert.Contains("(" + c.Status, detail);
        if (c.Status == "PartialChain") Assert.Contains("another root", detail);
    }

    [Fact]
    public async Task The_three_chain_faults_read_differently()
    {
        string[] details = new string[3];
        string[] names = ["expired", "other-root", "via-intermediate-not-sent"];
        for (int i = 0; i < names.Length; i++)
        {
            Case c = Of(names[i]);
            using Peer peer = await Peer.StartAsync(c.Make, c.ServerFiles);
            using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync(new() { ["NETSEC_OS_PEER"] = "127.0.0.1:" + peer.Port, ["SSL_CERT_FILE"] = Path.Combine(peer.Dir, c.Trust) });
            details[i] = string.Join(" ", (await host.Session(5, "os")).Where(f => f.GetProperty("type").GetString() == "trace")
                .Select(f => f.GetProperty("event")).Where(e => e.GetProperty("type").GetString() == "os.failed")
                .Select(e => e.GetProperty("detail").GetString()));
        }
        Assert.Equal(3, details.Distinct().Count());
    }
}
