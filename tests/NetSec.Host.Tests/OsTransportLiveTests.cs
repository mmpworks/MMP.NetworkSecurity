#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// Lesson 5 over the OS transport (slice V2): Windows SslStream speaks TLS 1.3 to an outside OpenSSL server.
/// The outside server writes the true session secrets to its own key log, so the test can look for each one in what the Host said.
/// </summary>
public sealed class OsTransportLiveTests
{
    static string OpenSsl()
    {
        string? set = Environment.GetEnvironmentVariable("NETSEC_OPENSSL");
        string path = !string.IsNullOrEmpty(set) ? set : @"C:\Program Files\Git\mingw64\bin\openssl.exe";
        Assert.True(File.Exists(path), "these tests need OpenSSL at " + path + " or in NETSEC_OPENSSL");
        return path;
    }

    static void Run(string exe, string args, string dir)
    {
        using Process p = Process.Start(new ProcessStartInfo(exe, args) { WorkingDirectory = dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(60_000) && p.ExitCode == 0, "openssl " + args + ": " + output);
    }

    /// <summary>An RSA server on a free port, with -rev so it answers each line reversed. Schannel refuses an Ed25519 server certificate.</summary>
    sealed class Peer : IDisposable
    {
        readonly Process _server;
        public readonly string Dir = Path.Combine(Path.GetTempPath(), "netsec-os-" + Guid.NewGuid().ToString("N"));
        public string Cert => Path.Combine(Dir, "cert.pem");
        public string KeyLog => Path.Combine(Dir, "peer.keylog");
        public readonly int Port;

        public Peer()
        {
            Directory.CreateDirectory(Dir);
            string openssl = OpenSsl();
            Run(openssl, "genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem", Dir);
            Run(openssl, "req -new -x509 -key key.pem -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -out cert.pem", Dir);
            _server = new Process { StartInfo = new ProcessStartInfo(openssl, "s_server -accept 0 -tls1_3 -rev -cert cert.pem -key key.pem -keylogfile peer.keylog")
            { WorkingDirectory = Dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true } };
            TaskCompletionSource<int> port = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _server.OutputDataReceived += (_, e) =>
            {
                Match m = Regex.Match(e.Data ?? "", @"^ACCEPT.*?(?<port>\d+)\s*$");
                if (m.Success) port.TrySetResult(int.Parse(m.Groups["port"].Value));
            };
            _server.Start();
            _server.BeginOutputReadLine();
            _server.BeginErrorReadLine();
            Assert.True(port.Task.Wait(TimeSpan.FromSeconds(20)), "openssl s_server gave no ACCEPT line in 20 s");
            Port = port.Task.Result;
        }

        /// <summary>The hex secrets of every line the server logged, as NSS key log lines hold them.</summary>
        public List<string> Secrets()
        {
            Thread.Sleep(500);
            using FileStream f = new(KeyLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return new StreamReader(f).ReadToEnd().Split('\n')
                .Select(l => Regex.Match(l.Trim(), @"^[A-Z0-9_]+ [0-9a-f]{64} (?<secret>[0-9a-f]{32,})$"))
                .Where(m => m.Success).Select(m => m.Groups["secret"].Value).ToList();
        }

        public void Dispose()
        {
            try { _server.Kill(entireProcessTree: true); _server.WaitForExit(5000); } catch (InvalidOperationException) { }
            _server.Dispose();
            try { Directory.Delete(Dir, true); } catch (IOException) { }
        }
    }

    static string TypeOf(JsonElement frame) => frame.GetProperty("type").GetString()!;

    [Fact]
    public async Task Lesson_5_on_the_os_transport_talks_tls_13_and_shows_no_secret()
    {
        using Peer peer = new();
        using SecurityLiveTests.Host host = new(new() { ["NETSEC_OS_PEER"] = "127.0.0.1:" + peer.Port, ["SSL_CERT_FILE"] = peer.Cert });
        List<JsonElement> frames = await host.Session(5, "os");

        JsonElement started = frames.First(f => TypeOf(f) == "session.started");
        Assert.Equal("os", started.GetProperty("transportKind").GetString());
        Assert.False(started.GetProperty("trainingOnly").GetBoolean());
        JsonElement finished = frames[^1];
        Assert.True(TypeOf(finished) == "session.finished", "the session ended with " + finished);
        Assert.Equal("completed", finished.GetProperty("outcome").GetString());

        List<JsonElement> events = frames.Where(f => TypeOf(f) == "trace").Select(f => f.GetProperty("event")).ToList();
        Assert.Contains(events, e => e.GetProperty("type").GetString() == "os.tls.handshake");
        Assert.Contains(events, e => e.GetProperty("type").GetString() == "os.app.received");
        Assert.All(events, e => Assert.False(e.TryGetProperty("secrets", out JsonElement s) && s.ValueKind == JsonValueKind.Array && s.GetArrayLength() > 0));

        string said = string.Join("\n", frames.Select(f => f.GetRawText())).ToLowerInvariant() + File.ReadAllText(started.GetProperty("sessionFile").GetString()!).ToLowerInvariant();
        List<string> secrets = peer.Secrets();
        Assert.True(secrets.Count >= 5, "the peer logged " + secrets.Count + " secrets, so the handshake did not reach it");
        Assert.All(secrets, s => Assert.DoesNotContain(s, said));

        (int status, string body) = await host.Get("/api/sessions/" + started.GetProperty("sessionId").GetString() + "/keylog");
        Assert.Equal(409, status);
        Assert.Equal("KEYLOG_NOT_KEPT", JsonDocument.Parse(body).RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_lesson_with_no_os_path_is_refused_by_name()
    {
        using Peer peer = new();
        using SecurityLiveTests.Host host = new(new() { ["NETSEC_OS_PEER"] = "127.0.0.1:" + peer.Port, ["SSL_CERT_FILE"] = peer.Cert });
        JsonElement last = (await host.Session(0, "os"))[^1];
        Assert.Equal("OS_TRANSPORT_NOT_BUILT", last.GetProperty("code").GetString());
        Assert.Contains("lesson 0", last.GetProperty("message").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_os_transport_with_no_peer_set_is_refused_by_name()
    {
        using SecurityLiveTests.Host host = new();
        JsonElement last = (await host.Session(5, "os"))[^1];
        Assert.Equal("OS_TRANSPORT_NO_PEER", last.GetProperty("code").GetString());
        Assert.Contains("NETSEC_OS_PEER", last.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_peer_the_trust_file_does_not_name_is_refused_and_no_data_moves()
    {
        using Peer peer = new(), other = new();
        using SecurityLiveTests.Host host = new(new() { ["NETSEC_OS_PEER"] = "127.0.0.1:" + peer.Port, ["SSL_CERT_FILE"] = other.Cert });
        List<JsonElement> frames = await host.Session(5, "os");
        JsonElement finished = frames[^1];
        Assert.Equal("session.finished", TypeOf(finished));
        Assert.Equal("OS_TRANSPORT_FAILED", finished.GetProperty("code").GetString());
        Assert.DoesNotContain(frames.Where(f => TypeOf(f) == "trace"), f => f.GetProperty("event").GetProperty("type").GetString() == "os.app.sent");
    }
}
