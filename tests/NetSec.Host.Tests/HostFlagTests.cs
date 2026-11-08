using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>The command-line route of design section 11, against the real process. The env route runs in HostLiveTests.</summary>
    public class HostFlagTests
    {
        static string HostDll()
        {
            for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                string candidate = Path.Combine(dir.FullName, "src", "NetSec.Host", "bin", "Release", "net10.0", "NetSec.Host.dll");
                if (File.Exists(candidate)) return candidate;
            }
            throw new FileNotFoundException("NetSec.Host.dll is not built");
        }

        static int FreePort()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        static Process Start(string args, string envPort, string envToken, DataReceivedEventHandler onLine)
        {
            ProcessStartInfo info = new ProcessStartInfo("dotnet", "\"" + HostDll() + "\" " + args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            info.Environment["LOCALAPPDATA"] = Path.GetTempPath();
            info.Environment.Remove("NETSEC_PORT");
            info.Environment.Remove("NETSEC_TOKEN");
            if (envPort != null) info.Environment["NETSEC_PORT"] = envPort;
            if (envToken != null) info.Environment["NETSEC_TOKEN"] = envToken;
            Process process = new Process { StartInfo = info };
            process.OutputDataReceived += onLine;
            process.ErrorDataReceived += onLine;
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return process;
        }

        static async Task<HttpStatusCode> Health(int port, string token)
        {
            using HttpClient http = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/api/health");
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
            return (await http.SendAsync(request)).StatusCode;
        }

        [Fact]
        public async Task Flags_set_the_port_and_token_and_win_over_the_environment()
        {
            int flagPort = FreePort(), envPort = FreePort();
            TaskCompletionSource<string> ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            using Process host = Start($"--port {flagPort} --token flag-token", envPort.ToString(), "env-token", (_, e) =>
            {
                if (e.Data != null && e.Data.StartsWith("HOST-READY")) ready.TrySetResult(e.Data);
            });
            try
            {
                Assert.True(await Task.WhenAny(ready.Task, Task.Delay(60000)) == ready.Task, "the Host gave no ready line in 60 s");
                Assert.Equal($"HOST-READY port={flagPort}", await ready.Task);
                Assert.Equal(HttpStatusCode.OK, await Health(flagPort, "flag-token"));
                Assert.Equal(HttpStatusCode.Unauthorized, await Health(flagPort, "env-token"));
            }
            finally
            {
                host.Kill(entireProcessTree: true);
                await ProcessWaits.ExitedWithin(host, TimeSpan.FromSeconds(5));
            }
        }

        [Theory]
        [InlineData("--port not-a-port")]
        [InlineData("--port 70000")]
        [InlineData("--port")]
        [InlineData("--token")]
        public async Task A_bad_flag_stops_the_Host_by_name(string args)
        {
            TaskCompletionSource<bool> named = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using Process host = Start(args, null, null, (_, e) =>
            {
                if (e.Data != null && e.Data.StartsWith("HOST_OPTION_REFUSED")) named.TrySetResult(true);
            });
            // ExitedWithin also waits for the end of the redirected output, so the refusal line, if the Host wrote one, has arrived.
            // The old wait, Task.Run(() => WaitForExit(60000)), held a pool thread and returned before the output drained.
            bool exited = await ProcessWaits.ExitedWithin(host, TimeSpan.FromSeconds(60));
            if (!exited) host.Kill(entireProcessTree: true);
            Assert.True(exited, "the Host kept running with a bad flag");
            Assert.Equal(2, host.ExitCode);
            Assert.True(named.Task.IsCompleted, "the Host did not name the refusal");
        }
    }
}
