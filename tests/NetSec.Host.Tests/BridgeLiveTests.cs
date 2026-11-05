using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>
    /// The bridge's edges: PIN pad, the CF-compiled CE, and bank HSM as real processes, with a tap on the pad to CE hop and a relay in
    /// the middle that this test owns. The acceptance suite runs all five processes. It reads only process output, trace files, and the bytes that crossed its relay. No product code is linked.
    /// </summary>
    public sealed class BridgeLiveTests : IDisposable
    {
        readonly List<Lab> _labs = new List<Lab>();
        readonly string _dir = Path.Combine(Path.GetTempPath(), "netsec-bridge-" + Guid.NewGuid().ToString("N"));

        public BridgeLiveTests() { Directory.CreateDirectory(_dir); }

        public void Dispose()
        {
            foreach (Lab lab in _labs) lab.Dispose();
            try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        }

        static string Under(params string[] parts)
        {
            for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                string candidate = Path.Combine(new[] { dir.FullName }.Concat(parts).ToArray());
                if (File.Exists(candidate)) return candidate;
            }
            throw new FileNotFoundException(string.Join("/", parts) + " is not built");
        }

        sealed class Child : IDisposable
        {
            public readonly Process P;
            public readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();

            public Child(string exe, string args)
            {
                P = new Process { StartInfo = new ProcessStartInfo(exe, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
                P.OutputDataReceived += (_, e) => { if (e.Data != null) Lines.Enqueue(e.Data); };
                P.ErrorDataReceived += (_, e) => { if (e.Data != null) Lines.Enqueue(e.Data); };
                P.Start();
                P.BeginOutputReadLine();
                P.BeginErrorReadLine();
            }

            public async Task<string> Line(string prefix, int ms = 30000)
            {
                DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
                while (DateTime.UtcNow < end)
                {
                    string hit = Lines.FirstOrDefault(l => l.StartsWith(prefix));
                    if (hit != null) return hit;
                    await Task.Delay(20);
                }
                throw new TimeoutException("no line starting '" + prefix + "'. Output: " + string.Join(" | ", Lines));
            }

            public void Dispose()
            {
                if (!P.HasExited) P.Kill(entireProcessTree: true);
                P.WaitForExit(5000);
                P.Dispose();
            }
        }

        /// <summary>A relay this test owns, standing where the gateway and server will stand. It can flip one byte going toward the bank.</summary>
        sealed class Relay : IDisposable
        {
            readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
            public readonly List<byte> Seen = new List<byte>();
            public readonly List<byte> SeenDown = new List<byte>();
            public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

            public Relay(int bankPort, int flipAt)
            {
                _listener.Start();
                _ = Run(bankPort, flipAt);
            }

            async Task Run(int bankPort, int flipAt)
            {
                using TcpClient from = await _listener.AcceptTcpClientAsync();
                using TcpClient to = new TcpClient();
                await to.ConnectAsync(IPAddress.Loopback, bankPort);
                Task up = Pump(from.GetStream(), to.GetStream(), flipAt, Seen);
                Task down = Pump(to.GetStream(), from.GetStream(), -1, SeenDown);
                await Task.WhenAny(up, down);
            }

            static async Task Pump(NetworkStream a, NetworkStream b, int flipAt, List<byte> seen)
            {
                byte[] buffer = new byte[4096];
                int at = 0, n;
                try
                {
                    while ((n = await a.ReadAsync(buffer)) > 0)
                    {
                        if (flipAt >= at && flipAt < at + n) buffer[flipAt - at] ^= 1;
                        if (seen != null) lock (seen) seen.AddRange(buffer.Take(n));
                        at += n;
                        await b.WriteAsync(buffer.AsMemory(0, n));
                    }
                }
                catch (IOException) { }
            }

            public void Dispose() => _listener.Stop();
        }

        sealed class Lab : IDisposable
        {
            public Child Bank, Pad, Ce;
            public Relay Relay, PadTap;
            public string BankTrace, CeTrace;
            public void Dispose()
            {
                Ce?.Dispose(); Pad?.Dispose(); Bank?.Dispose(); Relay?.Dispose(); PadTap?.Dispose();
            }
        }

        static int Port(string ready) => int.Parse(ready.Substring("READY port=".Length));

        async Task<Lab> Run(int flipAt, string seed = "")
        {
            string name = Guid.NewGuid().ToString("N");
            Lab lab = new Lab { BankTrace = Path.Combine(_dir, name + "-bank.ndjson"), CeTrace = Path.Combine(_dir, name + "-ce.ndjson") };
            _labs.Add(lab);
            string node = Under("src", "NetSec.Node", "bin", "Release", "net10.0", "NetSec.Node.dll");
            lab.Bank = new Child("dotnet", $"\"{node}\" --role bankhsm --listen 0 --trace-file \"{lab.BankTrace}\"");
            int bank = Port(await lab.Bank.Line("READY"));
            lab.Relay = new Relay(bank, flipAt);
            lab.Pad = new Child("dotnet", $"\"{node}\" --role pinpad --listen 0 --pin 1234 --pan 4111111111111111 --trace-file \"{Path.Combine(_dir, name + "-pad.ndjson")}\"{seed}");
            int pad = Port(await lab.Pad.Line("READY"));
            lab.PadTap = new Relay(pad, -1);
            string ce = Under("src", "NetSec.CeDevice", "bin", "Release", "net35", "NetSec.CeDevice.exe");
            lab.Ce = new Child(ce, $"--pinpad {lab.PadTap.Port} --gateway {lab.Relay.Port} --trace-file \"{lab.CeTrace}\" --link external-forward --suite modern --pool 25");
            await lab.Ce.Line("CE-READY", 10000);
            return lab;
        }

        /// <summary>The process still holds its trace file open for writing, as it does when the suite reads it.</summary>
        static string ReadShared(string path)
        {
            using FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using StreamReader reader = new StreamReader(file);
            return reader.ReadToEnd();
        }

        static JsonElement Json(string line) => JsonDocument.Parse(line.Substring(line.IndexOf(' ') + 1)).RootElement.Clone();

        /// <summary>The whole clear field, its first 8 bytes alone (control, PIN length, digits), and the digits as text. A search for the whole field alone would miss a partial leak.</summary>
        static void AssertNoPin(byte[] seen, string clearHex)
        {
            Assert.True(seen.Length > 0);
            string hex = Convert.ToHexStringLower(seen);
            Assert.DoesNotContain(clearHex, hex);
            Assert.DoesNotContain(clearHex.Substring(0, 16), hex);
            Assert.DoesNotContain("1234", System.Text.Encoding.ASCII.GetString(seen));
        }

        [Fact]
        public void The_pad_role_reads_no_base_key()
        {
            string program = File.ReadAllText(Under("src", "NetSec.Node", "Program.cs")).Replace("\r\n", "\n");
            int start = program.IndexOf("int PinPad()");
            string body = program.Substring(start, program.IndexOf("\n}\n", start) - start);
            Assert.DoesNotContain("Bdk", body);
            Assert.DoesNotContain("TrainingKeySource", body);
            Assert.DoesNotContain("DeriveInitialKey", body);
            Assert.Contains("InjectedInitialKey", body);
        }

        [Fact]
        public async Task A_cf_binary_relays_a_sealed_pin_and_the_bank_recovers_it()
        {
            Lab lab = await Run(flipAt: -1);
            JsonElement pad = Json(await lab.Pad.Line("RESULT"));
            JsonElement bank = Json(await lab.Bank.Line("RESULT"));
            JsonElement ce = Json(await lab.Ce.Line("CE-RESULT"));

            Assert.Equal("OK", bank.GetProperty("code").GetString());
            string clear = pad.GetProperty("pinBlockHex").GetString();
            Assert.Equal(clear, bank.GetProperty("pinBlockHex").GetString());
            Assert.True(ce.GetProperty("ok").GetBoolean());

            byte[] seen;
            lock (lab.Relay.Seen) seen = lab.Relay.Seen.ToArray();
            AssertNoPin(seen, clear);

            // The claim names this hop: the PIN pad's bytes as the CE takes them.
            byte[] fromPad;
            lock (lab.PadTap.SeenDown) fromPad = lab.PadTap.SeenDown.ToArray();
            AssertNoPin(fromPad, clear);

            string ceTrace = ReadShared(lab.CeTrace);
            Assert.DoesNotContain(clear, ceTrace);
            Assert.DoesNotContain(clear.Substring(0, 16), ceTrace);
            string traceId = ce.GetProperty("traceId").GetString();
            Assert.Contains(traceId, ReadShared(lab.BankTrace));
            Assert.Contains("\"traceId\":\"" + traceId + "\"", ceTrace);
        }

        [Fact]
        public async Task A_byte_flipped_on_the_way_stops_at_the_bank_by_name()
        {
            // Byte 20 of the stream is inside the envelope, past its 4-byte frame length.
            Lab lab = await Run(flipAt: 20);
            JsonElement bank = Json(await lab.Bank.Line("RESULT"));
            Assert.NotEqual("OK", bank.GetProperty("code").GetString());
            Assert.Equal("", bank.GetProperty("pinBlockHex").GetString());
            Assert.Equal("PIN block MAC at bank", bank.GetProperty("check").GetString());
            Assert.False(Json(await lab.Ce.Line("CE-RESULT")).GetProperty("ok").GetBoolean());
        }

        [Theory]
        [InlineData("gateway")]
        [InlineData("server")]
        public async Task A_middle_role_with_no_next_port_says_so_by_code(string role)
        {
            using Child node = new Child("dotnet", $"\"{Under("src", "NetSec.Node", "bin", "Release", "net10.0", "NetSec.Node.dll")}\" --role {role} --listen 0");
            await node.Line("NODE_FLAG_MISSING");
            Assert.True(await Task.Run(() => node.P.WaitForExit(30000)));
            Assert.Equal(2, node.P.ExitCode);
        }
    }
}
