using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// The CF-compiled exe, run as its own process on the desktop CLR, observed from outside. This proves the IL runs. It proves nothing
    /// about a CE device. Both frameworks run these facts, because the exe is the same file for both.
    /// </summary>
    public class CfBinaryTests
    {
        static string Exe()
        {
            for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                string candidate = Path.Combine(dir.FullName, "src", "NetSec.CeDevice", "bin", "Release", "net35", "NetSec.CeDevice.exe");
                if (File.Exists(candidate)) return candidate;
            }
            throw new FileNotFoundException("NetSec.CeDevice.exe is not built under src/NetSec.CeDevice/bin/Release/net35");
        }

        static string[] Run(string args, out int exitCode)
        {
            ProcessStartInfo info = new ProcessStartInfo(Exe(), args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using (Process p = Process.Start(info))
            {
                string text = p.StandardOutput.ReadToEnd();
                Assert.True(p.WaitForExit(30000), "the CE exe did not exit in 30 s");
                exitCode = p.ExitCode;
                return text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            }
        }

        /// <summary>Tells the two runs apart: net48 must run the CF binary, and net10.0 must not.</summary>
        [Fact]
        public void This_run_loads_the_build_it_claims_to_test()
        {
            var mscorlib = typeof(NetSec.Trace.TraceEvent).Assembly.GetReferencedAssemblies().FirstOrDefault(a => a.Name == "mscorlib");
            string token = mscorlib == null ? "" : string.Concat(mscorlib.GetPublicKeyToken().Select(b => b.ToString("x2")));
#if NET48
            Assert.Equal("969db8053d3322ac", token);
#else
            Assert.NotEqual("969db8053d3322ac", token);
#endif
        }

        [Fact]
        public void Config_names_clr4_so_the_exe_can_not_exit_silently()
        {
            string config = File.ReadAllText(Exe() + ".config");
            Assert.Contains("v4.0", config);
            Assert.DoesNotContain("v2.0.50727", config);
        }

        [Fact]
        public void Socket_loop_runs_all_four_begin_pairs_with_the_pool_capped_at_25()
        {
            int exit;
            string[] lines = Run("--socket-loop --pool 25", out exit);
            Assert.Equal(0, exit);
            Assert.StartsWith("CE-READY pool=25/25 ", lines[0]);
            Assert.Contains("clr=4.", lines[0]);
            string result = lines.Single(l => l.StartsWith("CE-RESULT "));
            Assert.Contains("\"ok\":true", result);
            Assert.Contains("\"beginConnect\":1", result);
            Assert.Contains("\"beginAccept\":1", result);
            Assert.DoesNotContain("\"beginSend\":0", result);
            Assert.DoesNotContain("\"beginReceive\":0", result);
        }

        /// <summary>
        /// The relay mode is built; BridgeLiveTests.A_cf_binary_relays_a_sealed_pin_and_the_bank_recovers_it runs it end to end. This pins the
        /// refusal when the relay's two ports are missing: exit 1 and one CE-RESULT line that names both options.
        /// </summary>
        [Fact]
        public void The_relay_mode_without_its_ports_is_refused_by_name()
        {
            int exit;
            string[] lines = Run("--pool 25", out exit);
            Assert.Equal(1, exit);
            string result = lines.Last();
            Assert.StartsWith("CE-RESULT {\"ok\":false", result);
            Assert.Contains("\"code\":\"CE_LINK_NOT_BUILT\"", result);
            Assert.Contains("--pinpad and --gateway are required", result);
        }
    }
}
