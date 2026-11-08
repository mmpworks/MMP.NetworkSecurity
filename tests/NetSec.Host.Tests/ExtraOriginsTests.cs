using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>NETSEC_ORIGINS (D14 amendment): extra browser origins for test runs. Jared's review items 1-4 are pinned here.</summary>
    public class ExtraOriginsParseTests
    {
        [Fact]
        public void Unset_or_blank_adds_nothing()
        {
            Assert.Empty(ExtraOrigins.Parse(null).Accepted);
            Assert.Empty(ExtraOrigins.Parse("").Accepted);
            Assert.Empty(ExtraOrigins.Parse("  , ,").Accepted);
            Assert.Empty(ExtraOrigins.Parse("").Dropped);
        }

        [Fact]
        public void Listed_localhost_and_loopback_origins_are_accepted_in_canonical_form()
        {
            ExtraOrigins.Result r = ExtraOrigins.Parse(" http://localhost:4181 , http://127.0.0.1:4182 ");
            Assert.Equal(new[] { "http://localhost:4181", "http://127.0.0.1:4182" }, r.Accepted);
            Assert.Empty(r.Dropped);
        }

        [Theory]
        [InlineData("https://localhost:4181")]
        [InlineData("http://localhost:4181/")]
        [InlineData("http://localhost:4181/path")]
        [InlineData("HTTP://localhost:4181")]
        [InlineData("http://LOCALHOST:4181")]
        [InlineData("http://localhost:04181")]
        [InlineData("http://localhost:1023")]
        [InlineData("http://localhost:65536")]
        [InlineData("http://localhost:99999")]
        [InlineData("http://localhost:٤١٨١")]   // Arabic-Indic digits: .NET \d matches them and int.Parse then throws
        [InlineData("http://localhost:0664066106680661")]   // Arabic-Indic digits: .NET d matches them, int.Parse then throws
        [InlineData("http://localhost")]
        [InlineData("http://evil.example:4181")]
        [InlineData("http://localhost.evil.example:4181")]
        [InlineData("http://*:4181")]
        [InlineData("file://")]
        [InlineData("null")]
        [InlineData("*")]
        public void A_malformed_or_out_of_range_entry_is_dropped_with_a_reason(string entry)
        {
            ExtraOrigins.Result r = ExtraOrigins.Parse(entry);
            Assert.Empty(r.Accepted);
            Assert.Single(r.Dropped);
            Assert.Contains(entry.Trim(), r.Dropped[0]);
        }

        [Fact]
        public void A_bad_entry_does_not_cancel_its_neighbours()
        {
            ExtraOrigins.Result r = ExtraOrigins.Parse("http://localhost:4181,https://x:1,http://127.0.0.1:4182");
            Assert.Equal(new[] { "http://localhost:4181", "http://127.0.0.1:4182" }, r.Accepted);
            Assert.Single(r.Dropped);
        }

        [Fact]
        public void A_repeated_entry_is_kept_once()
        {
            Assert.Single(ExtraOrigins.Parse("http://localhost:4181,http://localhost:4181").Accepted);
        }
    }

    public sealed class OriginsHostFixture : HostFixture
    {
        public OriginsHostFixture() : base(new Dictionary<string, string>
        {
            ["NETSEC_ORIGINS"] = "http://localhost:4181,http://127.0.0.1:4182,HTTP://localhost:4183,http://localhost:4184/,http://localhost:04185",
        }) { }
    }

    [Collection("ExtraOriginsHosts")]   // one collection: these three live Hosts start one after another, not beside the rest of the suite's burst
    public class ExtraOriginsLiveTests(OriginsHostFixture host) : IClassFixture<OriginsHostFixture>
    {
        async Task<(int Status, string Body, string Allow)> Get(string origin, bool withToken = true)
        {
            using HttpClient http = new HttpClient();
            using HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{host.Port}/api/health");
            req.Headers.TryAddWithoutValidation("Origin", origin);
            if (withToken) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
            using HttpResponseMessage res = await http.SendAsync(req);
            res.Headers.TryGetValues("Access-Control-Allow-Origin", out IEnumerable<string> allow);
            return ((int)res.StatusCode, await res.Content.ReadAsStringAsync(), allow?.FirstOrDefault());
        }

        [Theory]
        [InlineData("http://localhost:4180")]
        [InlineData("http://localhost:5173")]
        [InlineData("file://")]
        [InlineData("null")]
        public async Task The_default_origins_stay_allowed_when_extras_are_set(string origin)
        {
            (int status, _, string allow) = await Get(origin);
            Assert.Equal(200, status);
            Assert.Equal(origin, allow);
        }

        [Theory]
        [InlineData("http://localhost:4181")]
        [InlineData("http://127.0.0.1:4182")]
        public async Task A_listed_origin_is_allowed_and_echoed(string origin)
        {
            (int status, _, string allow) = await Get(origin);
            Assert.Equal(200, status);
            Assert.Equal(origin, allow);
        }

        [Fact]
        public async Task A_listed_origin_still_needs_the_token()
        {
            (int status, string body, _) = await Get("http://localhost:4181", withToken: false);
            Assert.Equal(401, status);
            Assert.Contains("HOST_TOKEN_REFUSED", body);
        }

        [Theory]
        [InlineData("http://127.0.0.1:4181")]   // only localhost:4181 is listed; the browser treats the two hosts as different origins
        [InlineData("http://localhost:4182")]
        [InlineData("http://localhost:4183")]   // uppercase entry was dropped
        [InlineData("http://localhost:4184")]   // trailing-slash entry was dropped
        [InlineData("http://localhost:4185")]   // leading-zero entry was dropped
        [InlineData("http://localhost:4199")]
        [InlineData("http://evil.example:4181")]
        public async Task An_unlisted_or_dropped_origin_is_refused(string origin)
        {
            (int status, string body, string allow) = await Get(origin);
            Assert.Equal(403, status);
            Assert.Contains("HOST_ORIGIN_REFUSED", body);
            Assert.Null(allow);
        }

        [Fact]
        public void The_start_log_names_each_accepted_and_each_dropped_entry()
        {
            string line = Assert.Single(host.StartLines, l => l.StartsWith("HOST-ORIGINS"));
            Assert.Contains("http://localhost:4181", line);
            Assert.Contains("http://127.0.0.1:4182", line);
            Assert.Contains("HTTP://localhost:4183", line);
            Assert.Contains("http://localhost:04185", line);
        }
    }

    [Collection("ExtraOriginsHosts")]
    public class ExtraOriginsUnsetLiveTests(HostFixture host) : IClassFixture<HostFixture>
    {
        [Fact]
        public async Task With_the_variable_unset_an_extra_origin_is_refused_and_nothing_is_logged()
        {
            using HttpClient http = new HttpClient();
            using HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{host.Port}/api/health");
            req.Headers.TryAddWithoutValidation("Origin", "http://localhost:4181");
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
            using HttpResponseMessage res = await http.SendAsync(req);
            Assert.Equal(403, (int)res.StatusCode);
            Assert.DoesNotContain(host.StartLines, l => l.StartsWith("HOST-ORIGINS"));
        }
    }

    public sealed class BlankOriginsHostFixture : HostFixture
    {
        public BlankOriginsHostFixture() : base(new Dictionary<string, string> { ["NETSEC_ORIGINS"] = "" }) { }
    }

    /// <summary>Electron sets NETSEC_ORIGINS to an empty string for the Host it spawns. The Host must read that as unset.</summary>
    [Collection("ExtraOriginsHosts")]
    public class ExtraOriginsBlankLiveTests(BlankOriginsHostFixture host) : IClassFixture<BlankOriginsHostFixture>
    {
        [Fact]
        public async Task An_empty_variable_reads_as_unset_nothing_logged_and_an_extra_origin_refused()
        {
            using HttpClient http = new HttpClient();
            using HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{host.Port}/api/health");
            req.Headers.TryAddWithoutValidation("Origin", "http://localhost:4181");
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
            using HttpResponseMessage res = await http.SendAsync(req);
            Assert.Equal(403, (int)res.StatusCode);
            Assert.DoesNotContain(host.StartLines, l => l.StartsWith("HOST-ORIGINS"));
        }
    }

    public class ElectronOriginsPinTests
    {
        [Fact]
        public void Electron_blanks_NETSEC_ORIGINS_for_the_Host_it_spawns()
        {
            // A developer who exported NETSEC_ORIGINS for the test harness must not widen the desktop app's Host.
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "app", "electron", "main.cjs"))) dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            string main = File.ReadAllText(Path.Combine(dir!, "app", "electron", "main.cjs"));
            Assert.Contains("NETSEC_ORIGINS: ''", main);
        }
    }
}
