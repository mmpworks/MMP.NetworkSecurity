using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice P4's key schedule route on a live Host. It runs on RFC 8448's public inputs, so it stays open with Show keys off.</summary>
public class Tls13WalkRoutesLiveTests
{
    static Dictionary<string, string> Vectors()
    {
        string dir = AppContext.BaseDirectory;
        while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "tls13-rfc8448.nsv"))) dir = Path.GetDirectoryName(dir);
        Assert.True(dir != null, "acceptance/vectors/tls13-rfc8448.nsv was not found above the test folder");
        Dictionary<string, string> v = [];
        foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "tls13-rfc8448.nsv")))
        {
            string line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq > 0 && !line.StartsWith('#')) v[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }
        return v;
    }

    [Fact]
    public async Task The_schedule_route_answers_with_Show_keys_off_and_every_step_matches_rfc_8448()
    {
        using SecurityLiveTests.Host host = new();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Get, $"http://127.0.0.1:{host.Port}/api/walk/tls13/schedule");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
        HttpResponseMessage r = await http.SendAsync(request);
        Assert.Equal(200, (int)r.StatusCode);
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString() ?? "");
        JsonElement body = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("rfc8448", body.GetProperty("keySource").GetString());

        Dictionary<string, string> v = Vectors();
        JsonElement[] steps = [.. body.GetProperty("steps").EnumerateArray()];
        Assert.Equal(21, steps.Length);
        foreach (JsonElement s in steps)
        {
            string name = s.GetProperty("name").GetString();
            Assert.Equal(v[name], s.GetProperty("output").GetString());
        }
        JsonElement cHs = steps.Single(s => s.GetProperty("name").GetString() == "c_hs_traffic");
        Assert.Equal("DeriveSecret", cHs.GetProperty("kind").GetString());
        Assert.Equal("c hs traffic", cHs.GetProperty("label").GetString());
        Assert.Equal(v["handshake_secret"], cHs.GetProperty("secret").GetString());
    }
}
