using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice P7's Diffie-Hellman route on a live Host. It runs on public practice exponents, so it stays open with Show keys off.</summary>
public class DhWalkRoutesLiveTests
{
    static async Task<(int Status, JsonElement Body, string CacheControl)> Get(SecurityLiveTests.Host host, string path)
    {
        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Get, $"http://127.0.0.1:{host.Port}{path}");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
        HttpResponseMessage r = await http.SendAsync(request);
        JsonElement body = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.Clone();
        return ((int)r.StatusCode, body, r.Headers.CacheControl?.ToString() ?? "");
    }

    static string Rfc3526PrimeHex()
    {
        string dir = AppContext.BaseDirectory;
        while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "dh-group14-rfc3526.nsv"))) dir = Path.GetDirectoryName(dir);
        Assert.True(dir != null, "acceptance/vectors/dh-group14-rfc3526.nsv was not found above the test folder");
        string line = File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "dh-group14-rfc3526.nsv")).Select(l => l.Trim()).First(l => l.StartsWith("p ="));
        return line[(line.IndexOf('=') + 1)..].Trim().ToLowerInvariant();
    }

    [Fact]
    public async Task Both_groups_answer_with_Show_keys_off_with_numbers_in_hex_and_decimal()
    {
        using SecurityLiveTests.Host host = new();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        (int status, JsonElement small, string cache) = await Get(host, "/api/walk/dh?group=small");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("practice", small.GetProperty("keySource").GetString());
        Assert.Equal("467", small.GetProperty("prime").GetProperty("dec").GetString());
        Assert.Equal("116", small.GetProperty("client").GetProperty("public").GetProperty("result").GetProperty("dec").GetString());
        Assert.Equal("429", small.GetProperty("server").GetProperty("public").GetProperty("result").GetProperty("dec").GetString());
        Assert.Equal("412", small.GetProperty("client").GetProperty("shared").GetProperty("result").GetProperty("dec").GetString());
        Assert.Equal("412", small.GetProperty("server").GetProperty("shared").GetProperty("result").GetProperty("dec").GetString());
        Assert.Equal("01d3", small.GetProperty("prime").GetProperty("hex").GetString());

        (status, JsonElement g14, cache) = await Get(host, "/api/walk/dh?group=group14");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal(Rfc3526PrimeHex(), g14.GetProperty("prime").GetProperty("hex").GetString());
        Assert.Equal(32, g14.GetProperty("client").GetProperty("public").GetProperty("rows").GetArrayLength());
        Assert.Equal(g14.GetProperty("client").GetProperty("shared").GetProperty("result").GetProperty("hex").GetString(),
            g14.GetProperty("server").GetProperty("shared").GetProperty("result").GetProperty("hex").GetString());
    }

    [Theory]
    [InlineData("/api/walk/dh")]
    [InlineData("/api/walk/dh?group=group15")]
    public async Task An_unknown_group_is_a_400_with_its_code(string path)
    {
        using SecurityLiveTests.Host host = new();
        (int status, JsonElement body, string cache) = await Get(host, path);
        Assert.Equal(400, status);
        Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
