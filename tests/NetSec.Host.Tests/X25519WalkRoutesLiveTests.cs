using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice P8's X25519 ladder route on a live Host. It runs on RFC 7748's public test scalars, so it stays open with Show keys off.</summary>
public class X25519WalkRoutesLiveTests
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

    [Fact]
    public async Task The_shared_step_answers_with_Show_keys_off_with_255_rows_and_the_rfc_secret()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);
        (int status, JsonElement body, string cache) = await Get(host, "/api/walk/x25519?step=shared");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("rfc7748", body.GetProperty("keySource").GetString());
        Assert.Equal("little-endian", body.GetProperty("byteOrder").GetString());
        // RFC 7748 section 6.1's shared secret K.
        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", body.GetProperty("result").GetString());
        JsonElement rows = body.GetProperty("rows");
        Assert.Equal(255, rows.GetArrayLength());
        Assert.Equal(254, rows[0].GetProperty("bit").GetInt32());
        Assert.True(rows[0].GetProperty("isOne").GetBoolean());
        Assert.Equal(body.GetProperty("result").GetString(), rows[254].GetProperty("u2").GetString());
    }

    [Theory]
    [InlineData("/api/walk/x25519")]
    [InlineData("/api/walk/x25519?step=carol")]
    public async Task An_unknown_step_is_a_400_with_its_code(string path)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int status, JsonElement body, string cache) = await Get(host, path);
        Assert.Equal(400, status);
        Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
