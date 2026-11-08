using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The ECDSA P-256 walk route on a live Host. It runs on RFC 6979's published test key, so it stays open with Show keys off.</summary>
public class EcdsaWalkRoutesLiveTests
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
    public async Task Sample_answers_with_Show_keys_off_and_the_rfc_signature()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);
        (int status, JsonElement body, string cache) = await Get(host, "/api/walk/ecdsa?message=sample");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("rfc6979", body.GetProperty("keySource").GetString());
        // RFC 6979 section A.2.5, SHA-256, message "sample".
        Assert.Equal("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60", body.GetProperty("k").GetString());
        Assert.Equal("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", body.GetProperty("r").GetString());
        Assert.Equal("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", body.GetProperty("s").GetString());
        Assert.Equal(256, body.GetProperty("kG").GetArrayLength());
        Assert.True(body.GetProperty("verify").GetProperty("valid").GetBoolean());
        Assert.True(body.GetProperty("rfc6979").GetArrayLength() >= 5);
    }

    [Theory]
    [InlineData("/api/walk/ecdsa")]
    [InlineData("/api/walk/ecdsa?message=other")]
    public async Task An_unknown_message_is_a_400_with_its_code(string path)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int status, JsonElement body, string cache) = await Get(host, path);
        Assert.Equal(400, status);
        Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
