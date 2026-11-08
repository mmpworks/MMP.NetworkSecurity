using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The Ed25519 walk route on a live Host. It runs on RFC 8032's published test keys, so it stays open with Show keys off.</summary>
public class Ed25519WalkRoutesLiveTests
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
    public async Task Test_1_answers_with_Show_keys_off_and_the_rfc_signature()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);
        (int status, JsonElement body, string cache) = await Get(host, "/api/walk/ed25519?test=1");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("rfc8032", body.GetProperty("keySource").GetString());
        // RFC 8032 section 7.1, TEST 1.
        Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", body.GetProperty("publicKey").GetString());
        Assert.Equal("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", body.GetProperty("signature").GetString());
        Assert.True(body.GetProperty("verify").GetProperty("valid").GetBoolean());
        Assert.Equal(body.GetProperty("rPoint").GetString(), body.GetProperty("verify").GetProperty("rPrime").GetString());
    }

    [Theory]
    [InlineData("/api/walk/ed25519")]
    [InlineData("/api/walk/ed25519?test=4")]
    public async Task An_unknown_test_is_a_400_with_its_code(string path)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int status, JsonElement body, string cache) = await Get(host, path);
        Assert.Equal(400, status);
        Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
