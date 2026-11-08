using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The DES walk route on a live Host. It runs on NIST CAVP's published keys, so it stays open with Show keys off.</summary>
public class DesWalkRoutesLiveTests
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
    public async Task Varkey_answers_with_Show_keys_off_and_the_cavp_ciphertext()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);
        (int status, JsonElement body, string cache) = await Get(host, "/api/walk/des?name=varkey");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("cavp", body.GetProperty("keySource").GetString());
        // NIST CAVP TECBvarkey, first row.
        Assert.Equal("95a8d72813daa94d", body.GetProperty("ciphertext").GetString());
        Assert.Equal(body.GetProperty("ciphertext").GetString(), body.GetProperty("output").GetString());
        Assert.Equal(16, body.GetProperty("rounds").GetArrayLength());
        Assert.Equal(16, body.GetProperty("schedule").GetProperty("rounds").GetArrayLength());
        JsonElement firstBox = body.GetProperty("rounds")[0].GetProperty("boxes")[0];
        Assert.Equal(6, firstBox.GetProperty("six").GetString()!.Length);
        Assert.Equal(12, body.GetProperty("rounds")[0].GetProperty("key").GetString()!.Length);
    }

    [Theory]
    [InlineData("/api/walk/des")]
    [InlineData("/api/walk/des?name=other")]
    public async Task An_unknown_name_is_a_400_with_its_code(string path)
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int status, JsonElement body, string cache) = await Get(host, path);
        Assert.Equal(400, status);
        Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
