using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice P8a's teaching routes on a live Host. Both serve fixed public values, so both stay open with Show keys off.</summary>
public class TeachingCurveRoutesLiveTests
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
    public async Task Both_routes_answer_with_Show_keys_off()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        (int status, JsonElement toy, string cache) = await Get(host, "/api/walk/toy-curve");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal(18, toy.GetProperty("points").GetArrayLength());
        Assert.Equal(19, toy.GetProperty("hops").GetArrayLength());
        Assert.True(toy.GetProperty("hops")[18].GetProperty("point").GetProperty("infinity").GetBoolean());
        Assert.Equal(13, toy.GetProperty("k").GetInt32());
        Assert.Equal(9, toy.GetProperty("ecdsa").GetProperty("recovery").GetProperty("privateKey").GetInt32());

        (int realStatus, JsonElement real, string realCache) = await Get(host, "/api/walk/real-curve");
        Assert.Equal(200, realStatus);
        Assert.Contains("no-store", realCache);
        Assert.Equal("chord", real.GetProperty("chord").GetProperty("kind").GetString());
        Assert.Equal(real.GetProperty("upper").GetArrayLength(), real.GetProperty("lower").GetArrayLength());
    }
}
