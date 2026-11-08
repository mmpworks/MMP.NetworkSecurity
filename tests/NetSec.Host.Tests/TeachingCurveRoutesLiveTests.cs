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
        Assert.Equal(7, toy.GetProperty("ecdsa").GetProperty("recovery").GetProperty("privateKey").GetInt32());

        (int realStatus, JsonElement real, string realCache) = await Get(host, "/api/walk/real-curve");
        Assert.Equal(200, realStatus);
        Assert.Contains("no-store", realCache);
        Assert.Equal("chord", real.GetProperty("chord").GetProperty("kind").GetString());
        Assert.Equal(real.GetProperty("upper").GetArrayLength(), real.GetProperty("lower").GetArrayLength());
        Assert.Equal(4, real.GetProperty("samples").GetArrayLength());
    }

    [Fact]
    public async Task A_pick_returns_the_engines_addition_and_a_bad_pick_is_refused_by_name()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        (int status, JsonElement twice, string cache) = await Get(host, "/api/walk/toy-curve/add?p=0&q=0");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("double", twice.GetProperty("step").GetProperty("kind").GetString());
        Assert.True(twice.GetProperty("step").GetProperty("inverse").GetProperty("rows").GetArrayLength() > 0);

        (_, JsonElement withO, _) = await Get(host, "/api/walk/toy-curve/add?p=18&q=3");
        Assert.Equal("identity", withO.GetProperty("step").GetProperty("kind").GetString());
        Assert.Equal(3, withO.GetProperty("resultIndex").GetInt32());

        foreach (string bad in new[] { "p=19&q=0", "p=-1&q=0", "p=abc&q=0", "q=0", "p=0" })
        {
            (int refused, JsonElement body, _) = await Get(host, "/api/walk/toy-curve/add?" + bad);
            Assert.True(refused == 400, bad + " got " + refused);
            Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        }
    }
}
