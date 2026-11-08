using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice P4b's TLS 1.1 key-schedule route on a live Host. It runs on the built-in training key, so it stays open with Show keys off.</summary>
public class Tls11WalkRoutesLiveTests
{
    [Fact]
    public async Task The_schedule_answers_with_Show_keys_off_on_the_training_key()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Get, $"http://127.0.0.1:{host.Port}/api/walk/tls11/schedule");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
        HttpResponseMessage r = await http.SendAsync(request);
        JsonElement body = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(200, (int)r.StatusCode);
        Assert.Contains("no-store", r.Headers.CacheControl?.ToString() ?? "");
        Assert.Equal("training", body.GetProperty("keySource").GetString());
        Assert.Equal("server-tls11-rsa", body.GetProperty("serverKeyId").GetString());
        Assert.Equal(96, body.GetProperty("premaster").GetString()!.Length);
        Assert.Equal(770, body.GetProperty("premasterVersion").GetInt32());
        string master = body.GetProperty("masterSecret").GetProperty("value").GetString()!;
        Assert.Equal("CLIENT_RANDOM " + body.GetProperty("clientRandom").GetString() + " " + master, body.GetProperty("keyLogLine").GetString());
        Assert.Equal(32, body.GetProperty("keyBlock").GetProperty("clientKey").GetString()!.Length);
    }
}
