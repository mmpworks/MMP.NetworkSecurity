using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Slice W1b's two text routes on a live Host. Each runs under the public practice key and reads no run, so each stays open with Show keys off (design section 2.2g).</summary>
public class AesTypedRoutesLiveTests
{
    static async Task<(int Status, JsonElement Body, string CacheControl)> Post(SecurityLiveTests.Host host, string path, string json)
    {
        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Post, $"http://127.0.0.1:{host.Port}{path}") { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + host.Token);
        HttpResponseMessage r = await http.SendAsync(request);
        JsonElement body = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.Clone();
        return ((int)r.StatusCode, body, r.Headers.CacheControl?.ToString() ?? "");
    }

    [Fact]
    public async Task Both_text_routes_answer_with_Show_keys_off_and_name_the_practice_key()
    {
        using SecurityLiveTests.Host host = new();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        (int status, JsonElement typed, string cache) = await Post(host, "/api/walk/aes/typed-block", "{\"text\":\"Pump\"}");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("typed-practice", typed.GetProperty("walk").GetProperty("keySource").GetString());
        Assert.Equal("notSent", typed.GetProperty("walk").GetProperty("wire").GetProperty("status").GetString());
        Assert.Equal(12, typed.GetProperty("cut").GetProperty("paddingBytes").GetInt32());
        Assert.Equal("50756d700c0c0c0c0c0c0c0c0c0c0c0c", typed.GetProperty("walk").GetProperty("inputHex").GetString());

        (status, JsonElement longText, cache) = await Post(host, "/api/walk/aes/long-text", "{\"text\":\"Pump four is ok.Pump four is ok.\",\"flipBlock\":0,\"flipBit\":0}");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("typed-practice", longText.GetProperty("keySource").GetString());
        Assert.Equal(3, longText.GetProperty("blocks").GetInt32());
        Assert.Equal(1, longText.GetProperty("ecbRepeats").GetInt32());
        Assert.Equal(3, longText.GetProperty("flipped").GetProperty("cbcBlocksChanged").GetInt32());
    }

    [Fact]
    public async Task Both_text_routes_follow_the_key_size_and_default_to_128_bits()
    {
        using SecurityLiveTests.Host host = new();
        (int status, JsonElement typed, _) = await Post(host, "/api/walk/aes/typed-block", "{\"text\":\"Pump\",\"keyBits\":256}");
        Assert.Equal(200, status);
        Assert.Equal(256, typed.GetProperty("walk").GetProperty("keyBits").GetInt32());
        Assert.Equal(14, typed.GetProperty("walk").GetProperty("rounds").GetInt32());
        Assert.Equal(60, typed.GetProperty("walk").GetProperty("keyWords").GetArrayLength());   // AES-256 expands to 4 x (14 + 1) words

        (status, typed, _) = await Post(host, "/api/walk/aes/typed-block", "{\"text\":\"Pump\"}");
        Assert.Equal(200, status);
        Assert.Equal(128, typed.GetProperty("walk").GetProperty("keyBits").GetInt32());

        (status, JsonElement longText, _) = await Post(host, "/api/walk/aes/long-text", "{\"text\":\"Pump four is ok.\",\"keyBits\":192}");
        Assert.Equal(200, status);
        Assert.Equal(192, longText.GetProperty("keyBits").GetInt32());
    }

    [Theory]
    [InlineData("/api/walk/aes/typed-block", "{\"text\":\"Pump\",\"keyBits\":100}", "WALK_BAD_ARGUMENT")]
    [InlineData("/api/walk/aes/long-text", "{\"text\":\"Pump\",\"keyBits\":512}", "WALK_BAD_ARGUMENT")]
    [InlineData("/api/walk/aes/typed-block", "{\"text\":\"\"}", "WALK_TEXT_EMPTY")]
    [InlineData("/api/walk/aes/typed-block", "{}", "WALK_TEXT_EMPTY")]
    [InlineData("/api/walk/aes/long-text", "{\"text\":\"Pump\",\"flipBlock\":0,\"flipBit\":40}", "WALK_BAD_ARGUMENT")]
    [InlineData("/api/walk/aes/long-text", "{\"text\":\"Pump\",\"flipBlock\":134217729,\"flipBit\":0}", "WALK_BAD_ARGUMENT")]   // Wrapped negative before the fix: a 500
    public async Task A_text_the_routes_cannot_walk_is_a_400_with_its_code(string path, string json, string code)
    {
        using SecurityLiveTests.Host host = new();
        (int status, JsonElement body, string cache) = await Post(host, path, json);
        Assert.Equal(400, status);
        Assert.Equal(code, body.GetProperty("code").GetString());
        Assert.Contains("no-store", cache);
    }
}
