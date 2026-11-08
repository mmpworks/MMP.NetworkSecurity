using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// The seal-chain walk on the fixture chain, and both P6 routes on a live Host. The chain's referee composes each row's text from its fields here and
/// hashes it with the BCL's SHA-256, apart from AuditChain's own composition.
/// </summary>
public class HmacChainWalkTests
{
    static string Sha(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    [Theory]
    [InlineData("none", 0)]
    [InlineData("middle", 3)]
    [InlineData("newest", 0)]
    public void Each_link_matches_an_independent_hash_and_the_edit_shows_where_the_chain_breaks(string edit, long firstBad)
    {
        SealChainWalkResult w = SealChainWalks.Build(edit);
        Assert.Equal(Sha("netsec-vault-audit-seed-v1"), w.Seed);
        Assert.Equal(4, w.Links.Count);
        string expected = w.Seed;
        foreach (SealChainLink l in w.Links)
        {
            string text = string.Join("\n", l.Row.PrevHash, l.Row.Seq, l.Row.At, l.Row.Caller, l.Row.Op, l.Row.Name, l.Row.Version?.ToString() ?? "", l.Row.Result, l.Row.Detail);
            Assert.Equal(text, l.Text);
            Assert.Equal(Sha(text), l.Hash);
            Assert.Equal(expected, l.ExpectedPrevHash);
            Assert.Equal(l.StoredPrevHash == expected, l.LinkHolds);
            expected = l.Hash;
        }
        Assert.Equal(firstBad, w.FirstBadSeq);
        Assert.Equal(firstBad == 0 ? 4 : 3, w.Links.Count(l => l.LinkHolds));
        // The newest-row edit changes that row's hash, and no row after it holds the old one, so the chain reads whole.
        if (edit == "newest") Assert.EndsWith("(edited)", w.Links[^1].Row.Detail);
    }

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
    public async Task Both_routes_answer_with_Show_keys_off_and_bad_arguments_are_refused_by_name()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);

        (int status, JsonElement hmac, string cache) = await Get(host, "/api/walk/hmac?case=1");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        Assert.Equal("rfc4231", hmac.GetProperty("keySource").GetString());
        // RFC 4231 section 4.2, test case 1.
        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hmac.GetProperty("mac").GetString());
        Assert.Equal(128, hmac.GetProperty("innerPad").GetString()!.Length);

        (int chainStatus, JsonElement chain, string chainCache) = await Get(host, "/api/walk/seal-chain?edit=middle");
        Assert.Equal(200, chainStatus);
        Assert.Contains("no-store", chainCache);
        Assert.Equal("fixture", chain.GetProperty("source").GetString());
        Assert.Equal(3, chain.GetProperty("firstBadSeq").GetInt64());
        Assert.False(chain.GetProperty("links")[2].GetProperty("linkHolds").GetBoolean());

        (int whole, JsonElement plain, _) = await Get(host, "/api/walk/seal-chain");
        Assert.Equal(200, whole);
        Assert.Equal(0, plain.GetProperty("firstBadSeq").GetInt64());

        foreach (string bad in new[] { "/api/walk/hmac", "/api/walk/hmac?case=5", "/api/walk/seal-chain?edit=all" })
        {
            (int refused, JsonElement body, _) = await Get(host, bad);
            Assert.True(refused == 400, bad + " got " + refused);
            Assert.Equal("WALK_BAD_ARGUMENT", body.GetProperty("code").GetString());
        }
    }

    [Fact]
    public async Task The_sha256_walk_answers_with_Show_keys_off_with_the_fips_digest()
    {
        using SecurityLiveTests.Host host = await SecurityLiveTests.Host.StartAsync();
        (int off, _) = await host.Put("/api/security/show-keys", "{\"on\":false}");
        Assert.Equal(200, off);
        (int status, JsonElement body, string cache) = await Get(host, "/api/walk/sha256?name=two-block");
        Assert.Equal(200, status);
        Assert.Contains("no-store", cache);
        // FIPS 180-4's two-block example.
        Assert.Equal("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", body.GetProperty("digest").GetString());
        Assert.Equal(2, body.GetProperty("blocks").GetArrayLength());
        Assert.Equal(64, body.GetProperty("blocks")[0].GetProperty("rounds").GetArrayLength());
        Assert.Equal(8, body.GetProperty("blocks")[1].GetProperty("hOut")[0].GetString()!.Length);
        (int refused, JsonElement bad, _) = await Get(host, "/api/walk/sha256?name=other");
        Assert.Equal(400, refused);
        Assert.Equal("WALK_BAD_ARGUMENT", bad.GetProperty("code").GetString());
    }
}
