using Microsoft.AspNetCore.Http;

namespace NetSec.Host;

/// <summary>The reply rules every walk route shares: no caching, and an error body with a code, a message, retryable and a request id.</summary>
public static class WalkReplies
{
    public static IResult NoStore(HttpContext http, IResult result)
    {
        http.Response.Headers.CacheControl = "no-store";
        return result;
    }

    public static IResult Refuse(int status, string code, string message, bool retryable = false) =>
        Results.Json(new { code, message, retryable, requestId = Guid.NewGuid().ToString("N") }, statusCode: status);
}
