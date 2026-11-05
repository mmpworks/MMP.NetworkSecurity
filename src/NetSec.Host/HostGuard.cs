using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetSec.Host;

/// <summary>
/// D14. A browser page can open a loopback socket, and this API returns keys. So every request passes two checks: an allowed
/// Origin when the request has one, and the session token. A preflight carries no token, so it passes on the Origin alone.
/// </summary>
public sealed class HostGuard(string token)
{
    public const string OriginRefused = "HOST_ORIGIN_REFUSED";
    public const string TokenRefused = "HOST_TOKEN_REFUSED";

    // A file:// page sends "file://" on a WebSocket and "null" on a fetch. The token still guards a sandboxed "null" page.
    static readonly HashSet<string> AllowedOrigins = new(StringComparer.OrdinalIgnoreCase)
    {
        "file://", "null", "http://localhost:4180", "http://localhost:5173",
    };

    readonly byte[] _token = Encoding.UTF8.GetBytes(token);

    public async Task Invoke(HttpContext ctx, RequestDelegate next)
    {
        string? origin = ctx.Request.Headers.Origin.FirstOrDefault();
        if (origin is not null && !AllowedOrigins.Contains(origin))
        {
            await Refuse(ctx, 403, OriginRefused, "This origin may not call the Host.");
            return;
        }
        if (origin is not null) AddCorsHeaders(ctx, origin);
        if (HttpMethods.IsOptions(ctx.Request.Method))
        {
            ctx.Response.StatusCode = 204;
            return;
        }
        if (!HasToken(ctx.Request))
        {
            await Refuse(ctx, 401, TokenRefused, "The session token is missing or wrong.");
            return;
        }
        await next(ctx);
    }

    static void AddCorsHeaders(HttpContext ctx, string origin)
    {
        ctx.Response.Headers.AccessControlAllowOrigin = origin;
        ctx.Response.Headers.AccessControlAllowHeaders = "Authorization, Content-Type";
        ctx.Response.Headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
        ctx.Response.Headers.Vary = "Origin";
    }

    bool HasToken(HttpRequest request)
    {
        string? presented = request.Path.StartsWithSegments("/ws")
            ? request.Query["token"].FirstOrDefault()
            : BearerOf(request.Headers.Authorization.FirstOrDefault());
        return presented is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), _token);
    }

    static string? BearerOf(string? header)
    {
        const string prefix = "Bearer ";
        return header is not null && header.StartsWith(prefix, StringComparison.Ordinal) ? header[prefix.Length..] : null;
    }

    static Task Refuse(HttpContext ctx, int status, string code, string message)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            code,
            message,
            retryable = false,
            requestId = ctx.TraceIdentifier,
        }, JsonSerializerOptions.Web));
    }
}
