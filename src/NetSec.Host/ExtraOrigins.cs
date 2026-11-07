using System.Text.RegularExpressions;

namespace NetSec.Host;

/// <summary>
/// NETSEC_ORIGINS (D14 amendment): extra browser origins the Host trusts, for test runs where each worktree serves its own
/// vite preview port. The variable adds to the built-in list and never replaces it. An entry must be exactly
/// <c>http://localhost:PORT</c> or <c>http://127.0.0.1:PORT</c> with PORT 1024-65535 and no leading zero, because a browser sends
/// that canonical form and nothing else can match. Any other entry is dropped, with a reason, and the rest still apply.
/// The token check runs after the origin check, so an extra origin gains nothing without the token. Electron blanks the variable.
/// </summary>
public static class ExtraOrigins
{
    public const string Variable = "NETSEC_ORIGINS";

    static readonly Regex Shape = new(@"^http://(?<host>localhost|127\.0\.0\.1):(?<port>[0-9]{1,5})\z", RegexOptions.CultureInvariant);

    public sealed record Result(IReadOnlyList<string> Accepted, IReadOnlyList<string> Dropped);

    public static Result Parse(string? raw)
    {
        List<string> accepted = [];
        List<string> dropped = [];
        foreach (string entry in (raw ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            Match m = Shape.Match(entry);
            if (!m.Success) { dropped.Add($"{entry} (not http://localhost:PORT or http://127.0.0.1:PORT)"); continue; }
            string digits = m.Groups["port"].Value;
            if (digits.Length > 1 && digits[0] == '0') { dropped.Add($"{entry} (leading zero in the port)"); continue; }
            int port = int.Parse(digits, System.Globalization.CultureInfo.InvariantCulture);
            if (port is < 1024 or > 65535) { dropped.Add($"{entry} (port outside 1024-65535)"); continue; }
            string canonical = $"http://{m.Groups["host"].Value}:{port}";
            if (!accepted.Contains(canonical)) accepted.Add(canonical);
        }
        return new Result(accepted, dropped);
    }
}
