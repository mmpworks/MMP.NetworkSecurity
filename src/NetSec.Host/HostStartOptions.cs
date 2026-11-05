using System.Security.Cryptography;

namespace NetSec.Host;

/// <summary>
/// The port and the session token. A flag wins over its environment variable, so a person or a suite can set them on the
/// command line and Electron's env route keeps working (docs/program-design.md section 11).
/// </summary>
public sealed record HostStartOptions(int Port, string Token, bool TokenWasGenerated)
{
    public const int DefaultPort = 5180;

    public static HostStartOptions From(string[] args, Func<string, string?> env)
    {
        string? portText = Flag(args, "--port") ?? env("NETSEC_PORT");
        string? token = Flag(args, "--token") ?? env("NETSEC_TOKEN");
        int port = portText is null ? DefaultPort : ParsePort(portText);
        return string.IsNullOrEmpty(token)
            ? new HostStartOptions(port, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)), true)
            : new HostStartOptions(port, token, false);
    }

    static string? Flag(string[] args, string name)
    {
        int at = Array.IndexOf(args, name);
        if (at < 0) return null;
        if (at + 1 >= args.Length) throw new ArgumentException($"{name} needs a value.");
        return args[at + 1];
    }

    static int ParsePort(string text) =>
        int.TryParse(text, out int port) && port is > 0 and < 65536
            ? port
            : throw new ArgumentException($"The port must be a number from 1 to 65535. It was '{text}'.");
}
