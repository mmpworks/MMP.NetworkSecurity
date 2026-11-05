using System.Diagnostics;

namespace NetSec.Host.Security;

/// <summary>Finds OpenSSL and runs it with a 30 s limit. The flows' checks and the vault exercise judge with the same program.</summary>
public sealed class OpenSslTool(Func<string, string?> env)
{
    public string? Locate()
    {
        string? set = env("NETSEC_OPENSSL");
        if (!string.IsNullOrEmpty(set)) return File.Exists(set) ? set : null;
        const string Pinned = @"C:\Program Files\Git\mingw64\bin\openssl.exe";
        return File.Exists(Pinned) ? Pinned : null;
    }

    public const int CouldNotStart = -2, TimedOut = -1;

    static Process? TryStart(ProcessStartInfo info)
    {
        try { return Process.Start(info); }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    public static (int Code, string Output) Run(string exe, string arguments, string dir)
    {
        ProcessStartInfo info = new(exe, arguments) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using Process? process = TryStart(info);
        if (process is null) return (CouldNotStart, "the tool could not start");
        Task<string> errors = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            return (TimedOut, "the tool did not finish in 30 s");
        }
        return (process.ExitCode, (output + errors.Result).Trim());
    }
}
