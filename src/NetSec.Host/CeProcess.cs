using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using NetSec.Bridge;
using NetSec.Errors;

namespace NetSec.Host;

/// <summary>Starts the CF-compiled exe and watches it from outside. No ready line in 10 s is CE_DEVICE_SILENT, because the exe can exit 0 with no output on a wrong runtime config.</summary>
public sealed class CeProcess
{
    public const string Label = "CF-compiled, run on the desktop CLR, never run on CE";
    static readonly TimeSpan ReadyLimit = TimeSpan.FromSeconds(10);

    readonly Lock _gate = new();
    Process? _process;
    string? _ready, _result, _error;

    public static string? FindExe()
    {
        string? configured = Environment.GetEnvironmentVariable("NETSEC_CE_EXE");
        if (configured is not null) return configured;
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "src", "NetSec.CeDevice", "bin", "Release", "net35", "NetSec.CeDevice.exe");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    public async Task<object> StartAsync()
    {
        string? exe = FindExe();
        if (exe is null)
        {
            lock (_gate) _error = "CE_EXE_NOT_BUILT";
            return Status();
        }
        Stop();
        Process process = new()
        {
            StartInfo = new ProcessStartInfo(exe, "--socket-loop --pool 25")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
            EnableRaisingEvents = true,
        };
        TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        process.OutputDataReceived += (_, e) => OnLine(e.Data, ready);
        lock (_gate) { _process = process; _ready = null; _result = null; _error = null; }
        process.Start();
        process.BeginOutputReadLine();
        if (await Task.WhenAny(ready.Task, Task.Delay(ReadyLimit)) != ready.Task)
            lock (_gate) _error = ErrorCodes.CeDeviceSilent;
        return Status();
    }

    public void Stop()
    {
        Process? process;
        lock (_gate) { process = _process; _process = null; }
        if (process is null || process.HasExited) return;
        process.Kill(entireProcessTree: true);
    }

    public object Status()
    {
        string? exe = FindExe();
        lock (_gate)
        {
            return new
            {
                running = _process is { HasExited: false },
                pid = _process?.Id,
                exePath = exe,
                mscorlibToken = exe is null ? null : MscorlibToken(exe),
                ready = _ready,
                result = _result,
                error = _error,
                label = Label,
                profile = DeviceProfile.Ce.Name,
                poolCap = DeviceProfile.Ce.PoolThreads,
                ramBytes = DeviceProfile.Ce.RamBytes,
            };
        }
    }

    void OnLine(string? line, TaskCompletionSource ready)
    {
        if (line is null) return;
        lock (_gate)
        {
            if (line.StartsWith("CE-READY", StringComparison.Ordinal)) { _ready = line; ready.TrySetResult(); }
            else if (line.StartsWith("CE-RESULT ", StringComparison.Ordinal)) _result = line["CE-RESULT ".Length..];
        }
    }

    static string? MscorlibToken(string path)
    {
        using FileStream stream = File.OpenRead(path);
        using PEReader pe = new(stream);
        MetadataReader reader = pe.GetMetadataReader();
        foreach (AssemblyReferenceHandle handle in reader.AssemblyReferences)
        {
            AssemblyReference reference = reader.GetAssemblyReference(handle);
            if (reader.GetString(reference.Name) == "mscorlib")
                return Convert.ToHexStringLower(reader.GetBlobBytes(reference.PublicKeyOrToken));
        }
        return null;
    }
}
