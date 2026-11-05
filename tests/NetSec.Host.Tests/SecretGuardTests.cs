#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>tools/secret_guard.py on real temp repositories. The words of a PEM header are joined at run time, so this file holds no block for the guard to find.</summary>
public class SecretGuardTests
{
    static readonly string Marker = "PRIV" + "ATE KEY";
    static readonly string Body = Convert.ToBase64String(new byte[48]);

    static string Block(string kind = "") => $"-----BEGIN {kind}{Marker}-----\n{Body}\n-----END {kind}{Marker}-----\n";

    sealed class Repo : IDisposable
    {
        public readonly string Dir = Path.Combine(Path.GetTempPath(), "netsec-guard-" + Guid.NewGuid().ToString("N"));

        public Repo()
        {
            Directory.CreateDirectory(Dir);
            Git("init -q");
            File.WriteAllText(Path.Combine(Dir, ".gitignore"), ".security/\n");
            Git("add .gitignore");
        }

        public void Git(string args)
        {
            (int code, string output) = Run("git", args);
            Assert.True(code == 0, "git " + args + ": " + output);
        }

        public void Stage(string name, byte[] bytes)
        {
            File.WriteAllBytes(Path.Combine(Dir, name), bytes);
            Git("add -- \"" + name + "\"");
        }

        public (int Code, string Output) Guard() => Run("python", "-I \"" + GuardPath() + "\"");

        (int, string) Run(string exe, string args)
        {
            ProcessStartInfo info = new(exe, args) { WorkingDirectory = Dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
            info.Environment["PYTHONUTF8"] = "1";
            using Process p = Process.Start(info)!;
            Task<string> errors = p.StandardError.ReadToEndAsync();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(60_000);
            return (p.ExitCode, output + errors.Result);
        }

        public void Dispose()
        {
            foreach (string f in Directory.GetFiles(Dir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(Dir, true);
        }
    }

    static string GuardPath()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "tools", "secret_guard.py");
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("tools/secret_guard.py");
    }

    static void AssertCaught(Repo repo, string name)
    {
        (int code, string output) = repo.Guard();
        Assert.True(code == 1, "the guard passed " + name + ", exit " + code + ": " + output);
        Assert.Contains(name, output);
    }

    [Fact]
    public void A_clean_repository_passes_and_prose_that_names_the_header_is_no_key()
    {
        using Repo repo = new();
        repo.Stage("doc.md", Encoding.UTF8.GetBytes("A key file starts with -----BEGIN " + Marker + "-----, and that is all this sentence says.\n"));
        repo.Stage("public.txt", Encoding.UTF8.GetBytes("-----BEGIN PUBLIC KEY-----\n" + Body + "\n-----END PUBLIC KEY-----\n"));
        (int code, string output) = repo.Guard();
        Assert.True(code == 0, output);
    }

    [Fact]
    public void A_plain_block_is_caught()
    {
        using Repo repo = new();
        repo.Stage("plain.txt", Encoding.UTF8.GetBytes(Block()));
        AssertCaught(repo, "plain.txt");
    }

    [Fact]
    public void A_staged_key_with_a_clean_working_copy_is_caught()
    {
        using Repo repo = new();
        repo.Stage("staged.txt", Encoding.UTF8.GetBytes(Block()));
        File.WriteAllText(Path.Combine(repo.Dir, "staged.txt"), "nothing here now\n");
        AssertCaught(repo, "staged.txt");
    }

    [Fact]
    public void An_encrypted_traditional_key_with_headers_is_caught()
    {
        using Repo repo = new();
        string text = $"-----BEGIN RSA {Marker}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n{Body}\n-----END RSA {Marker}-----\n";
        repo.Stage("enc-trad.txt", Encoding.UTF8.GetBytes(text));
        AssertCaught(repo, "enc-trad.txt");
    }

    [Fact]
    public void A_key_in_a_file_with_a_non_ascii_name_is_caught()
    {
        using Repo repo = new();
        repo.Git("config core.quotepath true");
        repo.Stage("café.txt", Encoding.UTF8.GetBytes(Block()));
        AssertCaught(repo, "café.txt");
    }

    [Fact]
    public void A_key_in_an_escaped_string_is_caught()
    {
        using Repo repo = new();
        repo.Stage("in-string.cs", Encoding.UTF8.GetBytes("const string K = \"" + Block().Replace("\n", "\\n") + "\";\n"));
        AssertCaught(repo, "in-string.cs");
    }

    [Fact]
    public void A_utf16_key_file_is_caught()
    {
        using Repo repo = new();
        repo.Stage("utf16.txt", Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(Block())).ToArray());
        AssertCaught(repo, "utf16.txt");
    }

    [Fact]
    public void A_staged_file_in_the_security_folder_is_caught_and_a_golden_trace_is_not()
    {
        using Repo repo = new();
        Directory.CreateDirectory(Path.Combine(repo.Dir, "acceptance", "golden"));
        repo.Stage("acceptance/golden/lab-00.ndjson", Encoding.UTF8.GetBytes("{}\n"));
        (int code, string output) = repo.Guard();
        Assert.True(code == 0, output);
        Directory.CreateDirectory(Path.Combine(repo.Dir, ".security"));
        File.WriteAllText(Path.Combine(repo.Dir, ".security", "modes.json"), "{}");
        repo.Git("add -f .security/modes.json");
        AssertCaught(repo, ".security/modes.json");
    }
}
