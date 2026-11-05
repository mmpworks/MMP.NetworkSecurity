#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// Jared's key shapes from his verdict on PR #118, each in a temp repository, and his three harmless controls. The key body is the shortest real one,
/// 64 base64 characters, split into lines of 32, so each wrapper below has as little to work with as a real key would give it.
/// </summary>
public class SecretGuardShapeTests
{
    static readonly string Marker = "PRIV" + "ATE KEY";
    static readonly string Body = Convert.ToBase64String(Enumerable.Range(0, 48).Select(i => (byte)i).ToArray());   // Holds + and /, so escaping a slash matters
    static readonly string[] Lines = { Body[..32], Body[32..] };
    static string Begin(string kind = "") => $"-----BEGIN {kind}{Marker}-----";
    static string End(string kind = "") => $"-----END {kind}{Marker}-----";
    static string Joined(string separator, string kind = "") => string.Join(separator, new[] { Begin(kind) }.Concat(Lines).Append(End(kind)));
    static string Plain() => Joined("\n") + "\n";

    static (string Name, byte[] Bytes) Shape(string shape) => shape switch
    {
        "plain" => ("plain.txt", Utf8(Plain())),
        "enc-trad" => ("enc-trad.txt", Utf8($"{Begin("RSA ")}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n{Lines[0]}\n{Lines[1]}\n{End("RSA ")}\n")),
        "space-name" => ("my key.txt", Utf8(Plain())),
        "non-ascii-name" => ("caf\u00e9.txt", Utf8(Plain())),
        "escaped-string" => ("escaped.cs", Utf8("const string K = \"" + Joined("\\n") + "\";\n")),
        "utf16" => ("utf16.txt", Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(Plain())).ToArray()),
        "csharp-array" => ("array.cs", Utf8("string[] k = {\n" + string.Join(",\n", new[] { Begin() }.Concat(Lines).Append(End()).Select(l => "    \"" + l + "\"")) + "\n};\n")),
        "xml-10" => ("key.xml", Utf8("<key>" + Joined("&#10;") + "</key>\n")),
        "xml-xa" => ("key-hex.xml", Utf8("<key>" + Joined("&#xA;") + "</key>\n")),
        "html-br" => ("key.html", Utf8("<p>" + Joined("<br>") + "</p>\n")),
        "json-slash" => ("slash.json", Utf8("{\"k\":\"" + Joined("\\n").Replace("/", "\\/") + "\"}\n")),
        "json-u000a" => ("u000a.json", Utf8("{\"k\":\"" + Joined("\\u000a") + "\"}\n")),
        "json-in-json" => ("nested.json", Utf8("{\"outer\":\"{\\\"k\\\":\\\"" + Joined("\\\\n") + "\\\"}\"}\n")),
        "powershell-backtick" => ("key.ps1", Utf8("$k = \"" + Joined("`n") + "\"\n")),
        "markdown-quote" => ("quote.md", Utf8(string.Join("\n", Plain().TrimEnd().Split('\n').Select(l => "> " + l)) + "\n")),
        "hash-comment" => ("hash.py", Utf8(string.Join("\n", Plain().TrimEnd().Split('\n').Select(l => "# " + l)) + "\n")),
        "slash-comment" => ("slash.cs", Utf8(string.Join("\n", Plain().TrimEnd().Split('\n').Select(l => "// " + l)) + "\n")),
        "plus-concat" => ("concat.cs", Utf8("string k = " + string.Join(" +\n    ", Plain().TrimEnd().Split('\n').Select(l => "\"" + l + "\\n\"")) + ";\n")),
        "csharp-verbatim" => ("verbatim.cs", Utf8("string k = @\"" + Plain() + "\";\n")),
        "python-bytes" => ("key.py", Utf8("k = b\"" + Joined("\\n") + "\"\n")),
        "go-raw" => ("key.go", Utf8("var k = `" + Plain() + "`\n")),
        "yaml-block" => ("key.yaml", Utf8("key: |\n" + string.Join("\n", Plain().TrimEnd().Split('\n').Select(l => "  " + l)) + "\n")),
        "markdown-indented" => ("indented.md", Utf8(string.Join("\n", Plain().TrimEnd().Split('\n').Select(l => "    " + l)) + "\n")),
        "prose-then-key" => ("prose-then-key.md", Utf8("A key file starts with " + Begin() + ", as below.\n\n" + Plain())),
        "placeholder-then-key" => ("placeholder-then-key.txt", Utf8(Begin() + "\n...\n" + End() + "\n" + Plain())),
        "over-8mib" => ("big.txt", Utf8(new string('x', 9 * 1024 * 1024) + "\n" + Plain())),
        _ => throw new ArgumentException(shape),
    };

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    static (string Name, byte[] Bytes) Control(string control) => control switch
    {
        // A header named in prose, and a long paragraph after it with no key in it.
        "prose-long" => ("prose-long.md", Utf8("A key file starts with " + Begin() + ". " + string.Concat(Enumerable.Repeat("The course shows each key on screen so a learner can see the parts. ", 40)) + "It ends with " + End() + ".\n")),
        "placeholder" => ("placeholder.md", Utf8(Begin() + "\n...\n" + End() + "\n")),
        "public" => ("public.txt", Utf8("-----BEGIN PUBLIC KEY-----\n" + Lines[0] + "\n" + Lines[1] + "\n-----END PUBLIC KEY-----\n")),
        _ => throw new ArgumentException(control),
    };

    public static TheoryData<string> Shapes => new()
    {
        "plain", "enc-trad", "space-name", "non-ascii-name", "escaped-string", "utf16", "csharp-array", "xml-10", "xml-xa", "html-br",
        "json-slash", "json-u000a", "json-in-json", "powershell-backtick", "markdown-quote", "hash-comment", "slash-comment", "plus-concat",
        "csharp-verbatim", "python-bytes", "go-raw", "yaml-block", "markdown-indented", "prose-then-key", "placeholder-then-key", "over-8mib",
    };

    public static TheoryData<string> Controls => new() { "prose-long", "placeholder", "public" };

    [Theory]
    [MemberData(nameof(Shapes))]
    public void Each_key_shape_is_caught(string shape)
    {
        (string name, byte[] bytes) = Shape(shape);
        (int code, string output) = Guard(name, bytes);
        Assert.True(code == 1, shape + ": the guard passed " + name + " (exit " + code + "): " + output);
    }

    [Theory]
    [MemberData(nameof(Controls))]
    public void Each_harmless_control_passes(string control)
    {
        (string name, byte[] bytes) = Control(control);
        (int code, string output) = Guard(name, bytes);
        Assert.True(code == 0, control + ": the guard refused " + name + " (exit " + code + "): " + output);
    }

    static (int, string) Guard(string name, byte[] bytes)
    {
        string dir = Path.Combine(Path.GetTempPath(), "netsec-shape-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Run(dir, "git", "init -q");
            Run(dir, "git", "config core.quotepath true");
            File.WriteAllText(Path.Combine(dir, ".gitignore"), ".security/\n");
            File.WriteAllBytes(Path.Combine(dir, name), bytes);
            Run(dir, "git", "add -- .gitignore \"" + name + "\"");
            return Run(dir, "python", "-I \"" + GuardPath() + "\"");
        }
        finally
        {
            foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);   // Git makes its objects read-only
            Directory.Delete(dir, true);
        }
    }

    static (int, string) Run(string dir, string exe, string args)
    {
        ProcessStartInfo info = new(exe, args) { WorkingDirectory = dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
        using Process p = Process.Start(info)!;
        Task<string> errors = p.StandardError.ReadToEndAsync();
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(60_000);
        return (p.ExitCode, output + errors.Result);
    }

    static string GuardPath()
    {
        for (DirectoryInfo? d = new(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            string candidate = Path.Combine(d.FullName, "tools", "secret_guard.py");
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("tools/secret_guard.py");
    }
}
