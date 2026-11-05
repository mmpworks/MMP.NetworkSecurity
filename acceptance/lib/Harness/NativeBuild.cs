using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Acceptance
{
    /// <summary>
    /// Builds native/netsec_ct.c with cl.exe into the work folder and loads it into the program, so the product's DllImport("netsec_ct.dll")
    /// finds it. Any group that runs a lesson 11 lab calls EnsureLoaded. The A12 native group calls Build and checks the result.
    /// </summary>
    public static class NativeBuild
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryW(string path);

        static string _built;
        static bool _loaded;

        static string Tail(string s) { s = s.Trim(); return s.Length > 600 ? s.Substring(s.Length - 600) : s; }

        /// <summary>Builds the library from the product sources into the work folder. Runs once per program.</summary>
        public static string Build(Ctx c)
        {
            if (_built != null) return _built;
            string src = Path.Combine(c.RepoRoot, "native", "netsec_ct.c");
            if (!File.Exists(src)) throw new NotRunException("PRODUCT_MISSING", "native/netsec_ct.c does not exist yet (slice S7)");
            string vcvars = c.Prop("vcvars64", @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat");
            if (!File.Exists(vcvars)) throw new NotRunException("TOOL_MISSING", "vcvars64.bat not found at " + vcvars);
            string outDir = Path.Combine(c.WorkDir, "native-x64");
            Directory.CreateDirectory(outDir);
            string cmd = Path.Combine(outDir, "build.cmd");
            File.WriteAllText(cmd,
                "@echo off\r\n" +
                "call \"" + vcvars + "\" >nul\r\n" +
                "if errorlevel 1 exit /b 91\r\n" +
                "cd /d \"" + c.RepoRoot + "\"\r\n" +
                "cl /nologo /W4 /WX /O2 /TP /LD /DNSCT_BUILD native\\netsec_ct.c /Fe\"" + outDir + "\\netsec_ct.dll\" /Fo\"" + outDir + "\\netsec_ct.obj\"\r\n" +
                "if errorlevel 1 exit /b 92\r\n" +
                "cl /nologo /W4 /WX /O2 /TC /c native\\netsec_ct.c /Fo\"" + outDir + "\\c_check.obj\"\r\n" +
                "if errorlevel 1 exit /b 93\r\n");
            string output;
            int code = Proc.Run("cmd.exe", "/c \"" + cmd + "\"", c.RepoRoot, 300000, out output);
            if (code == 92) throw new FailException("cl.exe failed to build the DLL as C++ (/TP /W4 /WX): " + Tail(output));
            if (code == 93) throw new FailException("cl.exe failed to compile the same file as C (/TC): the library must stay plain C-compatible so a CE compiler can take it. " + Tail(output));
            if (code != 0) throw new NotRunException("TOOL_FAILED", "build.cmd exited " + code + ": " + Tail(output));
            string dll = Path.Combine(outDir, "netsec_ct.dll");
            if (!File.Exists(dll)) throw new FailException("cl.exe reported success and wrote no DLL");
            _built = dll;
            return dll;
        }

        /// <summary>Builds the DLL if it is not built yet and loads it into this program. A missing source or tool is NOT RUN, named.</summary>
        public static void EnsureLoaded(Ctx c)
        {
            if (_loaded) return;
            string dll = Build(c);
            if (LoadLibraryW(dll) == IntPtr.Zero) throw new FailException("LoadLibrary failed for " + dll + " (Win32 error " + Marshal.GetLastWin32Error() + ")");
            _loaded = true;
        }
    }
}
