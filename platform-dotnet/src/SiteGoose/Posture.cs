using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>A folder the web serves, and the path it is served at.</summary>
public sealed class PostureRoot
{
    public string Dir { get; set; } = "";
    public string Prefix { get; set; } = "";
}

/// <summary>A check of your own, or one the package makes: pass, fail or unknown.</summary>
public sealed class PostureCheck
{
    public string Id { get; set; } = "";
    public string State { get; set; } = "unknown";
    public string? Value { get; set; }
}

/// <summary>How the server is set up (sdk/protocols/posture.md): the ASP.NET Core
/// settings that leave the app open (the Development environment, cookie
/// flags), whether it runs as root or an elevated administrator, code anyone
/// on the machine can write, and files in the folders it serves to the web
/// that should never be public. Sent to POST /events/posture a few minutes
/// after start and then once a day. Reads only, and no file's contents.</summary>
internal sealed class Posture
{
    public const int First = 180;
    public const int RetryEvery = 60 * 60;
    public const int Every = 24 * 60 * 60;
    public const int MaxChecks = 200;
    public const int MaxExposure = 50;
    public const int MaxEntries = 20000;
    public const int MaxDepth = 6;
    public const int MaxPermChecks = 3000;

    private static readonly HashSet<string> SkipDirs = new(StringComparer.Ordinal)
    {
        ".git", ".svn", ".hg", "node_modules", "vendor", "cache", ".cache", ".history", "__pycache__", "bin", "obj",
    };

    // Code the app runs: the Python package's list, and .NET's own (assemblies, Razor views).
    private static readonly Regex CodeFile = new("\\.(py|pyw|js|cjs|mjs|php[0-9]?|phtml|rb|pl|sh|dll|exe|cshtml|razor)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Files that shouldn't be downloadable, by name; first match wins.
    private static readonly (string Kind, Regex Pattern)[] Exposure =
    {
        ("database_dump", new Regex("\\.sql(\\.(gz|bz2|xz|zip))?$", RegexOptions.IgnoreCase)),
        ("private_key", new Regex("^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\\.(pem|key|p12|pfx|jks)$", RegexOptions.IgnoreCase)),
        ("env", new Regex("^\\.env($|\\.)|^env\\.(ini|txt)$", RegexOptions.IgnoreCase)),
        ("archive", new Regex("\\.(zip|tar|tgz|tar\\.gz|tar\\.bz2|rar|7z)$", RegexOptions.IgnoreCase)),
        ("backup", new Regex("\\.(bak|old|orig|save|swp|copy|backup)$|~$|\\.(py|json|conf|config|ini|ya?ml)\\.(bak|old|orig|save|txt)$", RegexOptions.IgnoreCase)),
        ("info", new Regex("^(phpinfo|info|adminer)\\.php$", RegexOptions.IgnoreCase)),
        ("log", new Regex("^(debug|error|access)[-_.]?log$|\\.log$", RegexOptions.IgnoreCase)),
        // .NET's own: appsettings with secrets in them, served by mistake.
        ("env", new Regex("^appsettings(\\.[A-Za-z0-9_-]+)?\\.json$|^web\\.config\\.(bak|old)$|^secrets\\.json$", RegexOptions.IgnoreCase)),
    };

    private readonly Core core;
    private readonly Func<IEnumerable<PostureCheck>>? extra;
    private readonly Func<IEnumerable<PostureCheck>>? framework;

    public Posture(Core core, IEnumerable<PostureRoot>? roots = null, string? host = null, Func<IEnumerable<PostureCheck>>? checks = null,
        Func<IEnumerable<PostureCheck>>? frameworkChecks = null, IEnumerable<PostureRoot>? defaultRoots = null, string? appDir = null)
    {
        this.core = core;
        Roots = RootsOf(roots, defaultRoots);
        extra = checks;
        framework = frameworkChecks;
        AppDir = appDir ?? AppContext.BaseDirectory;
        Host = Inventory.CleanHost(host);
        if (core.Valid) core.Every(ReportAsync, First);
    }

    public List<PostureRoot> Roots { get; }
    public string Host { get; }
    public string AppDir { get; }

    internal static string? KindOf(string name)
    {
        foreach (var (kind, pattern) in Exposure)
        {
            if (pattern.IsMatch(name)) return kind;
        }
        return null;
    }

    private static string Norm(string dir) => Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar, '/');

    /// <summary>A folder inside another folder on the list is already covered:
    /// without this, every file under it would be reported twice.</summary>
    internal static List<PostureRoot> WithoutNested(List<PostureRoot> roots)
    {
        var unique = new Dictionary<string, PostureRoot>(StringComparer.Ordinal);
        foreach (var root in roots)
        {
            if (!unique.ContainsKey(root.Dir)) unique[root.Dir] = root;
        }
        return unique.Values.Where(root => !unique.Keys.Any(other => other != root.Dir && (root.Dir + "/").StartsWith(other + "/", StringComparison.Ordinal))).ToList();
    }

    /// <summary>Prefix is where the web serves the folder, so the path we report
    /// is the one the dashboard can ask the site for. Not told: the web root
    /// (wwwroot), when it's there.</summary>
    internal static List<PostureRoot> RootsOf(IEnumerable<PostureRoot>? given, IEnumerable<PostureRoot>? fallback)
    {
        var roots = new List<PostureRoot>();
        foreach (var entry in given ?? Array.Empty<PostureRoot>())
        {
            if (entry == null || string.IsNullOrEmpty(entry.Dir)) continue;
            roots.Add(new PostureRoot { Dir = Norm(entry.Dir), Prefix = (entry.Prefix ?? "").Trim('/') });
        }
        if (roots.Count > 0) return WithoutNested(roots);
        foreach (var entry in fallback ?? Array.Empty<PostureRoot>())
        {
            if (entry == null || string.IsNullOrEmpty(entry.Dir) || !Directory.Exists(entry.Dir)) continue;
            roots.Add(new PostureRoot { Dir = Norm(entry.Dir), Prefix = (entry.Prefix ?? "").Trim('/') });
        }
        return WithoutNested(roots);
    }

    /// <summary>Running the web app as root (an elevated administrator on
    /// Windows) turns any hole in it into the whole machine. Null when it can't be told.</summary>
    internal static bool? RunsAsRoot()
    {
#if NET8_0_OR_GREATER
        try
        {
            return Environment.IsPrivilegedProcess;
        }
        catch (Exception)
        {
            return null;
        }
#else
        if (OperatingSystem.IsWindows()) return null;
        try
        {
            return geteuid() == 0;
        }
        catch (Exception)
        {
            return null;
        }
#endif
    }

#if !NET8_0_OR_GREATER
    [DllImport("libc", SetLastError = false)]
    private static extern uint geteuid();
#endif

    /// <summary>World-writable, from the file's mode. Null where there are no
    /// such bits (Windows) or they can't be read.</summary>
    internal static bool? WorldWritable(string path)
    {
        if (OperatingSystem.IsWindows()) return null;
#if NET7_0_OR_GREATER
        try
        {
            return (File.GetUnixFileMode(path) & UnixFileMode.OtherWrite) != 0;
        }
        catch (Exception)
        {
            return null;
        }
#else
        return null;
#endif
    }

    internal sealed class WalkResult
    {
        public List<Dictionary<string, object?>> Exposure = new();
        public int Writable;
        public int Checked;
        public List<string> Examples = new();
        public bool Truncated;
    }

    /// <summary>One bounded walk per root.</summary>
    internal static WalkResult Walk(List<PostureRoot> roots, WalkResult? into = null, bool exposure = true, HashSet<string>? skipPaths = null)
    {
        var result = into ?? new WalkResult();
        var entries = 0;
        foreach (var root in roots)
        {
            var queue = new Queue<(string Dir, int Depth)>();
            queue.Enqueue((root.Dir, 0));
            while (queue.Count > 0)
            {
                var (folder, depth) = queue.Dequeue();
                IEnumerable<string> names;
                try
                {
                    names = Directory.EnumerateFileSystemEntries(folder).ToList();
                }
                catch (Exception)
                {
                    continue;
                }
                foreach (var path in names)
                {
                    entries += 1;
                    if (entries > MaxEntries)
                    {
                        result.Truncated = true;
                        return result;
                    }
                    var name = Path.GetFileName(path);
                    FileSystemInfo info;
                    try
                    {
                        info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
                        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                    var relative = string.Join("/", new[] { root.Prefix, Path.GetRelativePath(root.Dir, path).Replace(Path.DirectorySeparatorChar, '/') }.Where(p => p.Length > 0));
                    if (info is DirectoryInfo)
                    {
                        if (name == ".git" || name == ".svn" || name == ".hg" || name == ".bzr")
                        {
                            if (exposure && result.Exposure.Count < MaxExposure) result.Exposure.Add(new Dictionary<string, object?> { ["path"] = relative + "/config", ["kind"] = "vcs" });
                            continue;
                        }
                        if (depth + 1 <= MaxDepth && !SkipDirs.Contains(name) && (skipPaths == null || !skipPaths.Contains(Norm(path)))) queue.Enqueue((path, depth + 1));
                        continue;
                    }
                    var kind = exposure ? KindOf(name) : null;
                    if (kind != null && result.Exposure.Count < MaxExposure)
                    {
                        var row = new Dictionary<string, object?> { ["path"] = relative, ["kind"] = kind };
                        try
                        {
                            var file = (FileInfo)info;
                            row["size"] = file.Length;
                            row["mtime"] = J.Iso(file.LastWriteTimeUtc);
                        }
                        catch (Exception)
                        {
                        }
                        result.Exposure.Add(row);
                    }
                    if (result.Checked < MaxPermChecks && CodeFile.IsMatch(name))
                    {
                        var writable = WorldWritable(path);
                        if (writable == null) continue;
                        result.Checked += 1;
                        if (writable == true)
                        {
                            result.Writable += 1;
                            if (result.Examples.Count < 3) result.Examples.Add(relative);
                        }
                    }
                }
            }
        }
        return result;
    }

    /// <summary>What would be reported now (also used by the job and by tests).</summary>
    internal Dictionary<string, object?> Report()
    {
        var walk = Walk(Roots);
        // The app's own assemblies aren't under the web root in .NET, but they
        // are its code: checked for permissions too, never reported as exposed.
        if (!string.IsNullOrEmpty(AppDir) && Directory.Exists(AppDir) && !Roots.Any(r => (Norm(AppDir) + "/").StartsWith(r.Dir + "/", StringComparison.Ordinal)))
        {
            var exposed = walk.Exposure;
            var truncated = walk.Truncated;
            Walk(new List<PostureRoot> { new() { Dir = Norm(AppDir), Prefix = "" } }, walk, exposure: false, skipPaths: new HashSet<string>(Roots.Select(r => r.Dir)));
            walk.Exposure = exposed;
            walk.Truncated = truncated;
        }
        var checks = new List<Dictionary<string, object?>>();
        void Add(PostureCheck check)
        {
            if (string.IsNullOrEmpty(check.Id) || (check.State != "pass" && check.State != "fail" && check.State != "unknown")) return;
            var row = new Dictionary<string, object?> { ["id"] = J.Clip(check.Id.ToLowerInvariant(), 60), ["state"] = check.State };
            if (!string.IsNullOrEmpty(check.Value)) row["value"] = J.Clip(check.Value, 200);
            checks.Add(row);
        }
        try
        {
            foreach (var check in framework?.Invoke() ?? Array.Empty<PostureCheck>()) Add(check);
        }
        catch (Exception)
        {
            // A check that errors is left out, never reported as fail.
        }
        var root = RunsAsRoot();
        if (root != null) Add(new PostureCheck { Id = "server.runs_as_root", State = root.Value ? "fail" : "pass" });
        if (walk.Checked > 0)
        {
            Add(new PostureCheck
            {
                Id = "server.code_writable",
                State = walk.Writable > 0 ? "fail" : "pass",
                Value = walk.Writable > 0 ? walk.Writable + " files, e.g. " + string.Join(", ", walk.Examples) : null,
            });
        }
        try
        {
            foreach (var check in extra?.Invoke() ?? Array.Empty<PostureCheck>())
            {
                if (check != null) Add(check);
            }
        }
        catch (Exception)
        {
        }
        var facts = new Dictionary<string, object?> { ["agent"] = "dotnet/" + Core.RuntimeVersion };
        var body = new Dictionary<string, object?>
        {
            ["site_id"] = core.SiteId,
            ["host"] = Host,
            ["at"] = J.Now(),
            ["checks"] = checks.Take(MaxChecks).ToList(),
            ["facts"] = facts,
        };
        if (Roots.Count > 0)
        {
            // Left out when there's no folder to walk: the dashboard then says
            // this wasn't checked, instead of taking an empty walk for a clean one.
            body["exposure"] = walk.Exposure.Take(MaxExposure).ToList();
            facts["webroot"] = J.Clip(Roots[0].Dir, 100);
        }
        if (walk.Truncated) body["truncated"] = true;
        return body;
    }

    private async Task<double> ReportAsync()
    {
        // The set-up checks ride the software inventory switch.
        if (!core.IsOn("inventory")) return RetryEvery;
        var res = await core.SendAsync("posture", "/events/posture", "POST", Report(), "bearer").ConfigureAwait(false);
        if (res == null || !res.Ok) return RetryEvery;
        return Math.Max(RetryEvery, J.Int(J.Prop(res.Json(), "every"), Every));
    }
}
