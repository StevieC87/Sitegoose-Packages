using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Software inventory module (sdk/protocols/inventory.md): the NuGet
/// packages the app was built with and its .NET version, sent to POST
/// /events/inventory a minute after start and then once a day (the
/// collector's `every`), so the Security check can match them against known
/// security holes. Runs in the background, never in a request; names and
/// versions only.
///
/// The list comes from the app's deps.json (what `dotnet publish` and
/// `dotnet run` resolve: every package, with the ones a project of the site
/// asks for by name marked `direct`). Where there is none (a host that strips
/// it), the loaded assemblies stand in, by their informational version, and
/// nothing is marked direct.</summary>
internal sealed class Inventory
{
    public const int First = 60;
    public const int RetryEvery = 60 * 60;
    public const int Every = 24 * 60 * 60;
    public const int MaxPackages = 5000;
    private static readonly Regex HostChars = new("[^A-Za-z0-9._-]", RegexOptions.CultureInvariant);

    private readonly Core core;

    public Inventory(Core core, string? host = null, string? depsFile = null)
    {
        this.core = core;
        Host = CleanHost(host);
        DepsFile = depsFile;
        if (core.Valid) core.Every(ReportAsync, First);
    }

    public string Host { get; }
    public string? DepsFile { get; }

    internal static string CleanHost(string? host)
    {
        var name = J.Clip(HostChars.Replace(host ?? Core.HostName(), "-"), 100);
        return name.Length == 0 ? "server" : name;
    }

    /// <summary>The app's deps.json files: the host's own list, else the entry assembly's.</summary>
    internal static List<string> DepsFiles(string? given)
    {
        var found = new List<string>();
        if (!string.IsNullOrEmpty(given))
        {
            found.Add(given!);
            return found;
        }
        if (AppContext.GetData("APP_CONTEXT_DEPS_FILES") is string list)
        {
            foreach (var file in list.Split(Path.PathSeparator))
            {
                if (file.Length > 0 && File.Exists(file)) found.Add(file);
            }
        }
        if (found.Count == 0)
        {
            var entry = Assembly.GetEntryAssembly()?.GetName().Name;
            if (entry != null)
            {
                var file = Path.Combine(AppContext.BaseDirectory, entry + ".deps.json");
                if (File.Exists(file)) found.Add(file);
            }
        }
        // Only the app's own: the shared frameworks' files list the runtime, not packages.
        return found.Where(f => !f.Replace('\\', '/').Contains("/shared/Microsoft.")).ToList();
    }

    /// <summary>[{ecosystem: "NuGet", name, version, direct?}] from deps.json text.</summary>
    internal static List<Dictionary<string, object?>> FromDeps(string json)
    {
        var packages = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (!root.TryGetProperty("libraries", out var libraries) || libraries.ValueKind != JsonValueKind.Object) return new List<Dictionary<string, object?>>();
        // What the site's own projects ask for by name: the dependencies of
        // every library of type "project" in the targets.
        var direct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var projects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var library in libraries.EnumerateObject())
        {
            if (library.Value.ValueKind == JsonValueKind.Object && library.Value.TryGetProperty("type", out var type) && type.GetString() == "project") projects.Add(library.Name);
        }
        if (root.TryGetProperty("targets", out var targets) && targets.ValueKind == JsonValueKind.Object)
        {
            foreach (var target in targets.EnumerateObject())
            {
                if (target.Value.ValueKind != JsonValueKind.Object) continue;
                foreach (var library in target.Value.EnumerateObject())
                {
                    if (!projects.Contains(library.Name) || library.Value.ValueKind != JsonValueKind.Object) continue;
                    if (!library.Value.TryGetProperty("dependencies", out var dependencies) || dependencies.ValueKind != JsonValueKind.Object) continue;
                    foreach (var dependency in dependencies.EnumerateObject()) direct.Add(dependency.Name);
                }
            }
        }
        foreach (var library in libraries.EnumerateObject())
        {
            if (library.Value.ValueKind != JsonValueKind.Object) continue;
            if (!library.Value.TryGetProperty("type", out var type) || type.GetString() != "package") continue;
            var slash = library.Name.IndexOf('/');
            if (slash <= 0 || slash == library.Name.Length - 1) continue;
            var name = library.Name.Substring(0, slash);
            var version = library.Name.Substring(slash + 1).TrimStart('v');
            if (packages.ContainsKey(name)) continue;
            var row = new Dictionary<string, object?> { ["ecosystem"] = "NuGet", ["name"] = name, ["version"] = version };
            if (direct.Contains(name)) row["direct"] = true;
            packages[name] = row;
        }
        return packages.Values.OrderBy(p => ((string)p["name"]!).ToLowerInvariant(), StringComparer.Ordinal).ToList();
    }

    /// <summary>Without a deps.json: the loaded assemblies that aren't the
    /// runtime's or the app's own, named and versioned as their package most
    /// often is (the assembly name, its informational version).</summary>
    internal static List<Dictionary<string, object?>> FromAssemblies()
    {
        var packages = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location) ?? "";
        var sharedRoot = runtimeDir.Length > 0 ? Path.GetDirectoryName(Path.GetDirectoryName(runtimeDir)) ?? "" : "";
        var entry = Assembly.GetEntryAssembly()?.GetName().Name;
        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            try
            {
                if (assembly.IsDynamic) continue;
                var location = assembly.Location;
                // The shared frameworks (Microsoft.NETCore.App, Microsoft.AspNetCore.App) are the runtime.
                if (location.Length > 0 && sharedRoot.Length > 0 && location.StartsWith(sharedRoot, StringComparison.OrdinalIgnoreCase)) continue;
                var name = assembly.GetName().Name;
                if (string.IsNullOrEmpty(name) || name == entry || name == "SiteGoose") continue;
                var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                              ?? assembly.GetName().Version?.ToString() ?? "";
                var plus = version.IndexOf('+');
                if (plus >= 0) version = version.Substring(0, plus);
                if (version.Length == 0 || packages.ContainsKey(name!)) continue;
                packages[name!] = new Dictionary<string, object?> { ["ecosystem"] = "NuGet", ["name"] = name, ["version"] = version };
            }
            catch (Exception)
            {
            }
        }
        return packages.Values.OrderBy(p => ((string)p["name"]!).ToLowerInvariant(), StringComparer.Ordinal).ToList();
    }

    internal List<Dictionary<string, object?>> InstalledPackages()
    {
        var all = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in DepsFiles(DepsFile))
        {
            try
            {
                foreach (var row in FromDeps(File.ReadAllText(file)))
                {
                    if (!all.ContainsKey((string)row["name"]!)) all[(string)row["name"]!] = row;
                }
            }
            catch (Exception error)
            {
                core.Log("inventory", "could not read " + file + ": " + error.Message);
            }
        }
        if (all.Count == 0 && DepsFiles(DepsFile).Count == 0) return FromAssemblies();
        return all.Values.OrderBy(p => ((string)p["name"]!).ToLowerInvariant(), StringComparer.Ordinal).ToList();
    }

    internal Dictionary<string, object?> Body()
    {
        var packages = InstalledPackages();
        return new Dictionary<string, object?>
        {
            ["site_id"] = core.SiteId,
            ["host"] = Host,
            ["at"] = J.Now(),
            ["runtime"] = new Dictionary<string, object?> { ["dotnet"] = Core.RuntimeVersion },
            ["packages"] = packages.Take(MaxPackages).ToList(),
            ["truncated"] = packages.Count > MaxPackages,
        };
    }

    private async Task<double> ReportAsync()
    {
        if (!core.IsOn("inventory")) return RetryEvery;
        var res = await core.SendAsync("inventory", "/events/inventory", "POST", Body(), "bearer").ConfigureAwait(false);
        if (res == null || !res.Ok) return RetryEvery;
        var every = J.Prop(res.Json(), "every");
        return J.IsNumber(every) && J.Int(every) > 0 ? Math.Max(RetryEvery, J.Int(every)) : Every;
    }
}
