using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace SiteGoose;

/// <summary>The package's options: the site's credentials, how to find the
/// visitor's address, and each module (on by default; Enabled = false turns
/// one off). Bound from the "SiteGoose" section of appsettings.json
/// and the environment (SiteGoose__Secret, ...) by AddSiteGoose. Each of
/// SiteId, Secret, Endpoint, TrustProxy and ServerName still empty then is
/// read from ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT,
/// ANALYTICS_TRUST_PROXY and ANALYTICS_SERVER_NAME, the names every other
/// package reads, so the environment alone is enough.</summary>
public sealed class PlatformOptions
{
    /// <summary>The site's ID (24 hex characters, site settings).</summary>
    public string? SiteId { get; set; }

    /// <summary>The site secret (site settings). Keep it on the server.</summary>
    public string? Secret { get; set; }

    /// <summary>The collector's URL.</summary>
    public string? Endpoint { get; set; }

    /// <summary>How to find the visitor's address: null or "0" the connection's;
    /// "1" for one proxy or load balancer ("2" for Cloudflare in front of one,
    /// and so on: that many addresses from the right of X-Forwarded-For);
    /// "cloudflare" when every request comes through Cloudflare
    /// (CF-Connecting-IP, believed only from Cloudflare's own addresses).</summary>
    public string? TrustProxy { get; set; }

    /// <summary>Your own way to find the visitor's address, given a header
    /// reader (lower-case names). Wins over TrustProxy.</summary>
    public Func<Func<string, string>, string?>? ClientIp { get; set; }

    /// <summary>This service's name, for every module that sends one (errors,
    /// server speed, crawlers, resources, inventory and posture, the check-in).
    /// Default: the machine's host name.</summary>
    public string? ServerName { get; set; }

    /// <summary>Print send problems to the console.</summary>
    public bool Debug { get; set; }

    /// <summary>Fills SiteId, Secret, Endpoint, TrustProxy and ServerName
    /// from the ANALYTICS_* environment variables where they're still empty
    /// (ANALYTICS_FIREWALL_ENDPOINT too, the name the PHP packages took
    /// first). What configuration or code set is never replaced.</summary>
    internal void FillFromEnvironment(Func<string, string?>? read = null)
    {
        read ??= Environment.GetEnvironmentVariable;
        string? Env(params string[] names)
        {
            foreach (var name in names)
            {
                var value = read(name)?.Trim();
                if (!string.IsNullOrEmpty(value)) return value;
            }
            return null;
        }
        if (string.IsNullOrWhiteSpace(SiteId)) SiteId = Env("ANALYTICS_SITE_ID") ?? SiteId;
        if (string.IsNullOrWhiteSpace(Secret)) Secret = Env("ANALYTICS_SITE_SECRET") ?? Secret;
        if (string.IsNullOrWhiteSpace(Endpoint)) Endpoint = Env("ANALYTICS_ENDPOINT", "ANALYTICS_FIREWALL_ENDPOINT") ?? Endpoint;
        if (string.IsNullOrWhiteSpace(TrustProxy)) TrustProxy = Env("ANALYTICS_TRUST_PROXY") ?? TrustProxy;
        if (string.IsNullOrWhiteSpace(ServerName)) ServerName = Env("ANALYTICS_SERVER_NAME") ?? ServerName;
    }

    public FirewallOptions Firewall { get; set; } = new();
    public ErrorsOptions Errors { get; set; } = new();
    public ModuleOptions Analytics { get; set; } = new();
    public PerformanceOptions Performance { get; set; } = new();
    public ServerNameOptions Crawlers { get; set; } = new();
    public ModuleOptions Forms { get; set; } = new();
    public ModuleOptions Headers { get; set; } = new();
    public AuditOptions Audit { get; set; } = new();
    public ModuleOptions Flags { get; set; } = new();
    public MaintenanceOptions Maintenance { get; set; } = new();
    public InventoryOptions Inventory { get; set; } = new();
    public PostureOptions Posture { get; set; } = new();
    public ServerNameOptions Resources { get; set; } = new();
    public ProxyOptions Proxy { get; set; } = new();

    /// <summary>For tests: what sends to the collector.</summary>
    internal HttpMessageHandler? Handler { get; set; }
}

public class ModuleOptions
{
    /// <summary>The module is loaded (default true). The dashboard can still
    /// switch a loaded module off (Security -> Server package).</summary>
    public bool Enabled { get; set; } = true;
}

public class ServerNameOptions : ModuleOptions
{
    public string? ServerName { get; set; }
}

public sealed class FirewallOptions : ModuleOptions
{
    /// <summary>"monitor" or "block": overrides the dashboard.</summary>
    public string? Mode { get; set; }

    /// <summary>Rules kept there between restarts.</summary>
    public string? CacheFile { get; set; }

    /// <summary>A counter shared between instances (Redis INCR + EXPIRE):
    /// (key, ttl seconds) -> hits. Without it each process counts on its own.</summary>
    public Func<string, int, long>? Counter { get; set; }

    /// <summary>Requests the firewall never looks at (health checks).</summary>
    public Func<HttpContext, bool>? Skip { get; set; }
}

public sealed class ErrorsOptions : ServerNameOptions
{
    /// <summary>Stack paths are made relative to it. Default: the working directory.</summary>
    public string? Root { get; set; }

    /// <summary>Which build this is, for "introduced in". Default: ANALYTICS_RELEASE.</summary>
    public string? Release { get; set; }

    /// <summary>Unhandled exceptions (AppDomain) and unobserved task exceptions. Default true.</summary>
    public bool CaptureUncaught { get; set; } = true;

    /// <summary>Exceptions logged through ILogger at Error or above are sent too. Default false.</summary>
    public bool CaptureLogging { get; set; }

    /// <summary>Where errors that couldn't be sent wait. Default: the temp folder; "false" keeps none.</summary>
    public string? SpoolDir { get; set; }

    /// <summary>Change an error before it is sent, or return null to drop it.</summary>
    public Func<Dictionary<string, object?>, Exception?, Dictionary<string, object?>?>? BeforeSend { get; set; }
}

public sealed class PerformanceOptions : ServerNameOptions
{
    /// <summary>Your own route name for a request ("" or null: the endpoint's pattern).</summary>
    public Func<HttpContext, string?>? Route { get; set; }

    /// <summary>Database query timings (Server speed -> Queries). Default true;
    /// false keeps Server speed and leaves queries out.</summary>
    public bool Queries { get; set; } = true;

    /// <summary>Outgoing HTTP calls, by host (Server speed -> Calls). Default
    /// true; false keeps Server speed and leaves calls out.</summary>
    public bool Calls { get; set; } = true;

    /// <summary>Job queues watched with WatchHangfire (Server speed -> Jobs).
    /// Default true; false keeps Server speed and leaves queues out.</summary>
    public bool Queues { get; set; } = true;
}

public sealed class AuditOptions : ModuleOptions
{
    /// <summary>Cookie authentication's sign-ins and sign-outs as "user.login" and "user.logout". Default true.</summary>
    public bool SignIns { get; set; } = true;
}

public sealed class MaintenanceOptions : ModuleOptions
{
    /// <summary>skip(path) -> true lets a request through (health checks).</summary>
    public Func<string, bool>? Skip { get; set; }
}

public sealed class InventoryOptions : ModuleOptions
{
    /// <summary>The server's name. Default: ServerName, else the host name.</summary>
    public string? Host { get; set; }

    /// <summary>The deps.json to read. Default: the app's own.</summary>
    public string? DepsFile { get; set; }
}

public sealed class PostureOptions : ModuleOptions
{
    /// <summary>The folders the web serves. Default: the web root (wwwroot).</summary>
    public List<PostureRoot>? Roots { get; set; }

    public string? Host { get; set; }

    /// <summary>Checks of your own.</summary>
    public Func<IEnumerable<PostureCheck>>? Checks { get; set; }
}

public sealed class ProxyOptions : ModuleOptions
{
    /// <summary>The path it answers on. Default: worked out from the secret.</summary>
    public string? Prefix { get; set; }
}
