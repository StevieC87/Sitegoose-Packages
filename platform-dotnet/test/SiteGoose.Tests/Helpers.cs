using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SiteGoose;

namespace SiteGoose.Tests;

/// <summary>A collector that answers from a function and keeps every request.</summary>
internal sealed class FakeCollector : HttpMessageHandler
{
    public sealed class Seen
    {
        public string Method = "";
        public string Url = "";
        public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
        public string Body = "";
        public JsonElement Json => JsonDocument.Parse(Body).RootElement;
    }

    private readonly Func<Seen, HttpResponseMessage> answer;
    public readonly List<Seen> Requests = new();

    public FakeCollector(Func<Seen, HttpResponseMessage>? answer = null)
    {
        this.answer = answer ?? (_ => Reply(202, "{}"));
    }

    public static HttpResponseMessage Reply(int status, string body, string? etag = null)
    {
        var res = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (etag != null) res.Headers.TryAddWithoutValidation("ETag", etag);
        return res;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var seen = new Seen { Method = request.Method.Method, Url = request.RequestUri!.ToString() };
        foreach (var h in request.Headers) seen.Headers[h.Key] = string.Join(", ", h.Value);
        if (request.Content != null)
        {
            foreach (var h in request.Content.Headers) seen.Headers[h.Key] = string.Join(", ", h.Value);
            seen.Body = await request.Content.ReadAsStringAsync(cancellationToken);
        }
        lock (Requests) Requests.Add(seen);
        return answer(seen);
    }
}

internal static class Shared
{
    public const string SiteId = "aaaaaaaaaaaaaaaaaaaaaaaa";
    public const string Endpoint = "http://collector.test";

    /// <summary>sdk/protocols, found by walking up from the test's folder.</summary>
    public static string Protocols(string file)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "protocols", file);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("sdk/protocols/" + file + " not found above " + AppContext.BaseDirectory);
    }

    public static JsonElement Load(string file) => JsonDocument.Parse(File.ReadAllText(Protocols(file))).RootElement;

    public static string TempDir(string prefix)
    {
        var dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>A file's permission bits as octal text ("600"); "" off Unix.</summary>
    public static string ModeOf(string file)
    {
        if (OperatingSystem.IsWindows()) return "";
        using var stat = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("stat", "-c %a " + file) { RedirectStandardOutput = true })!;
        var text = stat.StandardOutput.ReadToEnd().Trim();
        stat.WaitForExit();
        return text;
    }

    public static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    public static PlatformOptions Options(FakeCollector collector, Action<PlatformOptions>? more = null)
    {
        var options = new PlatformOptions
        {
            SiteId = SiteId,
            Secret = "test-secret-0123456789abcdef",
            Endpoint = Endpoint,
            ServerName = "web-1",
            Handler = collector,
        };
        options.Errors.CaptureUncaught = false;
        options.Errors.SpoolDir = "false";
        more?.Invoke(options);
        return options;
    }

    public static Core Core(FakeCollector? collector = null, string secret = "test-secret-0123456789abcdef") =>
        new(SiteId, secret, Endpoint, false, "web-1", collector ?? new FakeCollector());
}
