using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Outgoing HTTP calls (sdk/protocols/calls.md), part of the
/// performance module: HttpClient's own public hook, the
/// "HttpHandlerDiagnosticListener" DiagnosticListener, the same one the error
/// trail uses. Every HttpClient has it (IHttpClientFactory's too, and the
/// libraries built on them), on .NET 6 and 8 alike, so it is the one hook and
/// nothing is counted twice. One subscription however many platforms.
///
/// A call is timed from HttpRequestOut.Start (the request being sent) to
/// HttpRequestOut.Stop (its response's headers: a body read afterwards isn't
/// counted). No answer or a 5xx is an error; a 4xx is the other side's answer.
/// A call the app cancelled isn't counted, and neither is one HttpClient.Timeout
/// or SocketsHttpHandler.ConnectTimeout ended: at this hook all three are the
/// same Stop with RequestTaskStatus Canceled, no Exception event, and an
/// activity with no status or tags (.NET 8, measured). HttpClient tells a
/// timeout apart (a TimeoutException inside the TaskCanceledException) only
/// after the handlers, where nothing public reaches. Only the host is kept: never the
/// path, query, headers or body. The package's own calls to the collector and
/// a ClickHouse client's (its queries, timed as queries) are left out.
///
/// A subscriber that throws reaches the app: never.</summary>
internal static class CallHooks
{
    public const string Listener = "HttpHandlerDiagnosticListener";
    public const string Activity = "System.Net.Http.HttpRequestOut";
    public const string Start = "System.Net.Http.HttpRequestOut.Start";
    public const string Stop = "System.Net.Http.HttpRequestOut.Stop";

    private static readonly Regex HostChars = new(@"^[a-z0-9._\-\[\]:]{1,255}$", RegexOptions.CultureInvariant);
    private static readonly Regex MethodChars = new("^[A-Z]{1,10}$", RegexOptions.CultureInvariant);

    private static readonly object gate = new();
    private static Queries[] all = Array.Empty<Queries>();
    internal static readonly AllListenersWatch Listeners = new(listener =>
        listener.Name == Listener ? listener.Subscribe(new HttpObserver(), (name, _, _) => name == Activity || name == Start || name == Stop) : null);
    // The request message until its Stop: dropped with it, so a call that
    // never stops costs nothing.
    private static readonly ConditionalWeakTable<HttpRequestMessage, Pending> pending = new();

    private sealed class Pending
    {
        public Scope? Scope;
        public long Started;
        public string Method = "";
        public string Host = "";
    }

    public static void Watch(Queries calls)
    {
        lock (gate)
        {
            all = all.Append(calls).ToArray();
            Listeners.Start();
        }
    }

    public static void Unwatch(Queries calls)
    {
        lock (gate)
        {
            all = all.Where(c => c != calls).ToArray();
            if (all.Length > 0) return;
            Listeners.Stop();
        }
    }

    /// <summary>The host as calls.md stores it: lower case, with its port only
    /// when it isn't the scheme's own; "" when it isn't one.</summary>
    internal static string HostOf(Uri? uri)
    {
        if (uri == null || !uri.IsAbsoluteUri) return "";
        try
        {
            // IdnHost: a name in another script as its ASCII form. An IPv6
            // address keeps its brackets in Host.
            var name = uri.HostNameType == UriHostNameType.Dns ? uri.IdnHost : uri.Host;
            var host = (uri.IsDefaultPort ? name : name + ":" + uri.Port).ToLowerInvariant();
            return HostChars.IsMatch(host) ? host : "";
        }
        catch (Exception)
        {
            return "";
        }
    }

    /// <summary>scheme://host[:port]/path, no trailing slash: how an address
    /// is compared with the collector's.</summary>
    internal static string AddressOf(Uri uri) => (uri.Scheme + "://" + uri.Authority + uri.AbsolutePath.TrimEnd('/')).ToLowerInvariant();

    /// <summary>The collector's own address, or what's under it.</summary>
    internal static bool Ours(Uri uri, string endpoint)
    {
        if (endpoint.Length == 0 || !Uri.TryCreate(endpoint, UriKind.Absolute, out var own)) return false;
        var mine = AddressOf(own);
        var address = AddressOf(uri);
        return address == mine || address.StartsWith(mine + "/", StringComparison.Ordinal);
    }

    // A ClickHouse client's HTTP request is its query, timed as one (QueryHooks).
    private static bool InClickHouse()
    {
        for (var activity = System.Diagnostics.Activity.Current; activity != null; activity = activity.Parent)
        {
            if (QueryHooks.IsClickHouse(activity.Source.Name)) return true;
        }
        return false;
    }

    /// <summary>A request being sent: its clock starts.</summary>
    internal static void Started(HttpRequestMessage request)
    {
        var watchers = Volatile.Read(ref all);
        if (watchers.Length == 0 || request.RequestUri is not { IsAbsoluteUri: true } uri) return;
        foreach (var calls in watchers)
        {
            if (Ours(uri, calls.Endpoint)) return;
        }
        if (InClickHouse()) return;
        var host = HostOf(uri);
        var method = request.Method.Method.ToUpperInvariant();
        if (host.Length == 0 || !MethodChars.IsMatch(method)) return;
        pending.AddOrUpdate(request, new Pending { Scope = Scope.Current, Started = Stopwatch.GetTimestamp(), Method = method, Host = host });
    }

    /// <summary>Its response's headers arrived, or it failed or was cancelled.</summary>
    internal static void Stopped(HttpRequestMessage request, HttpResponseMessage? response, TaskStatus status)
    {
        if (!pending.TryGetValue(request, out var started)) return;
        pending.Remove(request);
        // Cancelled by the app (or its token): not the other side's failure, and not a wait.
        if (status == TaskStatus.Canceled) return;
        var failed = status == TaskStatus.Faulted || response == null || (int)response.StatusCode >= 500;
        var ms = Platform.ElapsedMs(started.Started);
        foreach (var calls in Volatile.Read(ref all))
        {
            try
            {
                calls.Add(started.Method, started.Host, ms, failed, started.Scope);
            }
            catch (Exception)
            {
            }
        }
    }

    private sealed class HttpObserver : IObserver<KeyValuePair<string, object?>>
    {
        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            try
            {
                // Write reaches every subscriber, whatever each one asked for: only these two.
                if (value.Key == Start)
                {
                    if (QueryHooks.Property(value.Value, "Request") is HttpRequestMessage request) Started(request);
                }
                else if (value.Key == Stop)
                {
                    if (QueryHooks.Property(value.Value, "Request") is not HttpRequestMessage request) return;
                    var status = QueryHooks.Property(value.Value, "RequestTaskStatus") is TaskStatus s ? s : TaskStatus.RanToCompletion;
                    Stopped(request, QueryHooks.Property(value.Value, "Response") as HttpResponseMessage, status);
                }
            }
            catch (Exception)
            {
            }
        }
    }
}
