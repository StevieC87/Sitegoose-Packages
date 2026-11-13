using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SiteGoose;

/// <summary>The request or job being handled: what an error captured inside it
/// is named after, and the trail of steps before it.</summary>
public sealed class RequestFields
{
    public string Method { get; set; } = "";
    public string Path { get; set; } = "";
    public string Route { get; set; } = "";
    public string SessionId { get; set; } = "";
}

internal sealed class Crumb
{
    public string Type = "note";
    public string Text = "";
    public int? Status;
    public double At;
}

/// <summary>The scope of one request or job (an AsyncLocal), set by the
/// middleware and by jobs: an error captured without a request (logged, or
/// caught deep in your code) still gets its route, and its trail.</summary>
internal sealed class Scope
{
    public const int CrumbMax = 15;
    private readonly Func<RequestFields> fields;
    private readonly List<Crumb> trail = new();

    public Scope(Func<RequestFields> fields)
    {
        this.fields = fields;
    }

    public RequestFields? Fields()
    {
        try
        {
            return fields();
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Add(Crumb crumb)
    {
        lock (trail)
        {
            trail.Add(crumb);
            if (trail.Count > CrumbMax) trail.RemoveRange(0, trail.Count - CrumbMax);
        }
    }

    /// <summary>The trail as the tracker sends it: how long before now each step happened.</summary>
    public List<Dictionary<string, object?>> Breadcrumbs()
    {
        var now = J.UnixNow();
        lock (trail)
        {
            return trail.Select(c =>
            {
                var row = new Dictionary<string, object?> { ["type"] = c.Type, ["text"] = c.Text };
                if (c.Type == "request") row["status"] = c.Status ?? 0;
                row["ms"] = (long)Math.Max(0, Math.Round((now - c.At) * 1000));
                return row;
            }).ToList();
        }
    }

    private static readonly AsyncLocal<Scope?> current = new();

    public static Scope? Current => current.Value;

    /// <summary>Enters a scope; dispose to leave it (back to the one before).</summary>
    public static IDisposable Enter(Scope scope)
    {
        var before = current.Value;
        current.Value = scope;
        return new Leave(before);
    }

    private sealed class Leave : IDisposable
    {
        private readonly Scope? before;
        private bool done;

        public Leave(Scope? before)
        {
            this.before = before;
        }

        public void Dispose()
        {
            if (done) return;
            done = true;
            current.Value = before;
        }
    }
}

/// <summary>Error monitoring module: the server's errors go to the collector
/// (POST /events/server-errors), where they join the browser's errors in the
/// Errors report. Unhandled exceptions (AppDomain) and unobserved task
/// exceptions are captured on their own; the middleware captures request
/// errors, including those UseExceptionHandler and the developer exception
/// page turn into a page; CaptureException() captures errors you catch;
/// CaptureLogging sends the exceptions your code logs at Error or above. An
/// error is sent once however many of those see it. Errors are sent in small
/// batches, a batch the collector couldn't take is tried once more, and
/// sending never throws. What still can't be sent waits in a file and is sent
/// once it can be, after a restart too; each error carries when it happened,
/// and the trail of its request or job.</summary>
internal sealed class Errors
{
    public const int Batch = 10;
    public const int QueueMax = 100;
    public const int FlushEvery = 2;
    public static int RetryAfterMs = 2000;
    public const int ResendEvery = 60;
    public const long SpoolBytes = 1024 * 1024;

    private static readonly object SpoolGate = new();
    private static readonly Regex ReleaseChars = new("[^\\w.+\\-]", RegexOptions.CultureInvariant);

    private readonly Core core;
    private readonly object gate = new();
    private List<Dictionary<string, object?>> queue = new();
    private readonly ConditionalWeakTable<Exception, Dictionary<string, object?>> seen = new();
    // Which exception each waiting event is: BeforeSend gets it when the event is sent.
    private readonly ConditionalWeakTable<Dictionary<string, object?>, Exception> origin = new();
    private readonly SemaphoreSlim resendLock = new(1, 1);
    private readonly SemaphoreSlim flushLock = new(1, 1);
    private double lastResend;
    private readonly Periodic? job;
    private bool hooked;

    public Errors(Core core, string? serverName = null, string? root = null, string? release = null, bool captureUncaught = true,
        Func<Dictionary<string, object?>, Exception?, Dictionary<string, object?>?>? beforeSend = null,
        bool captureLogging = false, string? spoolDir = null)
    {
        this.core = core;
        ServerName = J.Clip(string.IsNullOrEmpty(serverName) ? Core.HostName() : serverName, 100);
        Root = (root ?? SafeCwd()).TrimEnd('/', '\\');
        // Which build this is, for "introduced in" in the Errors report.
        Release = J.Clip(ReleaseChars.Replace((release ?? Environment.GetEnvironmentVariable("ANALYTICS_RELEASE") ?? "").Trim(), ""), 64);
        BeforeSend = beforeSend;
        CaptureLogging = captureLogging;
        // Named after the site and its secret, not the site id alone, so the
        // folder's listing tells nobody which site it is.
        var spoolOff = spoolDir != null && spoolDir.Trim().Equals("false", StringComparison.OrdinalIgnoreCase);
        if (!spoolOff && core.Valid)
        {
            var name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(core.SiteId + "|" + core.Secret))).ToLowerInvariant().Substring(0, 16);
            SpoolFile = Path.Combine(string.IsNullOrEmpty(spoolDir) ? Path.GetTempPath() : spoolDir!, "analytics-errors-" + name + ".jsonl");
        }
        if (core.Valid)
        {
            job = core.Every(async () =>
            {
                await FlushAsync().ConfigureAwait(false);
                return FlushEvery;
            }, FlushEvery);
        }
        if (captureUncaught)
        {
            AppDomain.CurrentDomain.UnhandledException += OnUnhandled;
            TaskScheduler.UnobservedTaskException += OnUnobserved;
            hooked = true;
        }
        Watchers.Watch(this);
    }

    public string ServerName { get; }
    public string Root { get; }
    public string Release { get; }
    public bool CaptureLogging { get; }
    public string? SpoolFile { get; }
    public Func<Dictionary<string, object?>, Exception?, Dictionary<string, object?>?>? BeforeSend { get; }
    internal string Endpoint => core.Endpoint;
    internal bool IsOn => core.IsOn("errors");

    private static string SafeCwd()
    {
        try
        {
            return Directory.GetCurrentDirectory();
        }
        catch (Exception)
        {
            return "";
        }
    }

    internal int QueueCount
    {
        get
        {
            lock (gate) return queue.Count;
        }
    }

    internal List<Dictionary<string, object?>> Queued()
    {
        lock (gate) return queue.ToList();
    }

    private void OnUnhandled(object? sender, UnhandledExceptionEventArgs args)
    {
        if (args.ExceptionObject is not Exception error) return;
        CaptureException(error, null, 0, "error");
        if (!args.IsTerminating) return;
        // The process is going down: one try to send, then the file, which
        // waits for the next start rather than delaying the exit.
        try
        {
            FlushAsync(resend: false, crashing: true).Wait(TimeSpan.FromSeconds(Core.TimeoutSeconds + 1));
        }
        catch (Exception)
        {
        }
        // A resend in progress keeps its taken file, picked up at the next start.
        SpoolWaiting();
    }

    private void OnUnobserved(object? sender, UnobservedTaskExceptionEventArgs args)
    {
        var error = args.Exception?.InnerExceptions.Count == 1 ? args.Exception.InnerExceptions[0] : args.Exception;
        if (error != null) CaptureException(error, null, 0, "rejection");
    }

    private void SpoolWaiting()
    {
        List<Dictionary<string, object?>> waiting;
        lock (gate)
        {
            waiting = queue;
            queue = new List<Dictionary<string, object?>>();
        }
        Spool(waiting);
    }

    private string Relative(string stack)
    {
        if (Root.Length == 0) return stack;
        return stack.Replace(Root + Path.DirectorySeparatorChar, "").Replace(Root + "/", "");
    }

    /// <summary>request: the request it came from (the middleware fills it in).</summary>
    public void CaptureException(Exception? error, RequestFields? request = null, int status = 0, string kind = "handled")
    {
        if (error == null || !core.IsOn("errors")) return;
        try
        {
            request ??= Scope.Current?.Fields();
            // The framework, your handler and logging can all see one error:
            // sent once, and a later capture fills in the event while it waits.
            if (seen.TryGetValue(error, out var waiting))
            {
                Upgrade(error, waiting, request, status, kind);
                return;
            }
            var message = error.Message;
            var evt = new Dictionary<string, object?>
            {
                ["message"] = string.IsNullOrEmpty(message) ? error.GetType().Name : message,
                ["error_type"] = error.GetType().Name,
                ["stack"] = Relative(StackOf(error)),
                ["kind"] = kind,
                ["status_code"] = status,
                ["runtime"] = ".NET",
                ["runtime_version"] = Core.RuntimeVersion,
                ["os"] = Core.OsName(),
                ["server_name"] = ServerName,
                ["release"] = Release,
                // When it happened: a crash sent after a restart keeps its own time.
                ["at"] = J.Now(),
            };
            var trail = Scope.Current?.Breadcrumbs();
            if (trail != null && trail.Count > 0) evt["breadcrumbs"] = trail;
            ApplyRequest(evt, request);
            bool full;
            lock (gate)
            {
                if (queue.Count >= QueueMax)
                {
                    core.Log("errors", "queue full, error dropped");
                    return;
                }
                queue.Add(evt);
                full = queue.Count >= Batch;
            }
            seen.AddOrUpdate(error, evt);
            origin.AddOrUpdate(evt, error);
            if (full) job?.RunNow();
        }
        catch (Exception failure)
        {
            core.Log("errors", "could not capture error: " + failure.Message);
        }
    }

    /// <summary>The stack as .NET prints it, which the collector reads frame by
    /// frame ("at Namespace.Type.Method(...) in /src/File.cs:line 42"), inner
    /// exceptions included. Async state machine frames are left as .NET names
    /// them; the collector normalises their generated parts.</summary>
    internal static string StackOf(Exception error)
    {
        try
        {
            return error.ToString();
        }
        catch (Exception)
        {
            return error.GetType().FullName + ": " + error.Message;
        }
    }

    private static void ApplyRequest(Dictionary<string, object?> evt, RequestFields? request)
    {
        if (request == null) return;
        evt["method"] = request.Method ?? "";
        evt["path"] = request.Path ?? "";
        evt["route"] = request.Route ?? "";
        evt["session_id"] = request.SessionId ?? "";
        var path = (string)evt["path"]!;
        if (path.Length > 0)
        {
            var q = path.IndexOf('?');
            evt["path"] = q >= 0 ? path.Substring(0, q) : path;
            // Named as Server speed names the request, so the two match.
            if (string.IsNullOrEmpty((string?)evt["route"])) evt["route"] = Performance.NormalizeRoute((string)evt["path"]!);
        }
    }

    /// <summary>An exception logged and then thrown on is captured first as
    /// "logged", with no status; the framework's capture that follows knows
    /// the status, the kind and the request.</summary>
    private void Upgrade(Exception error, Dictionary<string, object?> waiting, RequestFields? request, int status, string kind)
    {
        if (kind == "logged") return;
        lock (gate)
        {
            // Changed in place while it waits; once taken to be sent, left alone.
            if (queue.FindIndex(e => ReferenceEquals(e, waiting)) == -1) return;
            var evt = waiting;
            if ((string?)evt["kind"] == "logged") evt["kind"] = kind;
            if (Convert.ToInt32(evt.TryGetValue("status_code", out var s) ? s : 0) == 0) evt["status_code"] = status;
            if (request != null)
            {
                Fill(evt, "method", request.Method);
                Fill(evt, "path", request.Path);
                Fill(evt, "route", request.Route);
                Fill(evt, "session_id", request.SessionId);
            }
            if (evt.TryGetValue("path", out var p) && p is string path && path.Length > 0)
            {
                var q = path.IndexOf('?');
                if (q >= 0) evt["path"] = path.Substring(0, q);
            }
        }
    }

    /// <summary>BeforeSend, once per event, as it's taken to be sent (outside any lock).</summary>
    private List<Dictionary<string, object?>> Prepared(List<Dictionary<string, object?>> events)
    {
        if (BeforeSend == null) return events;
        var output = new List<Dictionary<string, object?>>(events.Count);
        foreach (var evt in events)
        {
            origin.TryGetValue(evt, out var error);
            try
            {
                var changed = BeforeSend(evt, error);
                if (changed != null) output.Add(changed);
            }
            catch (Exception failure)
            {
                core.Log("errors", "BeforeSend failed, error sent as it was: " + failure.Message);
                output.Add(evt);
            }
        }
        return output;
    }

    private static void Fill(Dictionary<string, object?> evt, string key, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        if (!evt.TryGetValue(key, out var have) || string.IsNullOrEmpty(have as string)) evt[key] = value;
    }

    private static bool Failed(CollectorResponse? res) => res == null || res.Status == 429 || res.Status >= 500;

    public Task FlushAsync() => FlushAsync(true, false);

    /// <summary>resend: then send what waits in the file; crashing (or closing):
    /// one try per batch, no wait between, and the file for what fails.</summary>
    internal async Task FlushAsync(bool resend, bool crashing = false, CancellationToken cancel = default)
    {
        await flushLock.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            List<Dictionary<string, object?>> taken;
            lock (gate)
            {
                taken = queue;
                queue = new List<Dictionary<string, object?>>();
            }
            var waiting = Prepared(taken);
            var sent = true;
            for (var i = 0; i < waiting.Count; i += Batch)
            {
                var batch = waiting.Skip(i).Take(Batch).ToList();
                if (cancel.IsCancellationRequested)
                {
                    sent = false;
                    Spool(waiting.Skip(i).ToList());
                    break;
                }
                var body = new Dictionary<string, object?> { ["errors"] = batch };
                var res = await core.SendAsync("errors", "/events/server-errors", "POST", body, cancel: cancel).ConfigureAwait(false);
                if (Failed(res) && !crashing)
                {
                    try
                    {
                        await Task.Delay(RetryAfterMs, cancel).ConfigureAwait(false);
                        res = await core.SendAsync("errors", "/events/server-errors", "POST", body, cancel: cancel).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }
                if (Failed(res))
                {
                    sent = false;
                    Spool(batch);
                }
            }
            // Not straight after the collector failed this flush: it would only
            // wait out another timeout.
            if (resend && sent && SpoolFile != null && J.UnixNow() - lastResend >= ResendEvery) await ResendAsync().ConfigureAwait(false);
        }
        finally
        {
            flushLock.Release();
        }
    }

    /// <summary>Appends events to the file. Credentials are added when sent, never written down.</summary>
    internal void Spool(List<Dictionary<string, object?>> events) => SpoolTo(SpoolFile, events);

    private void SpoolTo(string? file, List<Dictionary<string, object?>> events)
    {
        if (file == null || events.Count == 0) return;
        try
        {
            var info = new FileInfo(file);
            if (info.Exists && info.Length > SpoolBytes)
            {
                core.Log("errors", "waiting errors file is full, errors dropped");
                return;
            }
            var text = new StringBuilder();
            foreach (var evt in events) text.Append(J.Serialize(evt)).Append('\n');
            var bytes = Encoding.UTF8.GetBytes(text.ToString());
            lock (SpoolGate)
            {
                using var stream = OpenPrivate(file);
                stream.Write(bytes, 0, bytes.Length);
            }
        }
        catch (Exception failure)
        {
            core.Log("errors", "could not keep errors to send later: " + failure.Message);
        }
    }

    /// <summary>The file for appending, readable by this user only (errors carry
    /// paths, messages and visits) from the moment it exists.</summary>
    internal static FileStream OpenPrivate(string file)
    {
        if (OperatingSystem.IsWindows()) return new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
#if NET7_0_OR_GREATER
        return new FileStream(file, new FileStreamOptions
        {
            Mode = FileMode.Append,
            Access = FileAccess.Write,
            Share = FileShare.ReadWrite,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
#else
        // Created empty, made private, and only then written to.
        if (!File.Exists(file))
        {
            try
            {
                using (new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite))
                {
                }
            }
            catch (IOException)
            {
                // Another process made it first.
            }
        }
        if (Chmod(file, 0x180) != 0) throw new IOException("could not make the waiting errors file private");
        return new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
#endif
    }

#if !NET7_0_OR_GREATER
    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "chmod", SetLastError = true)]
    private static extern int Chmod(string path, uint mode);
#endif

    /// <summary>Sends what earlier attempts (or an earlier run) couldn't. Taken by
    /// renaming the file first, so two processes never send the same errors;
    /// the taken file goes only once it's sent, and what wasn't sent goes back
    /// in the file. A file left taken by a process that died is picked up again.</summary>
    public async Task ResendAsync(CancellationToken cancel = default)
    {
        lastResend = J.UnixNow();
        if (SpoolFile == null || !await resendLock.WaitAsync(0).ConfigureAwait(false)) return;
        try
        {
            Adopt();
            var taken = SpoolFile + "." + Environment.ProcessId + "." + StartedTicks(Environment.ProcessId) + "." + Guid.NewGuid().ToString("N").Substring(0, 6) + ".sending";
            try
            {
                File.Move(SpoolFile, taken);
            }
            catch (Exception)
            {
                return; // nothing waiting
            }
            var events = new List<Dictionary<string, object?>>();
            try
            {
                foreach (var line in File.ReadAllLines(taken, Encoding.UTF8))
                {
                    if (line.Length == 0) continue;
                    try
                    {
                        var evt = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
                        if (evt != null) events.Add(evt.ToDictionary(p => p.Key, p => (object?)p.Value));
                    }
                    catch (JsonException)
                    {
                    }
                }
            }
            catch (Exception failure)
            {
                core.Log("errors", "could not read the waiting errors: " + failure.Message);
                return;
            }
            var done = 0;
            var failed = false;
            while (done < events.Count && !cancel.IsCancellationRequested)
            {
                var batch = events.Skip(done).Take(Batch).ToList();
                var res = await core.SendAsync("errors", "/events/server-errors", "POST", new Dictionary<string, object?> { ["errors"] = batch }, cancel: cancel).ConfigureAwait(false);
                if (Failed(res))
                {
                    failed = true;
                    break;
                }
                done += batch.Count;
            }
            // What's left goes back in the file before the taken one goes.
            if (done < events.Count) SpoolTo(SpoolFile, events.Skip(done).ToList());
            try
            {
                File.Delete(taken);
            }
            catch (Exception)
            {
            }
            if (failed) core.Log("errors", "collector still away, " + (events.Count - done) + " errors keep waiting");
        }
        finally
        {
            resendLock.Release();
        }
    }

    /// <summary>Files another process took to send and never finished (it
    /// stopped or crashed): their errors go back in the file.</summary>
    private void Adopt()
    {
        try
        {
            var dir = Path.GetDirectoryName(SpoolFile!);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            var name = Path.GetFileName(SpoolFile!);
            foreach (var file in Directory.GetFiles(dir, name + ".*.sending"))
            {
                var parts = Path.GetFileName(file).Substring(name.Length + 1).Split('.');
                if (parts.Length < 4 || !int.TryParse(parts[0], out var pid)) continue;
                // The same process id and start: still running (this one, or
                // another). In a container a new process gets the old one's id.
                var running = StartedTicks(pid);
                if (running == parts[1] || running == "x") continue;
                var text = File.ReadAllText(file, Encoding.UTF8);
                lock (SpoolGate)
                {
                    using var stream = OpenPrivate(SpoolFile!);
                    var bytes = Encoding.UTF8.GetBytes(text);
                    stream.Write(bytes, 0, bytes.Length);
                }
                File.Delete(file);
            }
        }
        catch (Exception failure)
        {
            core.Log("errors", "could not pick up errors another process left: " + failure.Message);
        }
    }

    /// <summary>When a running process started, as text; "gone" when it isn't running.</summary>
    private static string StartedTicks(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.HasExited ? "gone" : process.StartTime.ToUniversalTime().Ticks.ToString();
        }
        catch (ArgumentException)
        {
            return "gone";
        }
        catch (Exception)
        {
            // Running, but not ours to look at: never adopted.
            return "x";
        }
    }

    /// <summary>At shutdown: one try for what's waiting (the file for what
    /// fails), no resend, within cancel.</summary>
    public async Task CloseAsync(CancellationToken cancel = default)
    {
        if (hooked)
        {
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandled;
            TaskScheduler.UnobservedTaskException -= OnUnobserved;
            hooked = false;
        }
        Watchers.Unwatch(this);
        try
        {
            await FlushAsync(resend: false, crashing: true, cancel).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Out of time before the flush could start: the file keeps them.
            SpoolWaiting();
        }
    }

    // ---- Breadcrumbs ----

    public static void AddBreadcrumb(string text)
    {
        var scope = Scope.Current;
        if (scope == null) return;
        scope.Add(new Crumb { Type = "note", Text = J.Clip(text ?? "", 200), At = J.UnixNow() });
    }
}

/// <summary>Exceptions your code logs (ILogger) at Error or above, when the
/// errors module's CaptureLogging is on. A log entry without an exception isn't
/// sent: it has no stack to group it by.</summary>
internal sealed class ErrorLoggerProvider : ILoggerProvider
{
    private readonly PlatformHolder holder;

    public ErrorLoggerProvider(PlatformHolder holder)
    {
        this.holder = holder;
    }

    public ILogger CreateLogger(string categoryName) => new ErrorLogger(holder, categoryName);

    public void Dispose()
    {
    }

    private sealed class ErrorLogger : ILogger
    {
        private readonly PlatformHolder holder;
        private readonly string category;

        public ErrorLogger(PlatformHolder holder, string category)
        {
            this.holder = holder;
            this.category = category;
        }

#if NET7_0_OR_GREATER
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
#else
        public IDisposable BeginScope<TState>(TState state) => NoScope.Instance;

        private sealed class NoScope : IDisposable
        {
            public static readonly NoScope Instance = new();

            public void Dispose()
            {
            }
        }
#endif

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Error && holder.Errors?.CaptureLogging == true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (exception == null || logLevel < LogLevel.Error || category.StartsWith("SiteGoose", StringComparison.Ordinal)) return;
            var errors = holder.Errors;
            if (errors == null || !errors.CaptureLogging) return;
            errors.CaptureException(exception, null, 0, "logged");
        }
    }
}

/// <summary>Where the logging provider, registered before the platform exists,
/// finds its errors module.</summary>
internal sealed class PlatformHolder
{
    public Errors? Errors;
}

/// <summary>Two global listeners, one subscription however many platforms:
/// outgoing HttpClient requests as steps of the trail ("HttpHandlerDiagnosticListener"),
/// and ASP.NET Core's own exception events ("Microsoft.AspNetCore"), so an
/// exception UseExceptionHandler or an MVC exception filter turns into a page
/// is still seen.</summary>
internal static class Watchers
{
    private static readonly object gate = new();
    private static readonly List<Errors> all = new();
    private static IDisposable? subscription;

    public const string ItemPending = "SiteGoose.Exception";
    public const string ItemPendingFiltered = "SiteGoose.FilteredException";
    public const string ItemOurs = "SiteGoose.Request";

    public static void Watch(Errors errors)
    {
        lock (gate)
        {
            all.Add(errors);
            subscription ??= DiagnosticListener.AllListeners.Subscribe(new AllObserver());
        }
    }

    public static void Unwatch(Errors errors)
    {
        lock (gate) all.Remove(errors);
    }

    internal static Errors[] Current()
    {
        lock (gate) return all.ToArray();
    }

    private sealed class AllObserver : IObserver<DiagnosticListener>
    {
        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void OnNext(DiagnosticListener listener)
        {
            try
            {
                if (listener.Name == "HttpHandlerDiagnosticListener")
                {
                    listener.Subscribe(new HttpObserver(), (name, _, _) =>
                        name == "System.Net.Http.HttpRequestOut" || name == "System.Net.Http.HttpRequestOut.Stop");
                }
                else if (listener.Name == "Microsoft.AspNetCore")
                {
                    listener.Subscribe(new AspNetObserver(), (name, _, _) =>
                        name == "Microsoft.AspNetCore.Diagnostics.HandledException" ||
                        name == "Microsoft.AspNetCore.Diagnostics.UnhandledException" ||
                        name == "Microsoft.AspNetCore.Hosting.UnhandledException" ||
                        name == "Microsoft.AspNetCore.Mvc.BeforeOnException");
                }
            }
            catch (Exception)
            {
            }
        }
    }

    internal static object? Property(object? payload, string name)
    {
        if (payload == null) return null;
        try
        {
            return payload.GetType().GetProperty(name)?.GetValue(payload);
        }
        catch (Exception)
        {
            return null;
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
            // A subscriber that throws reaches the app: never.
            try
            {
                if (value.Key != "System.Net.Http.HttpRequestOut.Stop") return;
                var scope = Scope.Current;
                if (scope == null) return;
                if (Property(value.Value, "Request") is not HttpRequestMessage request || request.RequestUri == null) return;
                var status = Property(value.Value, "RequestTaskStatus");
                // Cancelled by the app, as the tracker treats a cancelled fetch: not a failure.
                if (status is TaskStatus.Canceled) return;
                var uri = request.RequestUri;
                // Without user:password@ and the query: neither belongs in an error report.
                var url = uri.IsAbsoluteUri ? uri.Scheme + "://" + uri.Authority + uri.AbsolutePath : uri.OriginalString.Split('?')[0];
                foreach (var errors in Current())
                {
                    var endpoint = errors.Endpoint;
                    // The collector's own address and what's under it: a package's own calls aren't steps.
                    if (endpoint.Length > 0 && (url == endpoint || url.StartsWith(endpoint + "/", StringComparison.OrdinalIgnoreCase))) return;
                }
                var response = Property(value.Value, "Response") as HttpResponseMessage;
                scope.Add(new Crumb
                {
                    Type = "request",
                    Text = J.Clip(request.Method.Method + " " + url, 200),
                    Status = response == null ? 0 : (int)response.StatusCode,
                    At = J.UnixNow(),
                });
            }
            catch (Exception)
            {
            }
        }
    }

    private sealed class AspNetObserver : IObserver<KeyValuePair<string, object?>>
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
                Exception? exception;
                object? context;
                if (value.Key == "Microsoft.AspNetCore.Mvc.BeforeOnException")
                {
                    var exceptionContext = Property(value.Value, "exceptionContext");
                    exception = Property(exceptionContext, "Exception") as Exception;
                    context = Property(exceptionContext, "HttpContext");
                }
                else
                {
                    exception = Property(value.Value, "exception") as Exception;
                    context = Property(value.Value, "httpContext");
                }
                if (exception == null) return;
                var http = context as Microsoft.AspNetCore.Http.HttpContext;
                // Inside our middleware: decided when the request ends, with
                // the status it ended with.
                if (http != null && http.Items.ContainsKey(ItemOurs))
                {
                    if (value.Key == "Microsoft.AspNetCore.Mvc.BeforeOnException") http.Items[ItemPendingFiltered] = exception;
                    else http.Items[ItemPending] = exception;
                    return;
                }
                // No middleware of ours around it (a Platform registered
                // without AddSiteGoose, and UseSiteGoose not called or
                // called late): sent now, as a server error. An
                // exception an MVC filter may still turn into a page is only
                // noted, since its status isn't known.
                if (value.Key == "Microsoft.AspNetCore.Mvc.BeforeOnException") return;
                var fields = http == null ? null : new RequestFields
                {
                    Method = http.Request.Method,
                    Path = http.Request.PathBase.Add(http.Request.Path).Value ?? "",
                    SessionId = http.Request.Headers[Core.SessionHeader].ToString(),
                };
                foreach (var errors in Current()) errors.CaptureException(exception, fields, 500, "error");
            }
            catch (Exception)
            {
            }
        }
    }
}
