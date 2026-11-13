using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Job queues (sdk/protocols/queues.md), part of the performance
/// module: platform.WatchHangfire(JobStorage.Current) reads Hangfire's own
/// monitoring API once a minute, the same figures its dashboard shows, and
/// sends a row per queue to POST /events/server-queues, for Health -> Server
/// speed -> Jobs.
///
/// Hangfire is found by name (reflection over JobStorage.GetMonitoringApi()
/// and its IMonitoringApi), as MongoDB is: the package has no Hangfire
/// reference, so an app without Hangfire loads nothing more.
///
/// Per queue: waiting (EnqueuedCount) and how long its oldest job has waited
/// (the first enqueued job's EnqueuedAt). Hangfire keeps processing,
/// scheduled and failed jobs for the whole storage, not per queue, so those
/// and the jobs finished go on one more row, "(all queues)", rather than be
/// shown against a queue they may not belong to. Finished jobs are the
/// storage's own counters (succeeded, deleted, and failed for good), read the
/// same by every process watching it: shared. Hangfire counts no jobs added,
/// so added is null. A reading that fails or takes over 5 seconds sends
/// nothing for that minute: a gap, never a zero.</summary>
internal sealed class Queues
{
    public const int SampleEvery = 60;
    public const int MaxStorages = 20;
    public const int MaxQueues = 100;
    public const int MaxRows = 500;
    public const int ReadTimeoutMs = 5000;
    public const string AllQueues = "(all queues)";
    public const string SystemName = "hangfire";

    private static readonly Regex UserInfo = new(@"(?<=//)[^/@\s]*@", RegexOptions.CultureInvariant);
    private static readonly Regex Secrets = new(@"(?i)\b(password|pwd|user ?id|uid|user ?name|user|access ?key|secret)\s*=\s*[^;,]*[;,]?\s*", RegexOptions.CultureInvariant);
    // A storage's label for itself ("SQL Server: ", "PostgreSQL Server: ") and a scheme ("redis://").
    private static readonly Regex Label = new(@"^[A-Za-z][A-Za-z ]*:\s+", RegexOptions.CultureInvariant);
    private static readonly Regex Scheme = new(@"^[A-Za-z][A-Za-z0-9+.\-]*://", RegexOptions.CultureInvariant);
    private static readonly Regex Spaces = new(@"\s+", RegexOptions.CultureInvariant);
    private static readonly Regex Slashes = new("/{2,}", RegexOptions.CultureInvariant);

    private readonly Core core;
    private readonly Performance performance;
    private readonly object gate = new();
    private readonly List<Watched> watched = new();
    private List<Dictionary<string, object?>> unsent = new();

    public Queues(Core core, Performance performance)
    {
        this.core = core;
        this.performance = performance;
        // This process, so the collector tells a reading resent after a failed
        // answer from another process's on the same machine with the same counts.
        Sender = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        if (core.Valid)
        {
            core.Every(async () =>
            {
                await SampleAsync().ConfigureAwait(false);
                return SampleEvery;
            }, SampleEvery);
        }
    }

    public string Sender { get; }

    internal sealed class Watched
    {
        public object Storage = null!;
        public string Broker = "";
        // Every queue seen: one that empties is gone from Hangfire's list, and is 0 waiting, not unknown.
        public readonly List<string> Known = new();
        public Totals? Last;
        public Task? Reading;
    }

    /// <summary>The storage's counters since it began: two readings make finished.</summary>
    internal sealed class Totals
    {
        public long Succeeded;
        public long Deleted;
        public Dictionary<DateTime, long> FailedHours = new();
    }

    internal sealed class Reading
    {
        public List<(string Name, long Waiting, long? OldestS)> Queues = new();
        public long Running;
        public long Delayed;
        public long Failed;
        public Totals Totals = new();
    }

    /// <summary>Null when it's watched, or why not.</summary>
    public string? Watch(object storage, string? broker = null)
    {
        if (Method(storage.GetType(), "GetMonitoringApi", 0) == null) return "not a Hangfire JobStorage (no GetMonitoringApi)";
        lock (gate)
        {
            if (watched.Any(w => ReferenceEquals(w.Storage, storage))) return null;
            if (watched.Count >= MaxStorages) return "already watching " + MaxStorages + " storages; this one isn't";
            var named = string.IsNullOrEmpty(broker) ? "" : Scrub(broker!);
            watched.Add(new Watched { Storage = storage, Broker = named.Length > 0 ? named : BrokerOf(storage) });
        }
        return null;
    }

    /// <summary>Where the jobs live, as the storage names itself (Hangfire's
    /// SQL Server storage: "SQL Server: host@database"), with any user name or
    /// password taken out.</summary>
    internal static string BrokerOf(object storage)
    {
        string text;
        try
        {
            text = storage.ToString() ?? "";
        }
        catch (Exception)
        {
            text = "";
        }
        var broker = Scrub(text);
        return broker.Length > 0 ? broker : storage.GetType().Name;
    }

    /// <summary>A broker as the collector takes one: no user name or password,
    /// and none of what it refuses for looking like one ("@", "//", a space).
    /// "SQL Server: db1@Hangfire" is "db1/Hangfire", "redis://user:pw@cache:6379/0"
    /// "cache:6379/0". "" when nothing is left (or the storage couldn't name itself).</summary>
    internal static string Scrub(string text)
    {
        var broker = Secrets.Replace(UserInfo.Replace(text, ""), "").Trim().TrimEnd(';', ',').Trim();
        // Hangfire's "<Connection string can not be parsed>".
        if (broker.StartsWith("<", StringComparison.Ordinal)) return "";
        broker = Scheme.Replace(Label.Replace(broker, ""), "");
        broker = Slashes.Replace(Spaces.Replace(broker.Replace('@', '/'), ""), "/").Trim('/', ';', ',');
        return J.Clip(broker, 200);
    }

    // ---- Hangfire's monitoring API, by name ----

    private static readonly ConcurrentDictionary<(Type, string, int), MethodInfo?> methods = new();

    // The interface's own method first: a storage may implement it explicitly.
    private static MethodInfo? Method(Type type, string name, int arguments) => methods.GetOrAdd((type, name, arguments), key =>
    {
        foreach (var face in key.Item1.GetInterfaces())
        {
            if (face.Name != "IMonitoringApi") continue;
            var found = face.GetMethods().FirstOrDefault(m => m.Name == key.Item2 && m.GetParameters().Length == key.Item3);
            if (found != null) return found;
        }
        return key.Item1.GetMethods(BindingFlags.Public | BindingFlags.Instance).FirstOrDefault(m => m.Name == key.Item2 && m.GetParameters().Length == key.Item3);
    });

    private static object? Call(object target, string name, params object?[] arguments)
    {
        var method = Method(target.GetType(), name, arguments.Length) ?? throw new MissingMethodException(target.GetType().Name, name);
        try
        {
            return method.Invoke(target, arguments);
        }
        catch (TargetInvocationException error) when (error.InnerException != null)
        {
            throw error.InnerException;
        }
    }

    private static long Long(object? value) => value == null ? throw new InvalidOperationException("no count") : Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);

    // EnqueuedAt of each job in a JobList<EnqueuedJobDto> (KeyValuePair<id, dto> items).
    private static IEnumerable<DateTime> EnqueuedTimes(object? jobs)
    {
        if (jobs is not IEnumerable items) yield break;
        foreach (var item in items)
        {
            if (QueryHooks.Property(QueryHooks.Property(item, "Value"), "EnqueuedAt") is DateTime at)
            {
                yield return at.Kind == DateTimeKind.Local ? at.ToUniversalTime() : DateTime.SpecifyKind(at, DateTimeKind.Utc);
            }
        }
    }

    /// <summary>One reading of a storage's monitoring API. Throws when any of it can't be read.</summary>
    internal static Reading Read(object storage, IEnumerable<string> known, DateTime now)
    {
        var api = Call(storage, "GetMonitoringApi") ?? throw new InvalidOperationException("no monitoring API");
        var reading = new Reading();
        var listed = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (Call(api, "Queues") is IEnumerable queues)
        {
            foreach (var queue in queues)
            {
                if (QueryHooks.Property(queue, "Name") is string name && name.Length > 0 && listed.Count < MaxQueues) listed[name] = QueryHooks.Property(queue, "FirstJobs");
            }
        }
        foreach (var name in known)
        {
            if (!listed.ContainsKey(name) && listed.Count < MaxQueues) listed[name] = null;
        }
        foreach (var (name, firstJobs) in listed)
        {
            var waiting = Math.Max(0, Long(Call(api, "EnqueuedCount", name)));
            long? oldest = 0;
            if (waiting > 0)
            {
                var times = EnqueuedTimes(firstJobs).ToList();
                // The queue's far end too, as a storage may list its newest first
                // (Redis). Not when the first jobs run oldest first (SQL Server):
                // an offset that deep is a scan of the customer's queue table.
                var oldestFirst = times.Count >= 2 && times[0] < times[times.Count - 1];
                if (waiting > times.Count && !oldestFirst) times.AddRange(EnqueuedTimes(Call(api, "EnqueuedJobs", name, (int)Math.Min(int.MaxValue, waiting - 1), 1)));
                oldest = times.Count == 0 ? null : Math.Max(0, (long)Math.Round((now - times.Min()).TotalSeconds));
            }
            reading.Queues.Add((name, waiting, oldest));
        }
        reading.Running = Math.Max(0, Long(Call(api, "ProcessingCount")));
        reading.Delayed = Math.Max(0, Long(Call(api, "ScheduledCount")));
        reading.Failed = Math.Max(0, Long(Call(api, "FailedCount")));
        var stats = Call(api, "GetStatistics");
        reading.Totals.Succeeded = Long(QueryHooks.Property(stats, "Succeeded"));
        reading.Totals.Deleted = Long(QueryHooks.Property(stats, "Deleted"));
        // A dictionary of hour -> count (its KeyValuePairs, whatever the dictionary type).
        if (Call(api, "HourlyFailedJobs") is not IEnumerable hours) throw new InvalidOperationException("no hourly failed counts");
        foreach (var pair in hours)
        {
            if (QueryHooks.Property(pair, "Key") is DateTime hour) reading.Totals.FailedHours[hour] = Long(QueryHooks.Property(pair, "Value"));
        }
        return reading;
    }

    /// <summary>Jobs that left the storage between two readings: succeeded,
    /// deleted, and failed for good (Hangfire's hourly failed counts, which a
    /// retry doesn't add to). Null with no earlier reading, or a counter that
    /// went down (the storage was cleared).</summary>
    internal static long? FinishedSince(Totals? before, Totals after)
    {
        if (before == null) return null;
        var succeeded = after.Succeeded - before.Succeeded;
        var deleted = after.Deleted - before.Deleted;
        if (succeeded < 0 || deleted < 0) return null;
        long failed = 0;
        var newest = before.FailedHours.Count == 0 ? DateTime.MinValue : before.FailedHours.Keys.Max();
        foreach (var (hour, count) in after.FailedHours)
        {
            // An hour the earlier reading had, or one after it: older ones fell out of its window.
            if (before.FailedHours.TryGetValue(hour, out var was))
            {
                if (count < was) return null;
                failed += count - was;
            }
            else if (hour > newest)
            {
                failed += count;
            }
        }
        return succeeded + deleted + failed;
    }

    internal static List<Dictionary<string, object?>> RowsOf(Watched storage, Reading reading, long? finished, string minute)
    {
        Dictionary<string, object?> Row(string queue) => new()
        {
            ["minute"] = minute,
            ["system"] = SystemName,
            ["broker"] = storage.Broker,
            ["queue"] = J.Clip(queue, 200),
            ["waiting"] = null,
            ["running"] = null,
            ["delayed"] = null,
            ["failed"] = null,
            ["oldest_s"] = null,
            ["added"] = null,
            ["finished"] = null,
            ["shared"] = true,
        };
        var rows = new List<Dictionary<string, object?>>();
        foreach (var (name, waiting, oldest) in reading.Queues)
        {
            var row = Row(name);
            row["waiting"] = waiting;
            row["oldest_s"] = oldest;
            rows.Add(row);
        }
        var all = Row(AllQueues);
        all["running"] = reading.Running;
        all["delayed"] = reading.Delayed;
        all["failed"] = reading.Failed;
        all["finished"] = finished;
        rows.Add(all);
        return rows;
    }

    // A reading on a thread of its own, given up after 5 seconds; a storage
    // still being read from before is skipped.
    private async Task<List<Dictionary<string, object?>>?> SampleOneAsync(Watched storage, string minute)
    {
        if (storage.Reading is { IsCompleted: false }) return null;
        List<string> known;
        lock (gate) known = storage.Known.ToList();
        var task = Task.Run(() =>
        {
            // Hangfire on Redis may share the app's watched multiplexer: these reads are ours, not the app's.
            RedisHook.Own.Value = true;
            return Read(storage.Storage, known, DateTime.UtcNow);
        });
        storage.Reading = task;
        // Its failure is this module's, never the app's unobserved exception.
        _ = task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        if (await Task.WhenAny(task, Task.Delay(ReadTimeoutMs)).ConfigureAwait(false) != task)
        {
            core.Log("queues", "Hangfire took over " + ReadTimeoutMs / 1000 + " seconds to answer; nothing sent for this minute");
            return null;
        }
        if (task.IsFaulted)
        {
            core.Log("queues", "could not read Hangfire: " + task.Exception?.GetBaseException().Message);
            return null;
        }
        var reading = task.Result;
        long? finished;
        lock (gate)
        {
            foreach (var (name, _, _) in reading.Queues)
            {
                if (!storage.Known.Contains(name) && storage.Known.Count < MaxQueues) storage.Known.Add(name);
            }
            finished = FinishedSince(storage.Last, reading.Totals);
            storage.Last = reading.Totals;
        }
        return RowsOf(storage, reading, finished, minute);
    }

    /// <summary>One reading of every storage watched, sent at once.</summary>
    internal async Task<List<Dictionary<string, object?>>> SampleAsync()
    {
        List<Watched> all;
        lock (gate) all = watched.ToList();
        var rows = new List<Dictionary<string, object?>>();
        if (all.Count == 0) return rows;
        if (!core.IsOn("performance"))
        {
            // Off: the counters start again when it's back on, rather than
            // putting everything finished while it was off into one minute.
            lock (gate)
            {
                foreach (var storage in all) storage.Last = null;
            }
            return rows;
        }
        var minute = J.IsoSeconds(Performance.MinuteNow());
        foreach (var storage in all)
        {
            try
            {
                var some = await SampleOneAsync(storage, minute).ConfigureAwait(false);
                if (some != null) rows.AddRange(some);
            }
            catch (Exception error)
            {
                core.Log("queues", "could not read Hangfire: " + error.Message);
            }
        }
        await SendAsync(rows).ConfigureAwait(false);
        return rows;
    }

    private async Task SendAsync(List<Dictionary<string, object?>> rows)
    {
        List<Dictionary<string, object?>> ready;
        lock (gate)
        {
            ready = unsent.Concat(rows).ToList();
            unsent = new();
        }
        for (var i = 0; i < ready.Count; i += MaxRows)
        {
            var res = await core.SendAsync("queues", "/events/server-queues", "POST", new Dictionary<string, object?>
            {
                ["site_id"] = core.SiteId,
                ["server_name"] = performance.ServerName,
                ["runtime"] = performance.Runtime,
                ["sender"] = Sender,
                ["rows"] = ready.Skip(i).Take(MaxRows).ToList(),
            }, "bearer").ConfigureAwait(false);
            // Busy or down for a moment: sent again with the next reading (the
            // same sender, so it is stored once). Kept to a minute's worth.
            if (res != null && (res.Status == 429 || res.Status == 503))
            {
                lock (gate) unsent = ready.Skip(i).Take(MaxRows).ToList();
                break;
            }
        }
    }
}
