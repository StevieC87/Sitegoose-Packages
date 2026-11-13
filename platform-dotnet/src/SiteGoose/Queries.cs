using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Database query timings, part of the performance module
/// (sdk/protocols/queries.md): per minute, per route and per query, how many
/// ran, how many failed, their total and slowest time and a count per time
/// bucket, sent to POST /events/server-queries. Every value is taken out of a
/// query before it is counted (QueryText), and bound parameters are never read.
///
/// A query is added to the request or job it ran in (the scope errors and
/// breadcrumbs use), and that request's queries go into the minute's rows when
/// it finishes, under the method and route the performance module recorded
/// for it. A query outside any is "JOB" "(background)".
///
/// The same requests' outgoing HTTP calls (sdk/protocols/calls.md) are filed
/// the same way by a second instance of this class (Kind = Calls), keyed by
/// call method and host in place of database and statement (CallHooks), and
/// go to POST /events/server-calls.</summary>
internal sealed class Queries
{
    /// <summary>What one instance files: its endpoint and its two key fields.</summary>
    internal sealed record KindOf(string Name, string Path, string First, string Second);

    public static readonly KindOf QueryKind = new("queries", "/events/server-queries", "db", "statement");
    public static readonly KindOf CallKind = new("calls", "/events/server-calls", "call_method", "host");

    public const int FlushEvery = 60;
    public const int MaxRows = 500;
    public const int RequestMax = 50;
    public const int MinuteMax = 200;
    public const int MinuteHardMax = 300;
    public const int MaxMinutes = 60;
    public const string Background = "(background)";

    internal sealed class Stat
    {
        public long Count;
        public long Errors;
        public double SumMs;
        public double MaxMs;
        public readonly long[] Buckets = new long[Performance.BucketEdgesMs.Length + 1];

        public static Stat One(double ms, bool failed)
        {
            var stat = new Stat();
            stat.Add(ms, failed);
            return stat;
        }

        public void Add(double ms, bool failed)
        {
            if (double.IsNaN(ms) || ms < 0) ms = 0;
            Count += 1;
            if (failed) Errors += 1;
            SumMs += ms;
            MaxMs = Math.Max(MaxMs, ms);
            Buckets[Performance.BucketOf(ms)] += 1;
        }

        public void Merge(Stat other)
        {
            Count += other.Count;
            Errors += other.Errors;
            SumMs += other.SumMs;
            MaxMs = Math.Max(MaxMs, other.MaxMs);
            for (var i = 0; i < Buckets.Length; i++) Buckets[i] += other.Buckets[i];
        }
    }

    /// <summary>One request's or job's queries until it finishes; then where
    /// the ones it still runs (a task it left running) go.</summary>
    private sealed class Running
    {
        public readonly Dictionary<(string Db, string Statement), Stat> Map = new();
        public bool Finished;
        public string Method = "";
        public string Route = "";
    }

    private readonly Core core;
    private readonly Performance performance;
    private readonly object gate = new();
    private readonly ConditionalWeakTable<Scope, Running> running = new();
    private readonly Dictionary<long, Dictionary<(string Method, string Route, string Db, string Statement), Stat>> minutes = new();

    public Queries(Core core, Performance performance, KindOf? kind = null)
    {
        this.core = core;
        this.performance = performance;
        Kind = kind ?? QueryKind;
        if (core.Valid)
        {
            core.Every(async () =>
            {
                await FlushAsync(false).ConfigureAwait(false);
                return FlushEvery;
            }, FlushEvery);
            if (Kind == CallKind) CallHooks.Watch(this);
            else QueryHooks.Watch(this);
        }
    }

    public KindOf Kind { get; }

    /// <summary>The collector's own address, which the package's calls go to.</summary>
    internal string Endpoint => core.Endpoint;

    /// <summary>One query, already normalized, from a hook (for calls: the
    /// call method and the host).</summary>
    internal void Add(string db, string statement, double ms, bool failed) => Add(db, statement, ms, failed, Scope.Current);

    /// <summary>The same, in the request or job it started in.</summary>
    internal void Add(string db, string statement, double ms, bool failed, Scope? scope)
    {
        if (!core.IsOn("performance") || statement.Length == 0) return;
        if (scope == null)
        {
            AddRow(Performance.MinuteNow(), "JOB", Background, db, statement, Stat.One(ms, failed));
            return;
        }
        var run = running.GetValue(scope, _ => new Running());
        string method, route;
        lock (run)
        {
            if (!run.Finished)
            {
                var key = (db, statement);
                // Past 50 statements in one request, new ones are "(other)".
                if (!run.Map.ContainsKey(key) && run.Map.Count >= RequestMax) key = (db, QueryText.Other);
                if (!run.Map.TryGetValue(key, out var stat)) run.Map[key] = stat = new Stat();
                stat.Add(ms, failed);
                return;
            }
            method = run.Method;
            route = run.Route;
        }
        AddRow(Performance.MinuteNow(), method, route, db, statement, Stat.One(ms, failed));
    }

    /// <summary>A request or job finished, recorded by the performance module
    /// as method and route: its queries go into this minute's rows.</summary>
    internal void Finish(Scope? scope, string method, string route)
    {
        if (scope == null) return;
        var run = running.GetValue(scope, _ => new Running());
        List<KeyValuePair<(string Db, string Statement), Stat>> done;
        lock (run)
        {
            run.Finished = true;
            run.Method = method;
            run.Route = route;
            done = run.Map.ToList();
            run.Map.Clear();
        }
        var minute = Performance.MinuteNow();
        foreach (var pair in done) AddRow(minute, method, route, pair.Key.Db, pair.Key.Statement, pair.Value);
    }

    internal void AddRow(long minute, string method, string route, string db, string statement, Stat stat)
    {
        lock (gate)
        {
            if (!minutes.TryGetValue(minute, out var rows))
            {
                // Minutes the collector didn't take, piling up: nothing new.
                if (minutes.Count >= MaxMinutes) return;
                minutes[minute] = rows = new();
            }
            var key = (method, route, db, statement);
            if (!rows.ContainsKey(key) && rows.Count >= MinuteMax) key = (method, route, db, QueryText.Other);
            if (!rows.ContainsKey(key) && rows.Count >= MinuteHardMax) return;
            if (!rows.TryGetValue(key, out var row)) rows[key] = row = new Stat();
            row.Merge(stat);
        }
    }

    internal sealed record Ready(long Minute, (string Method, string Route, string Db, string Statement) Key, Stat Stat);

    internal List<Ready> Take(bool everything)
    {
        var current = Performance.MinuteNow();
        var ready = new List<Ready>();
        lock (gate)
        {
            foreach (var minute in minutes.Keys.Where(m => everything || m < current).OrderBy(m => m).ToList())
            {
                foreach (var pair in minutes[minute]) ready.Add(new Ready(minute, pair.Key, pair.Value));
                minutes.Remove(minute);
            }
        }
        return ready;
    }

    private void PutBack(IEnumerable<Ready> rows)
    {
        foreach (var row in rows) AddRow(row.Minute, row.Key.Method, row.Key.Route, row.Key.Db, row.Key.Statement, row.Stat);
    }

    internal static Dictionary<string, object?> RowOf(Ready row, KindOf kind) => new()
    {
        ["minute"] = J.IsoSeconds(row.Minute),
        ["method"] = row.Key.Method,
        ["route"] = row.Key.Route,
        [kind.First] = row.Key.Db,
        [kind.Second] = row.Key.Statement,
        ["count"] = row.Stat.Count,
        ["errors"] = row.Stat.Errors,
        ["sum_ms"] = Math.Round(row.Stat.SumMs, 1),
        ["max_ms"] = Math.Round(row.Stat.MaxMs, 1),
        ["buckets"] = row.Stat.Buckets.ToArray(),
    };

    public async Task FlushAsync(bool everything = true)
    {
        var ready = Take(everything);
        for (var i = 0; i < ready.Count; i += MaxRows)
        {
            var batch = ready.Skip(i).Take(MaxRows).ToList();
            var res = await core.SendAsync(Kind.Name, Kind.Path, "POST", new Dictionary<string, object?>
            {
                ["site_id"] = core.SiteId,
                ["server_name"] = performance.ServerName,
                ["runtime"] = performance.Runtime,
                ["rows"] = batch.Select(r => RowOf(r, Kind)).ToList(),
            }, "bearer").ConfigureAwait(false);
            // Busy or down for a moment: the rows wait for the next flush. Anything
            // else (a 400 or 401) won't be taken however often it's sent.
            if (res != null && (res.Status == 429 || res.Status == 503))
            {
                if (!everything) PutBack(ready.Skip(i));
                break;
            }
        }
    }

    public Task CloseAsync()
    {
        // Redis commands finished and not yet read: this platform's too.
        if (Kind == QueryKind) RedisHook.DrainNow();
        if (Kind == CallKind) CallHooks.Unwatch(this);
        else QueryHooks.Unwatch(this);
        return FlushAsync(true);
    }
}

/// <summary>DiagnosticListener.AllListeners, subscribed while anyone watches:
/// each listener pick wants (by name) is subscribed, whether it was made
/// before Start or after, and every one is left on Stop.
///
/// DiagnosticListener calls OnNext holding its own process-wide lock, the one
/// Subscribe and leaving AllListeners take too. So OnNext takes only
/// listenersGate, which is never held while calling into DiagnosticListener:
/// a listener being made on one thread while another starts or stops can't
/// deadlock. An observer of an earlier Start (its OnNext still running as it
/// is left) has an old generation, and subscribes nothing.</summary>
internal sealed class AllListenersWatch
{
    private readonly Func<DiagnosticListener, IDisposable?> pick;
    private readonly object gate = new();
    private readonly object listenersGate = new();
    private readonly List<IDisposable> subscriptions = new();
    private IDisposable? allListeners;
    private int generation;

    public AllListenersWatch(Func<DiagnosticListener, IDisposable?> pick)
    {
        this.pick = pick;
    }

    internal int Generation
    {
        get
        {
            lock (listenersGate) return generation;
        }
    }

    internal int Subscriptions
    {
        get
        {
            lock (listenersGate) return subscriptions.Count;
        }
    }

    public void Start()
    {
        lock (gate)
        {
            if (allListeners != null) return;
            int current;
            lock (listenersGate) current = ++generation;
            // Hands over the listeners that already exist from inside the call.
            allListeners = DiagnosticListener.AllListeners.Subscribe(new Observer(this, current));
        }
    }

    public void Stop()
    {
        lock (gate)
        {
            List<IDisposable> left;
            lock (listenersGate)
            {
                generation += 1;
                left = subscriptions.ToList();
                subscriptions.Clear();
            }
            allListeners?.Dispose();
            allListeners = null;
            foreach (var subscription in left) subscription.Dispose();
        }
    }

    internal IObserver<DiagnosticListener> ObserverOf(int ofGeneration) => new Observer(this, ofGeneration);

    private sealed class Observer : IObserver<DiagnosticListener>
    {
        private readonly AllListenersWatch owner;
        private readonly int generation;

        public Observer(AllListenersWatch owner, int generation)
        {
            this.owner = owner;
            this.generation = generation;
        }

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
                var subscription = owner.pick(listener);
                if (subscription == null) return;
                bool kept;
                lock (owner.listenersGate)
                {
                    kept = owner.generation == generation;
                    if (kept) owner.subscriptions.Add(subscription);
                }
                // Stopped (and maybe started again) while this one was handed over.
                if (!kept) subscription.Dispose();
            }
            catch (Exception)
            {
            }
        }
    }
}

/// <summary>Queries (or calls) started and not yet answered, by their ID: a
/// driver that never answers can't grow it past max, as it empties then. Its
/// own count, since ConcurrentDictionary.Count takes every lock it has, on
/// every query.</summary>
internal sealed class PendingMap<TKey, TValue> where TKey : notnull
{
    private readonly ConcurrentDictionary<TKey, TValue> map = new();
    private readonly int max;
    private int count;

    public PendingMap(int max)
    {
        this.max = max;
    }

    internal int Count => map.Count;

    public void Set(TKey key, TValue value)
    {
        if (Volatile.Read(ref count) >= max) Clear();
        if (map.TryAdd(key, value)) Interlocked.Increment(ref count);
        else map[key] = value;
    }

    public bool TryRemove(TKey key, out TValue value)
    {
        if (!map.TryRemove(key, out value!)) return false;
        // A Clear racing this can leave the count one off: it is a bound, not a tally.
        Interlocked.Decrement(ref count);
        return true;
    }

    public void Clear()
    {
        Interlocked.Exchange(ref count, 0);
        map.Clear();
    }
}

/// <summary>The database libraries' own public hooks, one subscription however
/// many platforms, by name only (no reference to any of them):
///
/// - SqlClient (System.Data.SqlClient and Microsoft.Data.SqlClient): the
///   "SqlClientDiagnosticListener" DiagnosticListener;
/// - Npgsql, MySqlConnector and ClickHouse (ClickHouse.Client and its
///   successor ClickHouse.Driver): their ActivitySources;
/// - EF Core's "Microsoft.EntityFrameworkCore" listener, only for SQLite, whose
///   driver publishes nothing. Every other EF Core provider's driver is
///   caught above, so no query is counted twice;
/// - MongoDB: WatchMongo (MongoHook);
/// - Redis (StackExchange.Redis): WatchRedis (RedisHook).
///
/// A subscriber that throws reaches the app: never.</summary>
internal static class QueryHooks
{
    public const string SqlClient = "SqlClientDiagnosticListener";
    public const string EntityFramework = "Microsoft.EntityFrameworkCore";
    public const string EfExecuted = "Microsoft.EntityFrameworkCore.Database.Command.CommandExecuted";
    public const string EfError = "Microsoft.EntityFrameworkCore.Database.Command.CommandError";
    public const int MaxPending = 10000;
    private const int CacheMax = 2000;
    private const int CacheTextMax = 2000;

    private static readonly object gate = new();
    private static Queries[] all = Array.Empty<Queries>();
    internal static readonly AllListenersWatch Listeners = new(Pick);
    private static ActivityListener? activities;
    private static readonly PendingMap<Guid, long> sqlStarted = new(MaxPending);
    private static readonly ConcurrentDictionary<(string Db, string Text), string> normalized = new();
    private static readonly ConcurrentDictionary<(Type, string), PropertyInfo?> properties = new();

    public static void Watch(Queries queries)
    {
        lock (gate)
        {
            all = all.Append(queries).ToArray();
            Listeners.Start();
            if (activities == null)
            {
                activities = new ActivityListener
                {
                    ShouldListenTo = source => source.Name == "Npgsql" || source.Name == "MySqlConnector" || IsClickHouse(source.Name),
                    // Asked for with their tags, not marked recorded: what a tracing
                    // exporter samples stays its own choice.
                    Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                    ActivityStopped = Stopped,
                };
                ActivitySource.AddActivityListener(activities);
            }
        }
    }

    public static void Unwatch(Queries queries)
    {
        lock (gate)
        {
            all = all.Where(q => q != queries).ToArray();
            if (all.Length > 0) return;
            Listeners.Stop();
            activities?.Dispose();
            activities = null;
            sqlStarted.Clear();
        }
    }

    internal static bool Watching => Volatile.Read(ref all).Length > 0;

    /// <summary>One query as its library gave it: normalized once, then added
    /// to every platform's queries.</summary>
    internal static void Report(string db, string? text, double ms, bool failed)
    {
        var watching = Volatile.Read(ref all);
        if (watching.Length == 0 || string.IsNullOrEmpty(text)) return;
        var database = QueryText.DatabaseOf(db);
        var statement = Normalized(database, text!);
        if (statement.Length == 0) return;
        foreach (var queries in watching)
        {
            try
            {
                queries.Add(database, statement, ms, failed);
            }
            catch (Exception)
            {
            }
        }
    }

    /// <summary>A statement already in its stored form (a Redis command's), in
    /// the request or job it was made in, added to every platform's queries.</summary>
    internal static void ReportNormalized(string db, string statement, double ms, bool failed, Scope? scope)
    {
        if (statement.Length == 0) return;
        foreach (var queries in Volatile.Read(ref all))
        {
            try
            {
                queries.Add(db, statement, ms, failed, scope);
            }
            catch (Exception)
            {
            }
        }
    }

    // The same query text normalized once, not on every run.
    private static string Normalized(string db, string text)
    {
        if (text.Length > CacheTextMax) return QueryText.Normalize(text, db);
        if (normalized.TryGetValue((db, text), out var statement)) return statement;
        statement = QueryText.Normalize(text, db);
        if (normalized.Count >= CacheMax) normalized.Clear();
        normalized[(db, text)] = statement;
        return statement;
    }

    /// <summary>A property of a diagnostic payload (an anonymous type, or the
    /// library's own event class): the payloads' public contract.</summary>
    internal static object? Property(object? target, string name)
    {
        if (target == null) return null;
        try
        {
            var property = properties.GetOrAdd((target.GetType(), name), key => key.Item1.GetProperty(key.Item2, BindingFlags.Public | BindingFlags.Instance));
            return property?.GetValue(target);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string? CommandText(object? command)
    {
        try
        {
            return command is IDbCommand db ? db.CommandText : Property(command, "CommandText") as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>ClickHouse's ADO.NET clients' ActivitySources.</summary>
    internal static bool IsClickHouse(string source) => source == "ClickHouse.Client" || source == "ClickHouse.Driver";

    private static void Stopped(Activity activity)
    {
        try
        {
            if (!Watching) return;
            var source = activity.Source.Name;
            // ClickHouse's own "SELECT version(), timezone()" when a connection
            // opens: the driver's talk, not the app's query.
            if (IsClickHouse(source) && activity.OperationName == "OpenAsync") return;
            var text = activity.GetTagItem("db.query.text") as string ?? activity.GetTagItem("db.statement") as string;
            // Connection opens and the like: not a query.
            if (string.IsNullOrEmpty(text)) return;
            var system = (activity.GetTagItem("db.system.name") ?? activity.GetTagItem("db.system")) as string;
            var db = source == "Npgsql" ? "postgresql" : IsClickHouse(source) ? "clickhouse" : system == "mariadb" ? "mariadb" : "mysql";
            var failed = activity.Status == ActivityStatusCode.Error ||
                string.Equals(activity.GetTagItem("otel.status_code") as string, "ERROR", StringComparison.OrdinalIgnoreCase);
            Report(db, text, activity.Duration.TotalMilliseconds, failed);
        }
        catch (Exception)
        {
        }
    }

    // SqlClient's and EF Core's listeners; every other one is left alone.
    private static IDisposable? Pick(DiagnosticListener listener)
    {
        if (listener.Name == SqlClient)
        {
            return listener.Subscribe(new SqlObserver(), (name, _, _) =>
                name.EndsWith(".WriteCommandBefore", StringComparison.Ordinal) ||
                name.EndsWith(".WriteCommandAfter", StringComparison.Ordinal) ||
                name.EndsWith(".WriteCommandError", StringComparison.Ordinal));
        }
        if (listener.Name == EntityFramework) return listener.Subscribe(new EfObserver(), (name, _, _) => name == EfExecuted || name == EfError);
        return null;
    }

    /// <summary>SqlClient: WriteCommandBefore starts the clock for its
    /// OperationId, WriteCommandAfter or WriteCommandError stops it.</summary>
    private sealed class SqlObserver : IObserver<KeyValuePair<string, object?>>
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
                if (Property(value.Value, "OperationId") is not Guid operation) return;
                if (value.Key.EndsWith(".WriteCommandBefore", StringComparison.Ordinal))
                {
                    if (!Watching) return;
                    sqlStarted.Set(operation, Stopwatch.GetTimestamp());
                    return;
                }
                // Write reaches every subscriber, whatever each one asked for: only these two.
                var failed = value.Key.EndsWith(".WriteCommandError", StringComparison.Ordinal);
                if (!failed && !value.Key.EndsWith(".WriteCommandAfter", StringComparison.Ordinal)) return;
                if (!sqlStarted.TryRemove(operation, out var started)) return;
                Report("mssql", CommandText(Property(value.Value, "Command")), Platform.ElapsedMs(started), failed);
            }
            catch (Exception)
            {
            }
        }
    }

    /// <summary>EF Core's executed and failed commands, for SQLite only.</summary>
    private sealed class EfObserver : IObserver<KeyValuePair<string, object?>>
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
                if (!Watching || (value.Key != EfExecuted && value.Key != EfError)) return;
                var command = Property(value.Value, "Command");
                var type = command?.GetType().FullName ?? "";
                if (!type.StartsWith("Microsoft.Data.Sqlite.", StringComparison.Ordinal) && !type.StartsWith("System.Data.SQLite.", StringComparison.Ordinal)) return;
                var duration = Property(value.Value, "Duration") is TimeSpan d ? d.TotalMilliseconds : 0;
                Report("sqlite", CommandText(command), duration, value.Key == EfError);
            }
            catch (Exception)
            {
            }
        }
    }
}

/// <summary>MongoDB's command events, subscribed on a MongoClientSettings'
/// ClusterConfigurator by name, so the package needs no MongoDB.Driver
/// reference: the driver calls ClusterBuilder.Subscribe for each event type
/// when the client is built. A filter's values are never read: only its keys
/// and its shape are written, and the normalizer makes them "?".</summary>
internal static class MongoHook
{
    private const string Events = "MongoDB.Driver.Core.Events.";
    private const int MaxItems = 1000;
    private const int MaxDepth = 8;

    // Connection chatter: never a query.
    private static readonly HashSet<string> Chatter = new(StringComparer.Ordinal)
    {
        "hello", "isMaster", "ismaster", "ping", "buildInfo", "saslStart", "saslContinue", "getMore", "endSessions", "killCursors", "getLastError",
    };

    private static readonly PendingMap<int, string> started = new(QueryHooks.MaxPending);
    // The configurators made here: watching the same settings (or a clone) twice is once.
    private static readonly ConditionalWeakTable<object, object> ours = new();

    /// <summary>Null when it's watched, or why not.</summary>
    public static string? Watch(object settings)
    {
        var property = settings.GetType().GetProperty("ClusterConfigurator", BindingFlags.Public | BindingFlags.Instance);
        var type = property?.PropertyType;
        if (property == null || type == null || !property.CanWrite || !type.IsGenericType || type.GetGenericTypeDefinition() != typeof(Action<>))
        {
            return "not a MongoClientSettings (no ClusterConfigurator)";
        }
        var before = property.GetValue(settings);
        if (before != null && ours.TryGetValue(before, out _)) return null;
        var builder = type.GetGenericArguments()[0];
        var subscribe = builder.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .FirstOrDefault(m => m.Name == "Subscribe" && m.IsGenericMethodDefinition && m.GetParameters().Length == 1);
        var startedType = builder.Assembly.GetType(Events + "CommandStartedEvent");
        var succeededType = builder.Assembly.GetType(Events + "CommandSucceededEvent");
        var failedType = builder.Assembly.GetType(Events + "CommandFailedEvent");
        if (subscribe == null || startedType == null || succeededType == null || failedType == null) return "this MongoDB driver has no command events";
        var handlers = new[]
        {
            (subscribe.MakeGenericMethod(startedType), Typed(startedType, OnStarted)),
            (subscribe.MakeGenericMethod(succeededType), Typed(succeededType, e => OnFinished(e, false))),
            (subscribe.MakeGenericMethod(failedType), Typed(failedType, e => OnFinished(e, true))),
        };
        Action<object> configure = clusterBuilder =>
        {
            foreach (var (method, handler) in handlers)
            {
                try
                {
                    method.Invoke(clusterBuilder, new[] { handler });
                }
                catch (Exception)
                {
                }
            }
        };
        var chained = typeof(MongoHook).GetMethod(nameof(Chain), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(builder).Invoke(null, new[] { before, configure })!;
        try
        {
            property.SetValue(settings, chained);
        }
        catch (TargetInvocationException error) when (error.InnerException != null)
        {
            return "call it before new MongoClient(settings): " + error.InnerException.Message;
        }
        ours.AddOrUpdate(chained, chained);
        return null;
    }

    private static Action<T> Chain<T>(Action<T>? before, Action<object> configure) => builder =>
    {
        before?.Invoke(builder);
        configure(builder!);
    };

    private static Action<T> Handler<T>(Action<object> handle) => e =>
    {
        try
        {
            handle(e!);
        }
        catch (Exception)
        {
        }
    };

    private static object Typed(Type eventType, Action<object> handle) =>
        typeof(MongoHook).GetMethod(nameof(Handler), BindingFlags.NonPublic | BindingFlags.Static)!.MakeGenericMethod(eventType).Invoke(null, new object[] { handle })!;

    internal static void OnStarted(object e)
    {
        if (!QueryHooks.Watching) return;
        if (QueryHooks.Property(e, "CommandName") is not string name || Chatter.Contains(name)) return;
        if (QueryHooks.Property(e, "RequestId") is not int id) return;
        started.Set(id, Text(name, QueryHooks.Property(e, "Command")));
    }

    internal static void OnFinished(object e, bool failed)
    {
        if (QueryHooks.Property(e, "RequestId") is not int id || !started.TryRemove(id, out var text)) return;
        var ms = QueryHooks.Property(e, "Duration") is TimeSpan d ? d.TotalMilliseconds : 0;
        QueryHooks.Report("mongodb", text, ms, failed);
    }

    /// <summary>"find users {"email":0}": the command, its collection and its
    /// filter's shape; the normalizer takes it from there.</summary>
    internal static string Text(string command, object? document)
    {
        var elements = Elements(document);
        var collection = "";
        foreach (var (name, value) in elements)
        {
            if (name == command)
            {
                // A collection's name; a database-wide command (aggregate: 1) has none.
                if (Is(value, "BsonString")) collection = value?.ToString() ?? "";
                break;
            }
        }
        var output = new StringBuilder(command);
        if (collection.Length == 0) return output.ToString();
        output.Append(' ').Append(collection);
        object? filter = command switch
        {
            "find" => Find(elements, "filter"),
            "aggregate" => Find(elements, "pipeline"),
            "count" or "distinct" or "findAndModify" => Find(elements, "query"),
            "delete" => Find(Elements(First(Find(elements, "deletes"))), "q"),
            "update" => Find(Elements(First(Find(elements, "updates"))), "q"),
            _ => null,
        };
        if (filter != null)
        {
            output.Append(' ');
            Shape(output, filter, 0);
        }
        return output.ToString();
    }

    private static object? Find(List<(string Name, object? Value)> elements, string name)
    {
        foreach (var (n, value) in elements)
        {
            if (n == name) return value;
        }
        return null;
    }

    private static object? First(object? array)
    {
        if (!Is(array, "BsonArray") || array is not IEnumerable items) return null;
        foreach (var item in items) return item;
        return null;
    }

    private static bool Is(object? value, string name)
    {
        for (var type = value?.GetType(); type != null; type = type.BaseType)
        {
            if (type.Name == name && type.Namespace == "MongoDB.Bson") return true;
        }
        return false;
    }

    private static List<(string Name, object? Value)> Elements(object? document)
    {
        var list = new List<(string, object?)>();
        if (!Is(document, "BsonDocument") || document is not IEnumerable elements) return list;
        foreach (var element in elements)
        {
            if (QueryHooks.Property(element, "Name") is string name) list.Add((name, QueryHooks.Property(element, "Value")));
        }
        return list;
    }

    // The filter's keys and structure as JSON, every value 0.
    private static void Shape(StringBuilder output, object? value, int depth)
    {
        if (depth < MaxDepth && Is(value, "BsonDocument"))
        {
            output.Append('{');
            var first = true;
            foreach (var (name, item) in Elements(value))
            {
                if (!first) output.Append(',');
                first = false;
                QueryText.Quote(output, name);
                output.Append(':');
                Shape(output, item, depth + 1);
            }
            output.Append('}');
        }
        else if (depth < MaxDepth && Is(value, "BsonArray") && value is IEnumerable items)
        {
            output.Append('[');
            var count = 0;
            foreach (var item in items)
            {
                if (count == MaxItems) break;
                if (count++ > 0) output.Append(',');
                Shape(output, item, depth + 1);
            }
            output.Append(']');
        }
        else output.Append('0');
    }
}
