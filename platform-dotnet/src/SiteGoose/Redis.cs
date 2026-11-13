using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

namespace SiteGoose;

/// <summary>StackExchange.Redis's commands for Server speed -> Queries
/// (sdk/protocols/queries.md, "Redis"), through its public profiling API,
/// found by name so the package needs no StackExchange.Redis reference:
/// platform.WatchRedis(multiplexer) calls
/// IConnectionMultiplexer.RegisterProfiler(Func&lt;ProfilingSession&gt;).
///
/// The multiplexer asks that function for a session as each command is made,
/// on the caller's own flow, so the answer is the session of the request or
/// job in Scope.Current: commands are counted under the request they ran in
/// without anything else in the request path. A finished command adds itself
/// to its session; every 5 seconds a timer takes what each session holds
/// (FinishProfiling, which empties a session and leaves it usable) and files
/// it under that session's request. So the app's thread only ever looks up a
/// session; reading the commands is the timer's. A request's session is let
/// go once it has had no new command for two rounds, and is read once more
/// after that for a command still on its way. Outside a request, and past
/// 10,000 requests' sessions at once, commands go to one background session.
///
/// What the profiler gives is the command's name and its times, no key and
/// no argument, so a command is counted as its name only ("GET", never
/// "GET user:?"), and the blocking ones are still left out by
/// QueryText.RedisCommand. It says nothing of how the command ended, so an
/// error reply or a timeout counts as a command, never as a failed one. A
/// command resent after a cluster's MOVED or ASK is counted once, with its
/// time from when it was first made.
///
/// RegisterProfiler holds one profiler per multiplexer: watching it replaces
/// one the app registered itself.</summary>
internal static class RedisHook
{
    public const int DrainEveryMs = 5000;
    public const int MaxSessions = 10000;
    public const int IdleRounds = 2;
    private const int StatementsMax = 1000;

    /// <summary>True while the package's own reading runs (Hangfire's queues,
    /// which may be on the same multiplexer): those commands are not the app's.</summary>
    internal static readonly AsyncLocal<bool> Own = new();

    private sealed class Session
    {
        public readonly object Value;
        public int Idle;

        public Session(object value) => Value = value;
    }

    private static readonly object gate = new();
    private static readonly object yes = new();
    private static readonly ConditionalWeakTable<object, object> watched = new();
    private static readonly ConcurrentDictionary<Scope, Session> sessions = new();
    private static readonly ConcurrentDictionary<string, string> statements = new(StringComparer.Ordinal);
    // Sessions let go last round, read once more; only Drain touches it, one round at a time.
    private static List<(Scope Scope, Session Session)> retiring = new();
    private static int count;
    private static int draining;
    private static Type? sessionType;
    private static Func<object>? make;
    private static MethodInfo? finish;
    private static Session? background;
    private static Timer? timer;

    /// <summary>Null when it's watched, or why not.</summary>
    public static string? Watch(object multiplexer)
    {
        var register = multiplexer.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance).FirstOrDefault(m =>
            m.Name == "RegisterProfiler" && m.GetParameters().Length == 1 &&
            m.GetParameters()[0].ParameterType is { IsGenericType: true } p && p.GetGenericTypeDefinition() == typeof(Func<>));
        if (register == null) return "not a StackExchange.Redis ConnectionMultiplexer (no RegisterProfiler)";
        var type = register.GetParameters()[0].ParameterType.GetGenericArguments()[0];
        var finishing = type.GetMethod("FinishProfiling", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null);
        var withToken = type.GetConstructor(new[] { typeof(object) });
        var plain = type.GetConstructor(Type.EmptyTypes);
        if (finishing == null || (withToken == null && plain == null)) return "this StackExchange.Redis has no ProfilingSession";
        lock (gate)
        {
            if (watched.TryGetValue(multiplexer, out _)) return null;
            if (sessionType == null)
            {
                Func<object> maker = withToken != null ? () => withToken.Invoke(new object?[] { null }) : () => plain!.Invoke(null);
                background = new Session(maker());
                make = maker;
                finish = finishing;
                sessionType = type;
                // Not the caller's request or flags: the timer belongs to no request.
                using (ExecutionContext.SuppressFlow())
                {
                    timer = new Timer(_ => Drain(false), null, DrainEveryMs, DrainEveryMs);
                }
            }
            else if (sessionType != type)
            {
                return "a second copy of StackExchange.Redis; this multiplexer isn't watched";
            }
            var provider = typeof(RedisHook).GetMethod(nameof(Provider), BindingFlags.NonPublic | BindingFlags.Static)!
                .MakeGenericMethod(type).Invoke(null, null)!;
            register.Invoke(multiplexer, new[] { provider });
            watched.AddOrUpdate(multiplexer, yes);
        }
        return null;
    }

    private static Func<T?> Provider<T>() where T : class => () => Provide() as T;

    /// <summary>The session for a command being made now: its request's, or the
    /// background one; null (not profiled) for the package's own commands.</summary>
    internal static object? Provide()
    {
        try
        {
            if (Own.Value || !QueryHooks.Watching || make == null) return null;
            var scope = Scope.Current;
            if (scope == null) return background?.Value;
            if (sessions.TryGetValue(scope, out var found))
            {
                if (found.Idle != 0) found.Idle = 0;
                return found.Value;
            }
            if (Volatile.Read(ref count) >= MaxSessions) return background?.Value;
            var made = new Session(make());
            var session = sessions.GetOrAdd(scope, made);
            if (ReferenceEquals(session, made)) Interlocked.Increment(ref count);
            return session.Value;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Files every finished command each session holds now, waiting
    /// for a round already running (a platform closing).</summary>
    internal static void DrainNow() => Drain(true);

    // The timer's round (wait false) is skipped while another still runs.
    private static void Drain(bool wait)
    {
        if (wait)
        {
            var spin = new SpinWait();
            while (Interlocked.CompareExchange(ref draining, 1, 0) == 1) spin.SpinOnce();
        }
        else if (Interlocked.Exchange(ref draining, 1) == 1) return;
        try
        {
            var last = retiring;
            retiring = new();
            foreach (var (scope, session) in last) Record(session, scope);
            foreach (var pair in sessions)
            {
                if (Record(pair.Value, pair.Key) > 0)
                {
                    pair.Value.Idle = 0;
                    continue;
                }
                if (++pair.Value.Idle < IdleRounds) continue;
                if (((ICollection<KeyValuePair<Scope, Session>>)sessions).Remove(pair))
                {
                    Interlocked.Decrement(ref count);
                    retiring.Add((pair.Key, pair.Value));
                }
            }
            if (background != null) Record(background, null);
        }
        catch (Exception)
        {
        }
        finally
        {
            Volatile.Write(ref draining, 0);
        }
    }

    // How many commands the session held; each is filed under scope.
    private static int Record(Session session, Scope? scope)
    {
        object? done;
        try
        {
            done = finish?.Invoke(session.Value, null);
        }
        catch (Exception)
        {
            return 0;
        }
        if (done is not IEnumerable items) return 0;
        var commands = new List<object>();
        HashSet<object>? resent = null;
        foreach (var item in items)
        {
            if (item == null) continue;
            commands.Add(item);
            if (QueryHooks.Property(item, "RetransmissionOf") is { } original) (resent ??= new(ReferenceEqualityComparer.Instance)).Add(original);
        }
        foreach (var command in commands)
        {
            // Resent after MOVED or ASK: the resend is counted, timed from the first send.
            if (resent != null && resent.Contains(command)) continue;
            if (QueryHooks.Property(command, "Command") is not string name) continue;
            var statement = StatementOf(name);
            if (statement.Length == 0) continue;
            var ms = QueryHooks.Property(command, "ElapsedTime") is TimeSpan elapsed ? elapsed.TotalMilliseconds : 0;
            QueryHooks.ReportNormalized("redis", statement, ms, false, scope);
        }
        return commands.Count;
    }

    // The command's name as QueryText.RedisCommand gives it; "" for one not timed.
    private static string StatementOf(string name)
    {
        if (statements.TryGetValue(name, out var statement)) return statement;
        statement = QueryText.RedisCommand(new object?[] { name }) ?? "";
        if (statements.Count < StatementsMax) statements[name] = statement;
        return statement;
    }
}
