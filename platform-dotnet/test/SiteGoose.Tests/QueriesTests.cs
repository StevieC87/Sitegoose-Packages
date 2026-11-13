using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Driver.Core.Configuration;
using MongoDB.Driver.Core.Events;
using Xunit;

namespace SiteGoose.Tests;

/// <summary>Database query timings (sdk/protocols/queries.md): the shared
/// normalizing cases, where a query is counted, the caps, what is sent, and
/// each hook fed by a stand-in with the real library's name.</summary>
public class QueriesTests
{
    private static Platform Make(FakeCollector? collector = null, Action<PlatformOptions>? more = null) =>
        new(Shared.Options(collector ?? new FakeCollector(), more));

    private static Queries.Ready Row(List<Queries.Ready> rows, string statement) =>
        Assert.Single(rows, r => r.Key.Statement == statement);

    [Fact]
    public void SharedCases()
    {
        var cases = Shared.Load("query-cases.json");
        Assert.Equal(QueryText.MaxStatement, cases.GetProperty("max_statement").GetInt32());
        var wrong = new List<string>();
        foreach (var c in cases.GetProperty("cases").EnumerateArray())
        {
            var expected = c.GetProperty("expected").GetString();
            var got = QueryText.Normalize(c.GetProperty("statement").GetString(), c.GetProperty("db").GetString());
            if (got != expected) wrong.Add(c.GetProperty("db").GetString() + ": " + c.GetProperty("statement").GetString() + "\n  expected " + expected + "\n  got      " + got);
        }
        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
    }

    [Fact]
    public async Task QueriesGoUnderTheirRequestJobOrBackground()
    {
        var collector = new FakeCollector();
        var platform = Make(collector);
        var queries = platform.QueriesModule!;
        using (Scope.Enter(new Scope(() => new RequestFields { Method = "GET", Path = "/products/7" })))
        {
            for (var i = 0; i < 3; i++) queries.Add("postgresql", "SELECT * FROM products WHERE id = $1", 10, false);
            queries.Add("postgresql", "SELECT * FROM products WHERE id = $1", 30, true);
            platform.TimeRequest("get", "/products/{id}", 200, Stopwatch.GetTimestamp());
            // A task the request left running: still the request's route.
            queries.Add("postgresql", "SELECT late", 1, false);
        }
        queries.Add("mysql", "SELECT background", 2, false);
        platform.RunJob("nightly", () => queries.Add("sqlite", "DELETE FROM sessions", 1, false));

        await platform.FlushAsync();
        var sent = Assert.Single(collector.Requests, r => r.Url.EndsWith("/events/server-queries", StringComparison.Ordinal));
        Assert.Equal("Bearer test-secret-0123456789abcdef", sent.Headers["Authorization"]);
        var body = sent.Json;
        Assert.Equal(Shared.SiteId, body.GetProperty("site_id").GetString());
        Assert.Equal("web-1", body.GetProperty("server_name").GetString());
        Assert.StartsWith(".NET ", body.GetProperty("runtime").GetString());
        var rows = body.GetProperty("rows").EnumerateArray().ToList();
        var products = Assert.Single(rows, r => r.GetProperty("statement").GetString() == "SELECT * FROM products WHERE id = $1");
        Assert.Equal("GET", products.GetProperty("method").GetString());
        Assert.Equal("/products/{id}", products.GetProperty("route").GetString());
        Assert.Equal("postgresql", products.GetProperty("db").GetString());
        Assert.Equal(4, products.GetProperty("count").GetInt32());
        Assert.Equal(1, products.GetProperty("errors").GetInt32());
        Assert.Equal(60, products.GetProperty("sum_ms").GetDouble());
        Assert.Equal(30, products.GetProperty("max_ms").GetDouble());
        Assert.Equal(new long[] { 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 }, products.GetProperty("buckets").EnumerateArray().Select(b => b.GetInt64()).ToArray());
        Assert.EndsWith(":00.000Z", products.GetProperty("minute").GetString());
        var late = Assert.Single(rows, r => r.GetProperty("statement").GetString() == "SELECT late");
        Assert.Equal("/products/{id}", late.GetProperty("route").GetString());
        var background = Assert.Single(rows, r => r.GetProperty("statement").GetString() == "SELECT background");
        Assert.Equal("JOB", background.GetProperty("method").GetString());
        Assert.Equal("(background)", background.GetProperty("route").GetString());
        var job = Assert.Single(rows, r => r.GetProperty("statement").GetString() == "DELETE FROM sessions");
        Assert.Equal("JOB", job.GetProperty("method").GetString());
        Assert.Equal("/(job) nightly", job.GetProperty("route").GetString());
    }

    [Fact]
    public void CapsPerRequestAndPerMinute()
    {
        var core = Shared.Core();
        var queries = new Queries(core, new Performance(core, "web-1"));
        var scope = new Scope(() => new RequestFields());
        using (Scope.Enter(scope))
        {
            for (var i = 0; i < 60; i++) queries.Add("postgresql", "SELECT c" + (char)('a' + i % 26) + (char)('a' + i / 26), 1, false);
        }
        queries.Finish(scope, "GET", "/caps");
        var rows = queries.Take(true);
        Assert.Equal(Queries.RequestMax + 1, rows.Count);
        Assert.Equal(10, Row(rows, QueryText.Other).Stat.Count);

        // 350 routes, one statement each: 200 rows, then "(other)" per route, then nothing new past 300.
        for (var i = 0; i < 350; i++)
        {
            var s = new Scope(() => new RequestFields());
            using (Scope.Enter(s)) queries.Add("mysql", "SELECT x", 1, false);
            queries.Finish(s, "GET", "/r" + i);
        }
        rows = queries.Take(true);
        Assert.Equal(Queries.MinuteHardMax, rows.Count);
        Assert.Equal(Queries.MinuteMax, rows.Count(r => r.Key.Statement == "SELECT x"));
        Assert.Contains(rows, r => r.Key.Route == "/r200" && r.Key.Statement == QueryText.Other);
        Assert.DoesNotContain(rows, r => r.Key.Route == "/r300");
    }

    [Fact]
    public async Task FiveHundredRowsARequest()
    {
        var collector = new FakeCollector();
        var platform = Make(collector);
        var queries = platform.QueriesModule!;
        // Three earlier minutes the collector didn't take yet, 200 rows each.
        for (var minute = 0; minute < 3; minute++)
        {
            for (var i = 0; i < 200; i++) queries.AddRow(1_700_000_000 + minute * 60, "GET", "/r" + i, "postgresql", "SELECT a", Queries.Stat.One(1, false));
        }
        await queries.FlushAsync(false);
        var sent = collector.Requests.Where(r => r.Url.EndsWith("/events/server-queries", StringComparison.Ordinal)).ToList();
        Assert.Equal(new[] { 500, 100 }, sent.Select(r => r.Json.GetProperty("rows").GetArrayLength()).ToArray());
    }

    [Fact]
    public async Task OffWithServerSpeedOrWhenAsked()
    {
        Assert.Null(Make(more: o => o.Performance.Queries = false).QueriesModule);
        Assert.Null(Make(more: o => o.Performance.Enabled = false).QueriesModule);
        var collector = new FakeCollector(r => r.Url.Contains("/events/platform/config")
            ? FakeCollector.Reply(200, "{\"v\":1,\"modules\":{\"performance\":false}}")
            : FakeCollector.Reply(202, "{}"));
        var platform = Make(collector);
        await platform.Core.SyncSwitchesAsync();
        platform.QueriesModule!.Add("postgresql", "SELECT switched_off", 1, false);
        Assert.Empty(platform.QueriesModule.Take(true));
    }

    [Fact]
    public void AListenerMadeBeforeThePlatformIsHeard()
    {
        using var listener = new DiagnosticListener("SqlClientDiagnosticListener");
        var platform = Make();
        var operation = Guid.NewGuid();
        var command = new FakeSqlCommand { CommandText = "SELECT sqlclient_early FROM t" };
        listener.Write("Microsoft.Data.SqlClient.WriteCommandBefore", new { OperationId = operation, Command = command });
        listener.Write("Microsoft.Data.SqlClient.WriteCommandAfter", new { OperationId = operation, Command = command });
        Assert.Contains(platform.QueriesModule!.Take(true), r => r.Key.Statement == "SELECT sqlclient_early FROM t");
    }

    [Fact]
    public void SqlClientDiagnosticListener()
    {
        var platform = Make();
        using var listener = new DiagnosticListener("SqlClientDiagnosticListener");
        Assert.True(listener.IsEnabled("Microsoft.Data.SqlClient.WriteCommandBefore"));
        var ok = Guid.NewGuid();
        var command = new FakeSqlCommand { CommandText = "SELECT sqlclient_ok FROM t WHERE id = 5" };
        listener.Write("Microsoft.Data.SqlClient.WriteCommandBefore", new { OperationId = ok, Operation = "ExecuteReader", Command = command, Timestamp = 0L });
        listener.Write("Microsoft.Data.SqlClient.WriteConnectionOpenAfter", new { OperationId = ok, Command = command });
        listener.Write("Microsoft.Data.SqlClient.WriteCommandAfter", new { OperationId = ok, Operation = "ExecuteReader", Command = command, Timestamp = 0L });
        var failed = Guid.NewGuid();
        var bad = new FakeSqlCommand { CommandText = "UPDATE sqlclient_bad SET a = 'x'" };
        listener.Write("System.Data.SqlClient.WriteCommandBefore", new { OperationId = failed, Command = bad });
        listener.Write("System.Data.SqlClient.WriteCommandError", new { OperationId = failed, Command = bad, Exception = new Exception("x") });

        var rows = platform.QueriesModule!.Take(true);
        var row = Row(rows, "SELECT sqlclient_ok FROM t WHERE id = ?");
        Assert.Equal(("JOB", "(background)", "mssql"), (row.Key.Method, row.Key.Route, row.Key.Db));
        Assert.Equal((1L, 0L), (row.Stat.Count, row.Stat.Errors));
        Assert.Equal(1, Row(rows, "UPDATE sqlclient_bad SET a = ?").Stat.Errors);
    }

    [Fact]
    public void NpgsqlAndMySqlConnectorActivities()
    {
        var platform = Make();
        using var npgsql = new ActivitySource("Npgsql");
        var scope = new Scope(() => new RequestFields());
        using (Scope.Enter(scope))
        {
            using (var activity = npgsql.StartActivity("SELECT", ActivityKind.Client))
            {
                Assert.NotNull(activity);
                activity!.SetTag("db.system", "postgresql");
                activity.SetTag("db.statement", "SELECT npgsql_x FROM t WHERE a = 'secret'");
            }
            // An open, not a query.
            npgsql.StartActivity("connect")?.Dispose();
        }
        platform.QueriesModule!.Finish(scope, "POST", "/orders");
        using var mysql = new ActivitySource("MySqlConnector");
        var failed = mysql.StartActivity("Execute")!;
        failed.SetTag("db.system.name", "mariadb");
        failed.SetTag("db.query.text", "UPDATE mysql_x SET a = 1");
        failed.SetStatus(ActivityStatusCode.Error);
        failed.Stop();

        var rows = platform.QueriesModule.Take(true);
        var pg = Row(rows, "SELECT npgsql_x FROM t WHERE a = ?");
        Assert.Equal(("POST", "/orders", "postgresql"), (pg.Key.Method, pg.Key.Route, pg.Key.Db));
        var my = Row(rows, "UPDATE mysql_x SET a = ?");
        Assert.Equal(("mariadb", 1L), (my.Key.Db, my.Stat.Errors));
    }

    [Fact]
    public void EntityFrameworkOnlyForSqlite()
    {
        var platform = Make();
        using var ef = new DiagnosticListener("Microsoft.EntityFrameworkCore");
        const string executed = "Microsoft.EntityFrameworkCore.Database.Command.CommandExecuted";
        ef.Write(executed, new { Command = new Microsoft.Data.Sqlite.SqliteCommand { CommandText = "SELECT ef_lite FROM t WHERE id = 3" }, Duration = TimeSpan.FromMilliseconds(4) });
        ef.Write("Microsoft.EntityFrameworkCore.Database.Command.CommandExecuting", new { Command = new Microsoft.Data.Sqlite.SqliteCommand { CommandText = "SELECT ef_lite FROM t WHERE id = 3" } });
        ef.Write("Microsoft.EntityFrameworkCore.Database.Command.CommandError", new { Command = new Microsoft.Data.Sqlite.SqliteCommand { CommandText = "DELETE FROM ef_lite" }, Duration = TimeSpan.FromMilliseconds(1) });
        // Npgsql's own ActivitySource has it already.
        ef.Write(executed, new { Command = new Npgsql.NpgsqlCommand { CommandText = "SELECT ef_pg FROM t" }, Duration = TimeSpan.FromMilliseconds(4) });

        var rows = platform.QueriesModule!.Take(true);
        var lite = Row(rows, "SELECT ef_lite FROM t WHERE id = ?");
        Assert.Equal(("sqlite", 1L, 4.0), (lite.Key.Db, lite.Stat.Count, lite.Stat.SumMs));
        Assert.Equal(1, Row(rows, "DELETE FROM ef_lite").Stat.Errors);
        Assert.DoesNotContain(rows, r => r.Key.Statement.Contains("ef_pg"));
    }

    [Fact]
    public void MongoCommandEvents()
    {
        var platform = Make();
        var settings = new MongoDB.Driver.MongoClientSettings();
        var theirs = false;
        settings.ClusterConfigurator = _ => theirs = true;
        Assert.Same(settings, platform.WatchMongo(settings));
        platform.WatchMongo(settings);
        var builder = new ClusterBuilder();
        settings.ClusterConfigurator!(builder);
        Assert.True(theirs);
        Assert.Equal(3, builder.Handlers.Count);

        var find = new BsonDocument
        {
            { "find", new BsonString("mongo_users") },
            { "filter", new BsonDocument { { "email", new BsonString("a@b.c") }, { "age", new BsonDocument { { "$gt", new BsonInt32(30) } } } } },
            { "limit", new BsonInt32(1) },
        };
        builder.Fire(new CommandStartedEvent("find", find, 990001));
        builder.Fire(new CommandSucceededEvent("find", 990001, TimeSpan.FromMilliseconds(7)));
        builder.Fire(new CommandStartedEvent("ping", new BsonDocument { { "ping", new BsonInt32(1) } }, 990002));
        builder.Fire(new CommandSucceededEvent("ping", 990002, TimeSpan.FromMilliseconds(1)));
        var deletes = new BsonArray { new BsonDocument { { "q", new BsonDocument { { "_id", new BsonString("x") } } }, { "limit", new BsonInt32(1) } } };
        builder.Fire(new CommandStartedEvent("delete", new BsonDocument { { "delete", new BsonString("mongo_carts") }, { "deletes", deletes } }, 990003));
        builder.Fire(new CommandFailedEvent("delete", 990003, TimeSpan.FromMilliseconds(2)));

        var rows = platform.QueriesModule!.Take(true);
        var found = Row(rows, "find mongo_users {\"email\":\"?\",\"age\":{\"$gt\":\"?\"}}");
        Assert.Equal(("mongodb", 1L, 7.0), (found.Key.Db, found.Stat.Count, found.Stat.SumMs));
        Assert.Equal(1, Row(rows, "delete mongo_carts {\"_id\":\"?\"}").Stat.Errors);
        Assert.DoesNotContain(rows, r => r.Key.Statement.StartsWith("ping", StringComparison.Ordinal));
    }

    [Fact]
    public void SharedRedisCommands()
    {
        var cases = Shared.Load("query-cases.json").GetProperty("redis_commands").EnumerateArray().ToList();
        Assert.True(cases.Count >= 40, "redis_commands: " + cases.Count);
        var wrong = new List<string>();
        foreach (var c in cases)
        {
            var args = c.GetProperty("args").EnumerateArray()
                .Select(a => a.ValueKind == System.Text.Json.JsonValueKind.String ? (object?)a.GetString() : a.ValueKind == System.Text.Json.JsonValueKind.Number ? a.GetDouble() : a.ToString())
                .ToList();
            var expected = c.GetProperty("expected").ValueKind == System.Text.Json.JsonValueKind.Null ? null : c.GetProperty("expected").GetString();
            var got = QueryText.RedisCommand(args);
            if (got != expected) wrong.Add("[" + string.Join(", ", args) + "] expected " + expected + " got " + got);
        }
        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
        // a-z only: no "I" from a dotless i, no "SS" from a sharp s.
        Assert.Null(QueryText.RedisCommand(new object?[] { "geß", "k" }));
        Assert.Equal("GET ?", QueryText.RedisCommand(new object?[] { "get", "straße" }));
    }

    [Fact]
    public async Task RedisProfiledCommands()
    {
        var platform = Make();
        var redis = new StackExchange.Redis.ConnectionMultiplexer();
        Assert.Same(redis, platform.WatchRedis(redis));
        platform.WatchRedis(redis);
        Assert.Equal(1, redis.Registered);
        Assert.Same(platform, platform.WatchRedis(platform));

        using (Scope.Enter(new Scope(() => new RequestFields { Method = "GET", Path = "/cart" })))
        {
            redis.Run("GET", 3);
            redis.Run("SET", 2);
            // A worker's wait, not work: never timed.
            redis.Run("BLPOP", 5000);
            // Resent after MOVED: counted once, the resend's time is from the first send.
            var moved = redis.Run("HGET", 1);
            redis.Run("HGET", 4, moved);
            platform.TimeRequest("get", "/cart", 200, Stopwatch.GetTimestamp());
        }
        redis.Run("INCR", 1);
        // The package's own reads (Hangfire's queues): not the app's.
        await Task.Run(() =>
        {
            RedisHook.Own.Value = true;
            redis.Run("ZCARD", 1);
        });
        RedisHook.DrainNow();

        var rows = platform.QueriesModule!.Take(true).Where(r => r.Key.Db == "redis").ToList();
        var get = Row(rows, "GET");
        Assert.Equal(("GET", "/cart", 1L, 3.0, 0L), (get.Key.Method, get.Key.Route, get.Stat.Count, get.Stat.SumMs, get.Stat.Errors));
        Assert.Equal((1L, 4.0), (Row(rows, "HGET").Stat.Count, Row(rows, "HGET").Stat.SumMs));
        Assert.Equal("/cart", Row(rows, "SET").Key.Route);
        Assert.Equal(("JOB", "(background)"), (Row(rows, "INCR").Key.Method, Row(rows, "INCR").Key.Route));
        Assert.DoesNotContain(rows, r => r.Key.Statement == "BLPOP" || r.Key.Statement == "ZCARD");
        await platform.CloseAsync();
    }

    // ---- Subscribing to the libraries' listeners ----

    private sealed class Heard : IObserver<KeyValuePair<string, object?>>
    {
        private readonly List<string> names;

        public Heard(List<string> names) => this.names = names;
        public void OnCompleted() { }
        public void OnError(Exception error) { }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            lock (names) names.Add(value.Key);
        }
    }

    [Fact]
    public void AListenersWatchHearsEachListenerOnceAndLeavesThemOnStop()
    {
        var name = "sitegoose-test-" + Guid.NewGuid().ToString("N");
        var heard = new List<string>();
        var watch = new AllListenersWatch(l => l.Name == name ? l.Subscribe(new Heard(heard)) : null);
        using var before = new DiagnosticListener(name);
        watch.Start();
        watch.Start();
        using var after = new DiagnosticListener(name);
        before.Write("a", null);
        after.Write("b", null);
        Assert.Equal(new[] { "a", "b" }, heard);
        Assert.Equal(2, watch.Subscriptions);

        var stale = watch.Generation;
        watch.Stop();
        Assert.False(before.IsEnabled());
        Assert.False(after.IsEnabled());
        before.Write("c", null);
        Assert.Equal(0, watch.Subscriptions);

        // Started again, and an observer of the stopped subscription still
        // handing over a listener: that one subscribes nothing, so it's heard once.
        watch.Start();
        watch.ObserverOf(stale).OnNext(before);
        before.Write("d", null);
        Assert.Equal(new[] { "a", "b", "d" }, heard);
        watch.Stop();
    }

    [Fact]
    public void StoppingWhileAListenerIsBeingMadeDoesntDeadlock()
    {
        var name = "sitegoose-test-" + Guid.NewGuid().ToString("N");
        using var inside = new System.Threading.ManualResetEventSlim();
        var watch = new AllListenersWatch(l =>
        {
            if (l.Name != name) return null;
            inside.Set();
            // DiagnosticListener's own lock is held here: Stop waits for it meanwhile.
            System.Threading.Thread.Sleep(200);
            return l.Subscribe(new Heard(new List<string>()));
        });
        watch.Start();
        DiagnosticListener? made = null;
        var making = Task.Run(() => made = new DiagnosticListener(name));
        Assert.True(inside.Wait(5000));
        var stopping = Task.Run(watch.Stop);
        Assert.True(Task.WaitAll(new[] { making, stopping }, 5000), "Stop and a new listener deadlocked");
        Assert.Equal(0, watch.Subscriptions);
        Assert.False(made!.IsEnabled());
        made.Dispose();
    }

    [Fact]
    public void PendingQueriesStayBounded()
    {
        var pending = new PendingMap<int, int>(10);
        for (var i = 0; i < 25; i++) pending.Set(i, i);
        Assert.InRange(pending.Count, 1, 10);
        Assert.True(pending.TryRemove(24, out var value));
        Assert.Equal(24, value);
        Assert.False(pending.TryRemove(24, out _));
    }

    // ---- Requests Server speed doesn't time ----

    private sealed class Upgradable : Microsoft.AspNetCore.Http.Features.IHttpUpgradeFeature
    {
        public bool IsUpgradableRequest => true;

        public Task<System.IO.Stream> UpgradeAsync() => Task.FromResult<System.IO.Stream>(new System.IO.MemoryStream());
    }

    private static Microsoft.AspNetCore.Http.DefaultHttpContext Request(string path)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("198.51.100.1");
        context.Request.Method = "GET";
        context.Request.Path = path;
        context.Response.Body = new System.IO.MemoryStream();
        return context;
    }

    [Fact]
    public async Task AWebSocketsAndAnEventStreamsQueriesAreBackgroundOnes()
    {
        var platform = Make();
        if (platform.FirewallModule is { } firewall) firewall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}"));
        var queries = platform.QueriesModule!;
        // A WebSocket: known as it starts, so its queries are filed as they run.
        var socket = Request("/ws");
        socket.Request.Headers.Upgrade = "websocket";
        socket.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpUpgradeFeature>(new Upgradable());
        Queries.Ready? during = null;
        await new PlatformMiddleware(_ =>
        {
            queries.Add("postgresql", "SELECT ws_during", 1, false);
            during = queries.Take(true).SingleOrDefault(r => r.Key.Statement == "SELECT ws_during");
            return Task.CompletedTask;
        }, platform).InvokeAsync(socket);
        Assert.NotNull(during);
        Assert.Equal(("JOB", "(background)"), (during!.Key.Method, during.Key.Route));
        // An event stream: known when it ends.
        await new PlatformMiddleware(c =>
        {
            queries.Add("postgresql", "SELECT sse_during", 1, false);
            c.Response.ContentType = "text/event-stream";
            return Task.CompletedTask;
        }, platform).InvokeAsync(Request("/events"));

        var row = Row(queries.Take(true), "SELECT sse_during");
        Assert.Equal(("JOB", "(background)", 1L), (row.Key.Method, row.Key.Route, row.Stat.Count));
        Assert.Empty(platform.PerformanceModule!.Take(true));
        await platform.CloseAsync();
    }
}
