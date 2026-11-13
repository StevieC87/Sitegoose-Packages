using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

// Stand-ins for Hangfire's monitoring API, found by name as the real one is:
// the same type and member names, and nothing else.
namespace Hangfire.Storage.Monitoring
{
    public class JobList<TDto> : List<KeyValuePair<string, TDto>>
    {
    }

    public sealed class EnqueuedJobDto
    {
        public DateTime? EnqueuedAt { get; set; }
    }

    public sealed class QueueWithTopEnqueuedJobsDto
    {
        public string Name { get; set; } = "";
        public long Length { get; set; }
        public JobList<EnqueuedJobDto> FirstJobs { get; set; } = new();
    }

    public sealed class StatisticsDto
    {
        public long Succeeded { get; set; }
        public long Deleted { get; set; }
    }
}

namespace Hangfire.Storage
{
    using Hangfire.Storage.Monitoring;

    public interface IMonitoringApi
    {
        IList<QueueWithTopEnqueuedJobsDto> Queues();
        long EnqueuedCount(string queue);
        JobList<EnqueuedJobDto> EnqueuedJobs(string queue, int from, int perPage);
        long ProcessingCount();
        long ScheduledCount();
        long FailedCount();
        StatisticsDto GetStatistics();
        IDictionary<DateTime, long> HourlyFailedJobs();
    }
}

namespace SiteGoose.Tests
{
    using Hangfire.Storage;
    using Hangfire.Storage.Monitoring;

    /// <summary>A JobStorage with a monitoring API the test sets, implemented
    /// explicitly as storages may.</summary>
    public sealed class FakeHangfire : IMonitoringApi
    {
        public Dictionary<string, List<DateTime>> Waiting = new();
        public long Processing = 2, Scheduled = 5, Failed = 1, Succeeded = 100, Deleted = 3;
        public Dictionary<DateTime, long> FailedHours = new();
        public bool Broken;
        public bool OldestFirst;
        public int FarEndReads;

        public object GetMonitoringApi() => Broken ? throw new InvalidOperationException("database down") : this;
        public override string ToString() => "Server: db1@Hangfire;Password=hunter2";

        IList<QueueWithTopEnqueuedJobsDto> IMonitoringApi.Queues() => Waiting.Where(p => p.Value.Count > 0).Select(p =>
        {
            var first = new JobList<EnqueuedJobDto>();
            // Newest first, as a storage may list them: the oldest is at the far end.
            foreach (var at in Ordered(p.Value).Take(5)) first.Add(new KeyValuePair<string, EnqueuedJobDto>("j", new EnqueuedJobDto { EnqueuedAt = at }));
            return new QueueWithTopEnqueuedJobsDto { Name = p.Key, Length = p.Value.Count, FirstJobs = first };
        }).ToList();

        private IEnumerable<DateTime> Ordered(List<DateTime> jobs) => OldestFirst ? jobs.OrderBy(t => t) : jobs.OrderByDescending(t => t);

        long IMonitoringApi.EnqueuedCount(string queue) => Waiting.TryGetValue(queue, out var jobs) ? jobs.Count : 0;

        JobList<EnqueuedJobDto> IMonitoringApi.EnqueuedJobs(string queue, int from, int perPage)
        {
            FarEndReads += 1;
            var list = new JobList<EnqueuedJobDto>();
            foreach (var at in Ordered(Waiting[queue]).Skip(from).Take(perPage)) list.Add(new KeyValuePair<string, EnqueuedJobDto>("j", new EnqueuedJobDto { EnqueuedAt = at }));
            return list;
        }

        long IMonitoringApi.ProcessingCount() => Processing;
        long IMonitoringApi.ScheduledCount() => Scheduled;
        long IMonitoringApi.FailedCount() => Failed;
        StatisticsDto IMonitoringApi.GetStatistics() => new() { Succeeded = Succeeded, Deleted = Deleted };
        IDictionary<DateTime, long> IMonitoringApi.HourlyFailedJobs() => new Dictionary<DateTime, long>(FailedHours);
    }

    /// <summary>Outgoing calls (calls.md), ClickHouse query timing, Hangfire
    /// queues (queues.md) and the limits pass (resources.md "Limits").</summary>
    public class CallsQueuesLimitsTests
    {
        private static Platform Make(FakeCollector? collector = null, Action<PlatformOptions>? more = null) =>
            new(Shared.Options(collector ?? new FakeCollector(), more));

        // ---- Query text and ClickHouse ----

        [Fact]
        public void PostgresBackslashesAreLiteralOutsideEStrings()
        {
            Assert.Equal("SELECT ? AS a, ? AS b", QueryText.Normalize(@"SELECT 'C:\' AS a, 'x' AS b", "postgresql"));
            Assert.Equal("SELECT ? AS a", QueryText.Normalize(@"SELECT E'it\'s' AS a", "postgresql"));
            // MySQL and ClickHouse still escape with one.
            Assert.Equal("SELECT ?", QueryText.Normalize(@"SELECT 'a\'b'", "mysql"));
            Assert.Equal("SELECT ?", QueryText.Normalize(@"SELECT 'a\'b'", "clickhouse"));
            Assert.Equal("clickhouse", QueryText.DatabaseOf("ClickHouse"));
        }

        [Fact]
        public void ClickHouseActivities()
        {
            var platform = Make();
            foreach (var name in new[] { "ClickHouse.Client", "ClickHouse.Driver" })
            {
                using var source = new ActivitySource(name);
                var scope = new Scope(() => new RequestFields());
                using (Scope.Enter(scope))
                {
                    // The connection's own version query when it opens: not the app's.
                    using (var open = source.StartActivity("OpenAsync", ActivityKind.Client))
                    {
                        Assert.NotNull(open);
                        open!.SetTag("db.statement", "SELECT version(), timezone() FORMAT TSV");
                    }
                    using (var query = source.StartActivity("PostSqlQueryAsync", ActivityKind.Client)!)
                    {
                        query.SetTag("db.system", "clickhouse");
                        query.SetTag("db.statement", "SELECT count() FROM ch_events WHERE site = 'x' -- " + name);
                    }
                    using (var bad = source.StartActivity("PostSqlQueryAsync", ActivityKind.Client)!)
                    {
                        bad.SetTag("db.statement", "SELECT ch_fail " + name.Length);
                        bad.SetTag("otel.status_code", "ERROR");
                    }
                }
                platform.QueriesModule!.Finish(scope, "GET", "/stats");
            }
            var rows = platform.QueriesModule!.Take(true).Where(r => r.Key.Db == "clickhouse").ToList();
            var count = Assert.Single(rows, r => r.Key.Statement == "SELECT count() FROM ch_events WHERE site = ?");
            Assert.Equal(("GET", "/stats", 2L, 0L), (count.Key.Method, count.Key.Route, count.Stat.Count, count.Stat.Errors));
            Assert.Equal(2, rows.Single(r => r.Key.Statement == "SELECT ch_fail ?").Stat.Errors);
            Assert.DoesNotContain(rows, r => r.Key.Statement.Contains("version()"));
        }

        // ---- Outgoing calls ----

        [Fact]
        public void HostsAsCallsMdStoresThem()
        {
            Assert.Equal("api.stripe.com", CallHooks.HostOf(new Uri("https://API.Stripe.com/v1/charges?key=secret")));
            Assert.Equal("localhost:8080", CallHooks.HostOf(new Uri("http://user:pw@localhost:8080/x")));
            Assert.Equal("example.com", CallHooks.HostOf(new Uri("http://example.com:80/")));
            Assert.Equal("[::1]:3000", CallHooks.HostOf(new Uri("http://[::1]:3000/")));
            Assert.Equal("xn--bcher-kva.example", CallHooks.HostOf(new Uri("https://bücher.example/")));
            Assert.Equal("", CallHooks.HostOf(new Uri("/relative", UriKind.Relative)));
            Assert.True(CallHooks.Ours(new Uri("http://collector.test/events/server-calls"), "http://collector.test"));
            Assert.True(CallHooks.Ours(new Uri("http://COLLECTOR.test:80/"), "http://collector.test/"));
            Assert.False(CallHooks.Ours(new Uri("http://collector.testing/x"), "http://collector.test"));
        }

        private static HttpRequestMessage Call(string method, string url) => new(new HttpMethod(method), url);

        private static void Answered(string method, string url, int status, TaskStatus task = TaskStatus.RanToCompletion)
        {
            var request = Call(method, url);
            CallHooks.Started(request);
            CallHooks.Stopped(request, status == 0 ? null : new HttpResponseMessage((HttpStatusCode)status), task);
        }

        [Fact]
        public async Task CallsGoUnderTheirRequestAndCountFailuresAsCallsMdSays()
        {
            var collector = new FakeCollector();
            var platform = Make(collector);
            var scope = new Scope(() => new RequestFields());
            using (Scope.Enter(scope))
            {
                Answered("POST", "https://pay.calls-a.test/v1/charges/ch_123?key=x", 200);
                Answered("POST", "https://pay.calls-a.test/v1/refunds", 502);
                Answered("POST", "https://pay.calls-a.test/v1/oops", 404);
                Answered("POST", "https://pay.calls-a.test/v1/reset", 0, TaskStatus.Faulted);
                // Cancelled by the app: not counted.
                Answered("POST", "https://pay.calls-a.test/v1/cancelled", 0, TaskStatus.Canceled);
                // The package's own calls to the collector: never.
                Answered("POST", "http://collector.test/events/server-errors", 202);
                platform.TimeRequest("POST", "/checkout", 200, Stopwatch.GetTimestamp());
            }
            Answered("GET", "http://calls-b.test:8080/health", 200);

            await platform.FlushAsync();
            var sent = collector.Requests.Where(r => r.Url.EndsWith("/events/server-calls", StringComparison.Ordinal)).ToList();
            Assert.NotEmpty(sent);
            Assert.Equal("Bearer test-secret-0123456789abcdef", sent[0].Headers["Authorization"]);
            var rows = sent.SelectMany(r => r.Json.GetProperty("rows").EnumerateArray()).ToList();
            var pay = Assert.Single(rows, r => r.GetProperty("host").GetString() == "pay.calls-a.test");
            Assert.Equal("POST", pay.GetProperty("method").GetString());
            Assert.Equal("/checkout", pay.GetProperty("route").GetString());
            Assert.Equal("POST", pay.GetProperty("call_method").GetString());
            Assert.Equal(4, pay.GetProperty("count").GetInt32());
            Assert.Equal(2, pay.GetProperty("errors").GetInt32());
            Assert.False(pay.TryGetProperty("db", out _));
            Assert.Equal(12, pay.GetProperty("buckets").GetArrayLength());
            var background = Assert.Single(rows, r => r.GetProperty("host").GetString() == "calls-b.test:8080");
            Assert.Equal(("JOB", "(background)", "GET"), (background.GetProperty("method").GetString(), background.GetProperty("route").GetString(), background.GetProperty("call_method").GetString()));
            Assert.DoesNotContain(rows, r => r.GetProperty("host").GetString() == "collector.test");
        }

        [Fact]
        public void FiftyHostsARequest()
        {
            var platform = Make();
            var scope = new Scope(() => new RequestFields());
            using (Scope.Enter(scope))
            {
                for (var i = 0; i < 55; i++) Answered("GET", "https://h" + i + ".calls-cap.test/", 200);
            }
            platform.CallsModule!.Finish(scope, "GET", "/fan-out");
            var rows = platform.CallsModule.Take(true).Where(r => r.Key.Route == "/fan-out").ToList();
            Assert.Equal(Queries.RequestMax + 1, rows.Count);
            Assert.Equal(5, rows.Single(r => r.Key.Statement == "(other)").Stat.Count);
        }

        [Fact]
        public async Task HttpClientsOwnHookTimesARealCall()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serving = Task.Run(async () =>
            {
                for (var i = 0; i < 3; i++)
                {
                    using var client = await listener.AcceptTcpClientAsync();
                    var stream = client.GetStream();
                    var buffer = new byte[4096];
                    var head = "";
                    while (!head.Contains("\r\n\r\n")) head += Encoding.ASCII.GetString(buffer, 0, await stream.ReadAsync(buffer));
                    var status = head.Contains("/fail") ? "503 Service Unavailable" : "200 OK";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
                }
            });
            using var http = new HttpClient();
            // HttpClient's listener exists before the platform does: it is still heard.
            (await http.GetAsync("http://127.0.0.1:" + port + "/before")).Dispose();
            var platform = Make();
            var scope = new Scope(() => new RequestFields());
            using (Scope.Enter(scope))
            {
                (await http.GetAsync("http://127.0.0.1:" + port + "/ok?token=x")).Dispose();
                (await http.PostAsync("http://127.0.0.1:" + port + "/fail", new StringContent("x"))).Dispose();
            }
            await serving;
            listener.Stop();
            platform.CallsModule!.Finish(scope, "GET", "/real");
            var rows = platform.CallsModule.Take(true).Where(r => r.Key.Statement == "127.0.0.1:" + port).ToList();
            Assert.Equal(1, rows.Single(r => r.Key.Db == "GET").Stat.Count);
            var failed = rows.Single(r => r.Key.Db == "POST");
            Assert.Equal((1L, 1L, "/real"), (failed.Stat.Count, failed.Stat.Errors, failed.Key.Route));
        }

        [Fact]
        public void AClickHouseClientsRequestIsItsQueryNotACall()
        {
            var platform = Make();
            using var source = new ActivitySource("ClickHouse.Client");
            using var http = new ActivitySource("calls-test-http");
            using var any = new ActivityListener { ShouldListenTo = s => s.Name == "calls-test-http", Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData };
            ActivitySource.AddActivityListener(any);
            using (source.StartActivity("PostSqlQueryAsync", ActivityKind.Client))
            using (http.StartActivity("System.Net.Http.HttpRequestOut"))
            {
                Answered("POST", "http://ch-host.calls.test:8123/", 200);
            }
            Assert.DoesNotContain(platform.CallsModule!.Take(true), r => r.Key.Statement == "ch-host.calls.test:8123");
        }

        [Fact]
        public void CallsAndQueuesOffWhenAsked()
        {
            var off = Make(more: o =>
            {
                o.Performance.Calls = false;
                o.Performance.Queues = false;
            });
            Assert.Null(off.CallsModule);
            Assert.Null(off.QueuesModule);
            Assert.NotNull(off.QueriesModule);
            Assert.Null(Make(more: o => o.Performance.Enabled = false).CallsModule);
            var storage = new FakeHangfire();
            Assert.Same(storage, off.WatchHangfire(storage));
        }

        // ---- Hangfire ----

        [Fact]
        public async Task HangfireQueuesAsQueuesMdSays()
        {
            var collector = new FakeCollector();
            var platform = Make(collector);
            var now = DateTime.UtcNow;
            var hour = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc);
            var storage = new FakeHangfire
            {
                Waiting = new()
                {
                    ["default"] = Enumerable.Range(0, 8).Select(i => now.AddSeconds(-30 - i * 10)).ToList(),
                    ["critical"] = new() { now.AddSeconds(-5) },
                },
                FailedHours = new() { [hour.AddHours(-1)] = 4, [hour] = 1 },
            };
            platform.WatchHangfire(storage);
            var first = await platform.QueuesModule!.SampleAsync();
            var byQueue = first.ToDictionary(r => (string)r["queue"]!);
            Assert.Equal(new[] { "(all queues)", "critical", "default" }, byQueue.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
            Assert.Equal(8L, byQueue["default"]["waiting"]);
            // The oldest is at the far end of a newest-first list.
            Assert.InRange((long)byQueue["default"]["oldest_s"]!, 99, 102);
            Assert.Null(byQueue["default"]["running"]);
            var all = byQueue["(all queues)"];
            Assert.Equal((2L, 5L, 1L), ((long)all["running"]!, (long)all["delayed"]!, (long)all["failed"]!));
            Assert.Null(all["waiting"]);
            // No earlier reading: finished is unknown, and Hangfire counts nothing added.
            Assert.Null(all["finished"]);
            Assert.Null(all["added"]);
            Assert.True((bool)all["shared"]!);
            Assert.Equal("hangfire", all["system"]);
            // As the collector takes a broker: no "@", "//" or space.
            Assert.Equal("db1/Hangfire", all["broker"]);

            var sent = collector.Requests.Single(r => r.Url.EndsWith("/events/server-queues", StringComparison.Ordinal)).Json;
            Assert.Equal(platform.QueuesModule.Sender, sent.GetProperty("sender").GetString());
            Assert.Equal("web-1", sent.GetProperty("server_name").GetString());

            // A minute on: 7 succeeded, 1 deleted, 2 failed for good (one in a new hour).
            storage.Succeeded += 7;
            storage.Deleted += 1;
            storage.FailedHours[hour] = 2;
            storage.FailedHours[hour.AddHours(1)] = 1;
            storage.FailedHours.Remove(hour.AddHours(-1));
            storage.Waiting["critical"].Clear();
            var second = (await platform.QueuesModule.SampleAsync()).ToDictionary(r => (string)r["queue"]!);
            Assert.Equal(10L, second["(all queues)"]["finished"]);
            // Emptied: gone from Hangfire's list, still 0 waiting here.
            Assert.Equal((0L, 0L), ((long)second["critical"]["waiting"]!, (long)second["critical"]["oldest_s"]!));

            // A reading that fails is a gap, never zeros.
            storage.Broken = true;
            Assert.Empty(await platform.QueuesModule.SampleAsync());
        }

        [Fact]
        public async Task HangfireOldestFirstAndSwitchedOff()
        {
            var off = false;
            var collector = new FakeCollector(r => r.Url.Contains("/events/platform/config")
                ? FakeCollector.Reply(200, off ? "{\"v\":1,\"modules\":{\"performance\":false}}" : "{\"v\":1,\"modules\":{}}")
                : FakeCollector.Reply(202, "{}"));
            var platform = Make(collector);
            var now = DateTime.UtcNow;
            var storage = new FakeHangfire { OldestFirst = true, Waiting = new() { ["default"] = Enumerable.Range(0, 8).Select(i => now.AddSeconds(-30 - i * 10)).ToList() } };
            platform.WatchHangfire(storage);
            var first = (await platform.QueuesModule!.SampleAsync()).Single(r => (string)r["queue"]! == "default");
            // The first jobs are the oldest: the far end isn't read (a deep offset scans the table).
            Assert.InRange((long)first["oldest_s"]!, 99, 102);
            Assert.Equal(0, storage.FarEndReads);

            // Off for a while: what finished meanwhile isn't put into one minute.
            off = true;
            await platform.Core.SyncSwitchesAsync();
            Assert.Empty(await platform.QueuesModule.SampleAsync());
            storage.Succeeded += 500;
            off = false;
            await platform.Core.SyncSwitchesAsync();
            Assert.Null((await platform.QueuesModule.SampleAsync()).Single(r => (string)r["queue"]! == "(all queues)")["finished"]);
        }

        [Fact]
        public void HangfireCountersThatWentDownAreUnknown()
        {
            var before = new Queues.Totals { Succeeded = 10, Deleted = 1 };
            Assert.Null(Queues.FinishedSince(before, new Queues.Totals { Succeeded = 2, Deleted = 1 }));
            Assert.Equal(0, Queues.FinishedSince(before, new Queues.Totals { Succeeded = 10, Deleted = 1 }));
            Assert.Equal("cache:6379/0", Queues.Scrub("redis://user:secret@cache:6379/0"));
            Assert.Equal("cache:6379", Queues.Scrub("cache:6379,password=secret"));
            Assert.Equal("(localdb)\\MSSQLLocalDB/Hangfire", Queues.Scrub("SQL Server: (localdb)\\MSSQLLocalDB@Hangfire"));
            Assert.Equal("Host:db,DB:hangfire,Schema:hangfire", Queues.Scrub("PostgreSQL Server: Host: db, DB: hangfire, Schema: hangfire"));
            Assert.Equal("", Queues.Scrub("<Connection string can not be parsed>"));
            Assert.Equal("jobs-db", Queues.Scrub("jobs-db"));
            Assert.Equal("not a Hangfire JobStorage (no GetMonitoringApi)", Make().QueuesModule!.Watch(new object()));
        }

        // ---- Limits ----

        private static Func<string, string> Files(Dictionary<string, string> files) => path => files.TryGetValue(path, out var text) ? text : "";

        [Fact]
        public void CgroupV2InAContainer()
        {
            var files = new Dictionary<string, string>
            {
                ["/proc/self/cgroup"] = "0::/\n",
                ["/sys/fs/cgroup/memory.max"] = "536870912\n",
                ["/sys/fs/cgroup/memory.current"] = "419430400\n",
                ["/sys/fs/cgroup/memory.stat"] = "anon 1\ninactive_file 104857600\n",
                ["/sys/fs/cgroup/memory.events"] = "low 0\noom_kill 1\n",
                ["/sys/fs/cgroup/cpu.max"] = "150000 100000\n",
                ["/sys/fs/cgroup/cpu.stat"] = "nr_periods 100\nnr_throttled 5\n",
            };
            var read = Files(files);
            var cg = Limits.FindCgroup(read)!;
            Assert.Equal((2, "/sys/fs/cgroup"), (cg.Version, cg.Memory));
            var before = Limits.ReadCgroup(cg, read);
            files["/sys/fs/cgroup/cpu.stat"] = "nr_periods 300\nnr_throttled 55\n";
            files["/sys/fs/cgroup/memory.events"] = "oom_kill 3\n";
            var fields = Limits.CgroupFields(before, Limits.ReadCgroup(cg, read), 7954, 8);
            Assert.Equal(512L, fields["limit_mem_mb"]);
            Assert.Equal(300L, fields["limit_mem_used_mb"]);
            Assert.Equal(1.5, fields["limit_cpu_cores"]);
            Assert.Equal(25.0, fields["cpu_throttled_pct"]);
            Assert.Equal(2L, fields["oom_kills"]);
        }

        [Fact]
        public void ACapThatIsntOneIsLeftOut()
        {
            var files = new Dictionary<string, string>
            {
                ["/proc/self/cgroup"] = "12:memory:/system.slice/app.service\n11:cpu,cpuacct:/system.slice/app.service\n",
                ["/sys/fs/cgroup/memory/memory.limit_in_bytes"] = "9223372036854771712\n",
                ["/sys/fs/cgroup/memory/memory.usage_in_bytes"] = "1000000\n",
                ["/sys/fs/cgroup/cpu/cpu.cfs_quota_us"] = "-1\n",
                ["/sys/fs/cgroup/cpu/cpu.cfs_period_us"] = "100000\n",
            };
            var read = Files(files);
            var cg = Limits.FindCgroup(read)!;
            Assert.Equal((1, "/sys/fs/cgroup/memory", "/sys/fs/cgroup/cpu"), (cg.Version, cg.Memory, cg.Cpu));
            var reading = Limits.ReadCgroup(cg, read);
            Assert.Empty(Limits.CgroupFields(null, reading, 7954, 8));
            // A cap at or above the machine's own memory, or cores, isn't one either.
            var big = new Limits.CgroupReading { MemCap = 8L * 1024 * 1024 * 1024, MemUsed = 1, CpuCores = 8 };
            Assert.Empty(Limits.CgroupFields(null, big, 7954, 8));
            Assert.Null(Limits.FindCgroup(Files(new())));
        }

        [Fact]
        public void PressureListenDropsConntrackAndFiles()
        {
            Assert.Equal(12.3, Limits.PressureSome("some avg10=1.00 avg60=12.34 avg300=0.50 total=1\nfull avg10=0 avg60=99 avg300=0 total=0\n"));
            Assert.Null(Limits.PressureSome(""));
            Assert.Equal(17, Limits.ListenOverflows("TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 17 20\nIpExt: a\nIpExt: 1\n"));
            Assert.Null(Limits.ListenOverflows("Ip: a\nIp: 1\n"));
            Assert.Equal(25.0, Limits.ConntrackPct(Files(new() { ["/proc/sys/net/netfilter/nf_conntrack_count"] = "16384", ["/proc/sys/net/netfilter/nf_conntrack_max"] = "65536" })));
            Assert.Null(Limits.ConntrackPct(Files(new())));
            Assert.Null(Limits.CountSince(10, 4));
            Assert.Equal(6, Limits.CountSince(4, 10));
            var limits = "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 1048576              files\n";
            var fields = Limits.FileFields(Files(new() { ["/proc/self/limits"] = limits }), () => 41);
            Assert.Equal((40L, 1024L), ((long)fields["fds_used"]!, (long)fields["fds_max"]!));
            Assert.Null(Limits.FdLimit("Max open files            unlimited            unlimited            files\n"));
            Assert.Empty(Limits.HeapFields(0, 100));
            Assert.Equal(4, Limits.HostCores("cpu  1 2 3\ncpu0 1\ncpu1 1\ncpu2 1\ncpu3 1\nintr 5\n"));
        }

        [Fact]
        public void TheSampleCarriesTheProcessFigures()
        {
            var platform = Make();
            var resources = platform.ResourcesModule!;
            var row = resources.Sample();
            Assert.Matches("^[0-9a-f]{12}$", (string)row["proc_key"]!);
            Assert.True((long)row["proc_uptime_s"]! >= 0);
            Assert.True(row.ContainsKey("queue_waiting"));
            Assert.True((long)row["heap_used_mb"]! >= 0 && (long)row["heap_max_mb"]! > 0);
            // The middleware never ran: no peak, never 0.
            Assert.False(row.ContainsKey("inflight_peak"));
#if NET7_0_OR_GREATER
            Assert.True(row.ContainsKey("gc_ms"));
#else
            Assert.False(row.ContainsKey("gc_ms"));
#endif
            var performance = platform.PerformanceModule!;
            performance.RequestStarted();
            performance.RequestStarted();
            performance.RequestStarted();
            performance.RequestEnded();
            Assert.Equal(3L, resources.Sample()["inflight_peak"]);
            // The peak starts again from what is still in progress.
            Assert.Equal(2L, resources.Sample()["inflight_peak"]);
        }
    }
}
