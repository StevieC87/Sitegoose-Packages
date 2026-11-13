package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mongodb.ServerAddress;
import com.mongodb.connection.ClusterId;
import com.mongodb.connection.ConnectionDescription;
import com.mongodb.connection.ServerId;
import com.mongodb.event.CommandFailedEvent;
import com.mongodb.event.CommandListener;
import com.mongodb.event.CommandStartedEvent;
import com.mongodb.event.CommandSucceededEvent;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.bson.BsonDocument;
import org.junit.jupiter.api.Test;

/** Database queries (sdk/protocols/queries.md): the shared cases, where each query is counted, the caps, and what is sent. */
class QueriesTest {
    static final Map<String, Object> CASES = Fixtures.protocol("query-cases.json");

    static Platform offline() {
        return Platform.create(new PlatformOptions().allOff().performance(true).shutdownHook(false));
    }

    /** Rows keyed "METHOD route db statement" -> the row. */
    static Map<String, Map<String, Object>> rows(Platform platform) {
        Map<String, Map<String, Object>> out = new HashMap<>();
        for (Map<String, Object> row : platform.queries().take(true)) {
            out.put(row.get("method") + " " + row.get("route") + " " + row.get("db") + " " + row.get("statement"), row);
        }
        return out;
    }

    /** Not in a minute's last seconds: the caps are per minute. */
    static void awayFromMinuteEnd() throws InterruptedException {
        long into = System.currentTimeMillis() % 60000;
        if (into > 57000) {
            Thread.sleep(60000 - into + 50);
        }
    }

    @Test
    void sharedCases() {
        assertEquals(((Number) CASES.get("max_statement")).intValue(), QueryText.MAX_STATEMENT);
        List<Map<String, Object>> cases = Fixtures.rows(CASES.get("cases"));
        assertTrue(cases.size() >= 29, "cases: " + cases.size());
        for (Map<String, Object> c : cases) {
            String statement = (String) c.get("statement");
            assertEquals(c.get("expected"), QueryText.normalize(statement, (String) c.get("db")), c.get("db") + ": " + statement);
        }
    }

    @Test
    void mongoKeysInJavaScriptsOrder() {
        // Array-index keys first in numeric order, "__proto__" dropped, as JSON.stringify gives them.
        assertEquals("find t {\"2\":\"?\",\"10\":\"?\",\"b\":\"?\",\"a\":\"?\",\"01\":\"?\"}",
                QueryText.normalize("find t {\"b\":1,\"10\":2,\"a\":3,\"2\":4,\"01\":5,\"__proto__\":{\"x\":1}}", "mongodb"));
        assertEquals("find t \"?\"", QueryText.normalize("find t null", "mongodb"));
        assertEquals("find t {\"é\\n\":\"?\"}", QueryText.normalize("find t {\"é\\n\":1}", "mongodb"));
    }

    @Test
    void queriesGoUnderTheirRequestsRoute() throws Exception {
        awayFromMinuteEnd();
        Platform platform = offline();
        List<String> executed = new ArrayList<>();
        DataSource db = platform.wrap(new FakeJdbc.Source("PostgreSQL 16.2", executed));
        assertTrue(Platform.isWrapped(db));
        assertSame(db, platform.wrap(db), "wrapped once");

        Platform.Scope scope = platform.enterRequest("GET", "/orders/7", () -> "/orders/{id}", "", "");
        try (Connection c = db.getConnection(); PreparedStatement s = c.prepareStatement("SELECT * FROM orders WHERE id = ?")) {
            s.setLong(1, 7);
            s.executeQuery();
            s.executeQuery();
        }
        scope.close();
        // The filter times the request after leaving it, with its context.
        platform.timeRequest("GET", "/orders/{id}", 200, System.nanoTime(), "/orders/7", scope.context());

        // Outside any request: background.
        try (Connection c = db.getConnection(); Statement s = c.createStatement()) {
            s.execute("DELETE FROM carts WHERE age > 30");
            SQLException failed = assertThrows(SQLException.class, () -> s.executeUpdate("UPDATE FAIL SET a = 1"));
            assertEquals("no such table", failed.getMessage());
        }
        // A job: its own JOB row's route.
        platform.job("export", () -> {
            try (Connection c = db.getConnection()) {
                c.prepareStatement("INSERT INTO exports (a, b) VALUES (?, ?)").executeBatch();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        });
        // No route given: Server speed's own name for the path.
        try (Platform.Scope s = platform.enterRequest("POST", "/carts/123", null, "", "")) {
            db.getConnection().prepareStatement("SELECT 1").execute();
            platform.timeRequest("POST", "", 201, System.nanoTime(), "/carts/123");
        }

        Map<String, Map<String, Object>> rows = rows(platform);
        Map<String, Object> order = rows.get("GET /orders/{id} postgresql SELECT * FROM orders WHERE id = ?");
        assertNotNull(order, rows.keySet().toString());
        assertEquals(2L, order.get("count"));
        assertEquals(0L, order.get("errors"));
        assertEquals(12, ((List<?>) order.get("buckets")).size());
        assertEquals(2L, ((List<?>) order.get("buckets")).get(0));
        assertEquals(1L, rows.get("JOB (background) postgresql DELETE FROM carts WHERE age > ?").get("count"));
        assertEquals(1L, rows.get("JOB (background) postgresql UPDATE FAIL SET a = ?").get("errors"));
        assertNotNull(rows.get("JOB /(job) export postgresql INSERT INTO exports (a, b) VALUES (?)"), rows.keySet().toString());
        assertNotNull(rows.get("POST /carts/:id postgresql SELECT ?"), rows.keySet().toString());
        assertEquals(5, rows.size(), rows.keySet().toString());
        assertTrue(executed.contains("SELECT * FROM orders WHERE id = ?"), "the driver ran it");
        platform.close(0);
    }

    @Test
    void neverCountedTwice() throws Exception {
        Platform platform = offline();
        List<String> executed = new ArrayList<>();
        DataSource inner = platform.wrap(new FakeJdbc.Source("MySQL", executed));
        // A routing DataSource of the app's own in front of the wrapped pool, wrapped as well.
        DataSource routing = (DataSource) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {DataSource.class},
                (proxy, method, args) -> method.invoke(inner, args));
        DataSource outer = platform.wrap(routing);
        outer.getConnection().prepareStatement("SELECT name FROM users WHERE email = 'a@b.c'").executeQuery();
        Map<String, Map<String, Object>> rows = rows(platform);
        assertEquals(1, rows.size(), rows.keySet().toString());
        assertEquals(1L, rows.values().iterator().next().get("count"));
        // unwrap still finds the driver's object; a pool's metrics rely on it.
        assertTrue(inner.isWrapperFor(FakeJdbc.Source.class));
        assertTrue(inner.unwrap(FakeJdbc.Source.class) instanceof FakeJdbc.Source);
        platform.close(0);
    }

    @Test
    void offMeansUnwrapped() {
        DataSource source = new FakeJdbc.Source("PostgreSQL", new ArrayList<>());
        Platform noQueries = Platform.create(new PlatformOptions().allOff().performance(true).queries(false).shutdownHook(false));
        assertSame(source, noQueries.wrap(source));
        Platform noPerformance = Platform.create(new PlatformOptions().allOff().shutdownHook(false));
        assertSame(source, noPerformance.wrap(source));
        noQueries.close(0);
        noPerformance.close(0);
    }

    @Test
    void springDataSourceBeansKeepTheirClass() throws Exception {
        Platform platform = offline();
        org.springframework.beans.factory.support.StaticListableBeanFactory beans = new org.springframework.beans.factory.support.StaticListableBeanFactory();
        beans.addBean("analyticsPlatform", platform);
        com.sitegoose.analytics.spring.PlatformSpringSupport.DataSources wrapper =
                new com.sitegoose.analytics.spring.PlatformSpringSupport.DataSources(beans.getBeanProvider(Platform.class));
        List<String> executed = new ArrayList<>();
        FakeJdbc.Source bean = new FakeJdbc.Source("PostgreSQL", executed);
        Object timed = wrapper.postProcessAfterInitialization(bean, "dataSource");
        assertTrue(timed instanceof FakeJdbc.Source, "still injectable by its own class: " + timed.getClass());
        assertTrue(timed != bean);
        assertSame(timed, wrapper.postProcessAfterInitialization(timed, "dataSource"), "wrapped once");
        DataSource mine = platform.wrap(bean);
        assertSame(mine, wrapper.postProcessAfterInitialization(mine, "dataSource"), "wrap() by hand is left alone");
        assertSame("x", wrapper.postProcessAfterInitialization("x", "name"));
        ((DataSource) timed).getConnection().prepareStatement("SELECT 1").executeQuery();
        assertEquals(1, bean.connections);
        assertEquals(1L, rows(platform).get("JOB (background) postgresql SELECT ?").get("count"));
        platform.close(0);
    }

    @Test
    void caps() throws Exception {
        awayFromMinuteEnd();
        Platform platform = offline();
        Queries q = platform.queries();
        // 50 distinct statements in one request, then "(other)".
        RequestContext request = new RequestContext("GET", "/big", () -> "/big", "", "");
        for (int i = 0; i < 60; i++) {
            q.record("postgresql", "SELECT a" + i + " FROM t WHERE id = 1", 1, false, request);
        }
        q.finish(request, "GET", "/big");
        Map<String, Map<String, Object>> rows = rows(platform);
        assertEquals(51, rows.size());
        assertEquals(10L, rows.get("GET /big postgresql (other)").get("count"));

        // A minute: 200 keys, then "(other)" per method, route and db; past 300 nothing new.
        for (int i = 0; i < 200; i++) {
            q.record("mysql", "SELECT c" + i + " FROM t", 1, false, null);
        }
        q.record("mysql", "SELECT more FROM t", 1, false, null);
        q.record("mysql", "SELECT evenmore FROM t", 1, false, null);
        for (int i = 0; i < 120; i++) {
            RequestContext r = new RequestContext("GET", "/r" + i, null, "", "");
            q.record("mysql", "SELECT x FROM t", 1, false, r);
            q.finish(r, "GET", "/r" + i);
        }
        rows = rows(platform);
        assertEquals(300, rows.size());
        assertEquals(2L, rows.get("JOB (background) mysql (other)").get("count"));
        assertNotNull(rows.get("GET /r98 mysql (other)"));
        assertFalse(rows.containsKey("GET /r99 mysql (other)"), "the 301st key isn't kept");
        platform.close(0);
    }

    @Test
    void mongoCommands() throws Exception {
        Platform platform = offline();
        CommandListener listener = platform.mongoListener();
        ConnectionDescription connection = new ConnectionDescription(new ServerId(new ClusterId(), new ServerAddress()));
        AtomicInteger ids = new AtomicInteger();
        String[][] commands = {
            {"find", "{\"find\":\"users\",\"filter\":{\"email\":\"a@b.c\",\"age\":{\"$gt\":30}},\"$db\":\"shop\"}"},
            {"delete", "{\"delete\":\"carts\",\"deletes\":[{\"q\":{\"_id\":{\"$oid\":\"65a1b2c3d4e5f60718293a4b\"}},\"limit\":1}]}"},
            {"insert", "{\"insert\":\"orders\",\"documents\":[{\"total\":9}]}"},
            {"ping", "{\"ping\":1}"},
        };
        try (Platform.Scope scope = platform.enterRequest("GET", "/account", () -> "/account", "", "")) {
            for (String[] c : commands) {
                int id = ids.incrementAndGet();
                listener.commandStarted(new CommandStartedEvent(null, 1, id, connection, "shop", c[0], BsonDocument.parse(c[1])));
                if ("delete".equals(c[0])) {
                    listener.commandFailed(new CommandFailedEvent(null, 1, id, connection, "shop", c[0], 3_000_000, new RuntimeException("x")));
                } else {
                    listener.commandSucceeded(new CommandSucceededEvent(null, 1, id, connection, "shop", c[0], new BsonDocument(), 3_000_000));
                }
            }
            platform.timeRequest("GET", "/account", 200, System.nanoTime(), "/account");
        }
        Map<String, Map<String, Object>> rows = rows(platform);
        assertEquals(3, rows.size(), rows.keySet().toString());
        Map<String, Object> find = rows.get("GET /account mongodb find users {\"email\":\"?\",\"age\":{\"$gt\":\"?\"}}");
        assertNotNull(find, rows.keySet().toString());
        assertEquals(3.0, find.get("sum_ms"));
        assertEquals(1L, rows.get("GET /account mongodb delete carts {\"_id\":\"?\"}").get("errors"));
        assertNotNull(rows.get("GET /account mongodb insert orders"));
        platform.close(0);
    }

    @Test
    void sharedRedisCommands() {
        List<Map<String, Object>> cases = Fixtures.rows(CASES.get("redis_commands"));
        assertTrue(cases.size() >= 40, "redis_commands: " + cases.size());
        List<String> wrong = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            List<?> args = (List<?>) c.get("args");
            String got = QueryText.redisCommand(args);
            if (!java.util.Objects.equals(c.get("expected"), got)) {
                wrong.add(args + " expected " + c.get("expected") + " got " + got);
            }
        }
        assertTrue(wrong.isEmpty(), String.join("\n", wrong));
        // a-z only: no "SS" from a German sharp s, no dotless i made "I".
        assertEquals(null, QueryText.redisCommand(java.util.Arrays.asList("geß", "k")));
        assertEquals("GET ?", QueryText.redisCommand(java.util.Arrays.asList("get", "straße")));
    }

    @SuppressWarnings("unchecked")
    static io.lettuce.core.protocol.RedisCommand<Object, Object, Object> lettuce(io.lettuce.core.protocol.ProtocolKeyword type,
            io.lettuce.core.protocol.CommandArgs<?, ?> args) {
        return (io.lettuce.core.protocol.RedisCommand<Object, Object, Object>) (Object) new io.lettuce.core.protocol.Command<>(type,
                new io.lettuce.core.output.StatusOutput<>(io.lettuce.core.codec.StringCodec.UTF8), (io.lettuce.core.protocol.CommandArgs<String, String>) args);
    }

    static io.lettuce.core.protocol.CommandArgs<String, String> args() {
        return new io.lettuce.core.protocol.CommandArgs<>(io.lettuce.core.codec.StringCodec.UTF8);
    }

    /** One command through the listener as Lettuce calls it: started, then succeeded or failed with cause. */
    static void run(io.lettuce.core.event.command.CommandListener listener, io.lettuce.core.protocol.RedisCommand<Object, Object, Object> command,
            Throwable cause) {
        io.lettuce.core.event.command.CommandStartedEvent started = new io.lettuce.core.event.command.CommandStartedEvent(command, 1L);
        listener.commandStarted(started);
        if (cause == null) {
            listener.commandSucceeded(new io.lettuce.core.event.command.CommandSucceededEvent(command, started.getContext(), 1L, 2L));
        } else {
            listener.commandFailed(new io.lettuce.core.event.command.CommandFailedEvent(command, started.getContext(), cause));
        }
    }

    @Test
    void lettuceCommands() {
        Platform platform = offline();
        io.lettuce.core.event.command.CommandListener listener = platform.redisListener();
        try (Platform.Scope scope = platform.enterRequest("GET", "/cart", () -> "/cart", "", "")) {
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.SET, args().addKey("session:abc123").addValue("{\"user\":\"bob@x.com\"}").add("EX").add(60)), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.GET, args().addKey("user:42:cart")),
                    new io.lettuce.core.RedisCommandExecutionException("WRONGTYPE Operation against a key holding the wrong kind of value"));
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.GET, args().addKey("user:43:cart")),
                    new io.lettuce.core.RedisCommandExecutionException("MOVED 3999 127.0.0.1:6381"));
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.EVAL, args().add("return redis.call('get', KEYS[1])").add(1).addKey("lock:order:9").addValue("hunter2")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.EVALSHA, args().add("e0e1f9fabfc9d4800c877a703b823ac0578ff8db").add(0).addValue("hunter2")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.CLIENT, args().add(io.lettuce.core.protocol.CommandKeyword.SETNAME).add("app-1")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.OBJECT, args().add("ENCODING").addKey("k:1")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.BITOP, args().add("AND").addKey("dest:1").addKey("src:2")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.XREADGROUP,
                    args().add("GROUP").add("g").add("c").add("COUNT").add(10).add("STREAMS").addKey("jobs:email").add(">")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.XREAD, args().add("BLOCK").add(0).add("STREAMS").addKey("s").add("$")), null);
            // A stream named with " BLOCK " in it, after STREAMS: still timed.
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.XREAD, args().add("COUNT").add(1).add("STREAMS").addKey("x BLOCK y").add("$")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.BLPOP, args().addKey("queue:default").add(5)), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.AUTH, args().add("default").add("hunter2")), null);
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.PING, null), new io.lettuce.core.RedisException("Connection closed"));
            // A key that isn't UTF-8: its bytes become "?" like any other value.
            io.lettuce.core.protocol.CommandArgs<byte[], byte[]> bytes = new io.lettuce.core.protocol.CommandArgs<>(io.lettuce.core.codec.ByteArrayCodec.INSTANCE)
                    .addKey(new byte[] {(byte) 0xff, ':', 'c', 'a', 'r', 't'});
            run(listener, lettuce(io.lettuce.core.protocol.CommandType.DEL, bytes), null);
            platform.timeRequest("GET", "/cart", 200, System.nanoTime(), "/cart");
        }
        Map<String, Map<String, Object>> rows = rows(platform);
        assertEquals(new java.util.TreeSet<>(java.util.Arrays.asList(
                "GET /cart redis SET session:?", "GET /cart redis GET user:?:cart", "GET /cart redis EVAL lock:order:?",
                "GET /cart redis EVALSHA", "GET /cart redis CLIENT SETNAME", "GET /cart redis OBJECT ENCODING k:?",
                "GET /cart redis BITOP dest:?", "GET /cart redis XREADGROUP jobs:email", "GET /cart redis AUTH",
                "GET /cart redis PING", "GET /cart redis DEL ?:cart", "GET /cart redis XREAD ?")), new java.util.TreeSet<>(rows.keySet()));
        Map<String, Object> get = rows.get("GET /cart redis GET user:?:cart");
        assertEquals(2L, get.get("count"));
        assertEquals(1L, get.get("errors"), "WRONGTYPE is an error, MOVED isn't");
        assertEquals(1L, rows.get("GET /cart redis PING").get("errors"), "no answer is an error");
        assertEquals(0L, rows.get("GET /cart redis SET session:?").get("errors"));

        // Outside any request: background. Performance off: nothing.
        io.lettuce.core.event.command.CommandListener late = Platform.redisListener(() -> platform);
        run(late, lettuce(io.lettuce.core.protocol.CommandType.INCR, args().addKey("hits:9")), null);
        assertNotNull(rows(platform).get("JOB (background) redis INCR hits:?"));
        platform.close(0);
        Platform off = Platform.create(new PlatformOptions().allOff().performance(true).queries(false).shutdownHook(false));
        run(off.redisListener(), lettuce(io.lettuce.core.protocol.CommandType.GET, args().addKey("a")), null);
        assertTrue(off.queries() == null || off.queries().take(true).isEmpty());
        off.close(0);
    }

    @Test
    void sentToTheCollector() throws Exception {
        List<String[]> seen = new CopyOnWriteArrayList<>();
        AtomicInteger answers = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            int status = 202;
            if (path.equals("/events/server-queries")) {
                seen.add(new String[] {exchange.getRequestHeaders().getFirst("Authorization"), body});
                // Busy the first time: the rows must come again.
                if (answers.getAndIncrement() == 0) {
                    status = 503;
                    exchange.getResponseHeaders().add("Retry-After", "1");
                }
            } else if (path.startsWith("/events/platform/config")) {
                status = 304;
            }
            byte[] out = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, status == 304 ? -1 : out.length);
            if (status != 304) {
                exchange.getResponseBody().write(out);
            }
            exchange.close();
        });
        server.start();
        Platform platform = Platform.create(new PlatformOptions().allOff().performance(true)
                .siteId("b".repeat(24)).secret("query-secret").endpoint("http://127.0.0.1:" + server.getAddress().getPort())
                .serverName("shop-api").shutdownHook(false));
        try {
            Queries q = platform.queries();
            q.record("PostgreSQL", "SELECT * FROM users WHERE email = 'secret@example.com'", 12.345, false, null);
            q.record("postgresql", "SELECT * FROM users WHERE email = 'other@example.com'", 0.04, true, null);
            platform.flush();
            platform.flush();
            assertEquals(2, seen.size());
            assertEquals(seen.get(0)[1], seen.get(1)[1], "the turned-away rows went again");
            assertEquals("Bearer query-secret", seen.get(1)[0]);
            String body = seen.get(1)[1];
            assertFalse(body.contains("secret@example.com") || body.contains("query-secret"), body);
            Map<String, Object> sent = Json.map(Json.parse(body));
            assertEquals("b".repeat(24), sent.get("site_id"));
            assertEquals("shop-api", sent.get("server_name"));
            assertTrue(String.valueOf(sent.get("runtime")).startsWith("Java "));
            List<Map<String, Object>> rows = Fixtures.rows(sent.get("rows"));
            assertEquals(1, rows.size());
            Map<String, Object> row = rows.get(0);
            assertEquals("JOB", row.get("method"));
            assertEquals("(background)", row.get("route"));
            assertEquals("postgresql", row.get("db"));
            assertEquals("SELECT * FROM users WHERE email = ?", row.get("statement"));
            assertEquals(2L, row.get("count"));
            assertEquals(1L, row.get("errors"));
            assertEquals(12.4, row.get("sum_ms"));
            assertEquals(12.3, row.get("max_ms"));
            assertTrue(String.valueOf(row.get("minute")).matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:00Z"), String.valueOf(row.get("minute")));
            assertEquals("[1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]", String.valueOf(row.get("buckets")));
            platform.flush();
            assertEquals(2, seen.size(), "nothing left to send");
        } finally {
            platform.close(0);
            server.stop(0);
        }
    }
}
