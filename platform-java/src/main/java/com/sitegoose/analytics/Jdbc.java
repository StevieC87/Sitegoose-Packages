package com.sitegoose.analytics;

import java.io.Closeable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.function.Supplier;
import javax.sql.DataSource;

/**
 * Plain JDBC's queries, timed through its public interfaces: a DataSource
 * whose connections hand out statements that time execute, executeQuery,
 * executeUpdate and executeBatch. The statement's text is the one given to
 * prepareStatement/prepareCall, or to execute itself; bound parameters are
 * never read. Everything else goes straight to the driver's own objects, and
 * unwrap() still finds them (a pool's metrics, Hikari's MXBean).
 *
 * <p>Never counted twice: a wrapped DataSource over another wrapped one (a
 * routing or transaction-aware DataSource in front of a pool) times the query
 * at the outer statement only.
 */
final class Jdbc {
    private Jdbc() {
    }

    /** Set on this thread while a statement is being timed: an inner wrapped statement leaves it to the outer one. */
    private static final ThreadLocal<Boolean> TIMING = new ThreadLocal<>();

    static boolean isWrapped(Object dataSource) {
        return dataSource != null && Proxy.isProxyClass(dataSource.getClass())
                && Proxy.getInvocationHandler(dataSource) instanceof Source;
    }

    /** The data source with its queries timed; queries: where they go (resolved on each query, may be null). */
    static DataSource wrap(DataSource target, Supplier<Queries> queries) {
        if (target == null || isWrapped(target)) {
            return target;
        }
        // Closeable kept, so a framework that closes the pool at shutdown still finds close().
        Class<?>[] types = target instanceof Closeable ? new Class<?>[] {DataSource.class, Closeable.class}
                : target instanceof AutoCloseable ? new Class<?>[] {DataSource.class, AutoCloseable.class}
                : new Class<?>[] {DataSource.class};
        return (DataSource) Proxy.newProxyInstance(Jdbc.class.getClassLoader(), types, new Source(target, queries));
    }

    private static Object call(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }

    /** equals, hashCode and toString of the proxy itself; null when the method is another. */
    private static Object identity(Object proxy, Object target, Method method, Object[] args) {
        switch (method.getName()) {
            case "equals":
                return method.getParameterCount() == 1 ? Boolean.valueOf(proxy == args[0]) : null;
            case "hashCode":
                return method.getParameterCount() == 0 ? Integer.valueOf(System.identityHashCode(proxy)) : null;
            case "toString":
                return method.getParameterCount() == 0 ? "timed " + target : null;
            default:
                return null;
        }
    }

    /** unwrap(type) / isWrapperFor(type): the driver's own object answers, as if we weren't there. */
    private static Object wrapper(Object target, Method method, Object[] args) throws Throwable {
        if (args != null && args.length == 1 && args[0] instanceof Class) {
            Class<?> type = (Class<?>) args[0];
            if ("unwrap".equals(method.getName()) && type.isInstance(target)) {
                return target;
            }
            if ("isWrapperFor".equals(method.getName()) && type.isInstance(target)) {
                return Boolean.TRUE;
            }
        }
        return call(target, method, args);
    }

    private static final class Source implements InvocationHandler {
        final DataSource target;
        final Supplier<Queries> queries;
        /** The database, from the first connection's metadata. */
        volatile String db;

        Source(DataSource target, Supplier<Queries> queries) {
            this.target = target;
            this.queries = queries;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object own = identity(proxy, target, method, args);
            if (own != null) {
                return own;
            }
            String name = method.getName();
            if ("unwrap".equals(name) || "isWrapperFor".equals(name)) {
                return wrapper(target, method, args);
            }
            Object result = call(target, method, args);
            if ("getConnection".equals(name) && result instanceof Connection) {
                Connection connection = (Connection) result;
                if (db == null) {
                    db = databaseOf(connection);
                }
                return Proxy.newProxyInstance(Jdbc.class.getClassLoader(), new Class<?>[] {Connection.class}, new Conn(connection, this));
            }
            return result;
        }

        /** From the driver's product name ("PostgreSQL", "ClickHouse"...), else its URL (jdbc:clickhouse:, jdbc:ch:...). */
        static String databaseOf(Connection connection) {
            java.sql.DatabaseMetaData meta;
            try {
                meta = connection.getMetaData();
            } catch (Exception | LinkageError unknown) {
                return "other";
            }
            String db = "other";
            try {
                db = QueryText.databaseOfProduct(meta.getDatabaseProductName());
            } catch (Exception | LinkageError unknown) {
                // the URL may still say
            }
            if ("other".equals(db)) {
                try {
                    db = QueryText.databaseOfUrl(meta.getURL());
                } catch (Exception | LinkageError unknown) {
                    return "other";
                }
            }
            return db;
        }
    }

    private static final class Conn implements InvocationHandler {
        final Connection target;
        final Source source;

        Conn(Connection target, Source source) {
            this.target = target;
            this.source = source;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object own = identity(proxy, target, method, args);
            if (own != null) {
                return own;
            }
            String name = method.getName();
            if ("unwrap".equals(name) || "isWrapperFor".equals(name)) {
                return wrapper(target, method, args);
            }
            Object result = call(target, method, args);
            if (!(result instanceof Statement)) {
                return result;
            }
            Class<?> type = result instanceof CallableStatement && method.getReturnType() == CallableStatement.class ? CallableStatement.class
                    : result instanceof PreparedStatement && method.getReturnType() != Statement.class ? PreparedStatement.class
                    : Statement.class;
            String sql = ("prepareStatement".equals(name) || "prepareCall".equals(name)) && args != null && args.length > 0
                    && args[0] instanceof String ? (String) args[0] : null;
            return Proxy.newProxyInstance(Jdbc.class.getClassLoader(), new Class<?>[] {type}, new Stmt((Statement) result, sql, source, (Connection) proxy));
        }
    }

    private static final class Stmt implements InvocationHandler {
        final Statement target;
        final String prepared;
        final Source source;
        final Connection connection;
        /** A plain Statement's batch: the first statement added stands for it. */
        private volatile String batch;

        Stmt(Statement target, String prepared, Source source, Connection connection) {
            this.target = target;
            this.prepared = prepared;
            this.source = source;
            this.connection = connection;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object own = identity(proxy, target, method, args);
            if (own != null) {
                return own;
            }
            String name = method.getName();
            switch (name) {
                case "unwrap":
                case "isWrapperFor":
                    return wrapper(target, method, args);
                case "getConnection":
                    if (method.getParameterCount() == 0) {
                        Object real = call(target, method, args);
                        return real == null ? null : connection;
                    }
                    break;
                case "addBatch":
                    if (args != null && args.length == 1 && args[0] instanceof String && batch == null) {
                        batch = (String) args[0];
                    }
                    break;
                case "clearBatch":
                    batch = null;
                    break;
                default:
                    break;
            }
            if (!name.startsWith("execute")) {
                return call(target, method, args);
            }
            // The driver empties its batch when it runs it, so it starts again
            // here too, timed or not: the next batch is named by its own first statement.
            String ran = null;
            if (name.endsWith("Batch")) {
                ran = batch;
                batch = null;
            }
            if (TIMING.get() != null) {
                return call(target, method, args);
            }
            String text;
            if (args != null && args.length > 0 && args[0] instanceof String) {
                text = (String) args[0];
            } else if (name.endsWith("Batch") && prepared == null) {
                text = ran;
            } else {
                text = prepared;
            }
            Queries queries = text == null ? null : source.queries.get();
            if (queries == null || !queries.on()) {
                return call(target, method, args);
            }
            RequestContext context = RequestContext.current();
            TIMING.set(Boolean.TRUE);
            long started = System.nanoTime();
            boolean failed = false;
            try {
                return call(target, method, args);
            } catch (Throwable error) {
                failed = true;
                throw error;
            } finally {
                TIMING.remove();
                double ms = (System.nanoTime() - started) / 1e6;
                try {
                    queries.record(source.db, text, ms, failed, context);
                } catch (RuntimeException ignored) {
                    // timing never changes the query's outcome
                }
            }
        }
    }
}
