package com.sitegoose.analytics;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.List;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** A driver that runs nothing: it notes each statement executed, and fails the ones containing FAIL. */
public final class FakeJdbc {
    private FakeJdbc() {
    }

    static Object zero(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int[].class) {
            return new int[0];
        }
        if (type == long[].class) {
            return new long[0];
        }
        return null;
    }

    static Statement statement(Class<? extends Statement> type, String prepared, List<String> executed) {
        return (Statement) Proxy.newProxyInstance(FakeJdbc.class.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            if (method.getName().startsWith("execute")) {
                String sql = args != null && args.length > 0 && args[0] instanceof String ? (String) args[0] : prepared;
                executed.add(sql);
                if (sql != null && sql.contains("FAIL")) {
                    throw new SQLException("no such table");
                }
            }
            return zero(method.getReturnType());
        });
    }

    static Connection connection(String product, List<String> executed) {
        DatabaseMetaData meta = (DatabaseMetaData) Proxy.newProxyInstance(FakeJdbc.class.getClassLoader(), new Class<?>[] {DatabaseMetaData.class},
                (proxy, method, args) -> "getDatabaseProductName".equals(method.getName()) ? product : zero(method.getReturnType()));
        return (Connection) Proxy.newProxyInstance(FakeJdbc.class.getClassLoader(), new Class<?>[] {Connection.class}, (proxy, method, args) -> {
            switch (method.getName()) {
                case "getMetaData":
                    return meta;
                case "createStatement":
                    return statement(Statement.class, null, executed);
                case "prepareStatement":
                    return statement(PreparedStatement.class, (String) args[0], executed);
                case "prepareCall":
                    return statement(java.sql.CallableStatement.class, (String) args[0], executed);
                default:
                    return zero(method.getReturnType());
            }
        });
    }

    /** A plain class (not a proxy), as a pool is: the Spring starter keeps its type. */
    public static class Source implements DataSource {
        final String product;
        final List<String> executed;
        int connections;

        public Source(String product, List<String> executed) {
            this.product = product;
            this.executed = executed;
        }

        @Override
        public Connection getConnection() {
            connections++;
            return connection(product, executed);
        }

        @Override
        public Connection getConnection(String user, String password) {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public <T> T unwrap(Class<T> type) throws SQLException {
            if (type.isInstance(this)) {
                return type.cast(this);
            }
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return type.isInstance(this);
        }
    }
}
