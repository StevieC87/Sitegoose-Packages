package com.sitegoose.analytics.jakarta;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;

/**
 * The response as the app writes it: the dashboard's security headers (and
 * a maintenance preview cookie) go on just before the first byte is
 * written, so a header the app or another filter sets itself wins; and the
 * bytes are counted for the crawler report.
 *
 * <p>The javax copy (com.sitegoose.analytics.javax) is generated from this
 * file at build time.
 */
final class TrackedResponse extends HttpServletResponseWrapper {
    private final Runnable beforeCommit;
    private boolean committed;
    private long bytes;
    private long length = -1;
    private ServletOutputStream stream;
    private PrintWriter writer;

    TrackedResponse(HttpServletResponse response, Runnable beforeCommit) {
        super(response);
        this.beforeCommit = beforeCommit;
    }

    /** Adds what goes on before commit, once (also called when the request ends). */
    void commit() {
        if (committed) {
            return;
        }
        committed = true;
        if (!isCommitted()) {
            try {
                beforeCommit.run();
            } catch (RuntimeException ignored) {
                // fail open: the response goes out as the app made it
            }
        }
    }

    long bytes() {
        return length >= 0 ? length : bytes;
    }

    @Override
    public void setContentLength(int len) {
        length = len;
        super.setContentLength(len);
    }

    @Override
    public void setContentLengthLong(long len) {
        length = len;
        super.setContentLengthLong(len);
    }

    @Override
    public void sendError(int sc) throws IOException {
        commit();
        super.sendError(sc);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        commit();
        super.sendError(sc, msg);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        commit();
        super.sendRedirect(location);
    }

    /**
     * Servlet 6.1's sendRedirect(location, status, clearBuffer): no
     * {@code @Override}, since it is compiled against Servlet 5; on 6.1 this
     * overrides it, and passes it on to the real response.
     */
    public void sendRedirect(String location, int sc, boolean clearBuffer) throws IOException {
        commit();
        try {
            getResponse().getClass().getMethod("sendRedirect", String.class, int.class, boolean.class)
                    .invoke(getResponse(), location, sc, clearBuffer);
        } catch (java.lang.reflect.InvocationTargetException thrown) {
            Throwable cause = thrown.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new IOException(cause);
        } catch (ReflectiveOperationException older) {
            super.sendRedirect(location);
        }
    }

    @Override
    public void flushBuffer() throws IOException {
        commit();
        super.flushBuffer();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (stream == null) {
            ServletOutputStream real = super.getOutputStream();
            stream = new ServletOutputStream() {
                @Override
                public boolean isReady() {
                    return real.isReady();
                }

                @Override
                public void setWriteListener(WriteListener listener) {
                    real.setWriteListener(listener);
                }

                @Override
                public void write(int b) throws IOException {
                    commit();
                    bytes += 1;
                    real.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    commit();
                    bytes += len;
                    real.write(b, off, len);
                }

                @Override
                public void flush() throws IOException {
                    commit();
                    real.flush();
                }

                @Override
                public void close() throws IOException {
                    commit();
                    real.close();
                }
            };
        }
        return stream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            PrintWriter real = super.getWriter();
            writer = new PrintWriter(new Writer() {
                @Override
                public void write(char[] buffer, int off, int len) {
                    commit();
                    // Characters, not bytes: close enough for a crawler's byte count.
                    bytes += len;
                    real.write(buffer, off, len);
                }

                @Override
                public void flush() {
                    commit();
                    real.flush();
                }

                @Override
                public void close() {
                    commit();
                    real.close();
                }
            }, false) {
                /**
                 * The real writer's errors too: a server-sent-events loop
                 * (while (!writer.checkError())) stops when the visitor leaves.
                 */
                @Override
                public boolean checkError() {
                    boolean mine = super.checkError();
                    return real.checkError() || mine;
                }
            };
        }
        return writer;
    }
}
