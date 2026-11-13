package com.sitegoose.analytics;

import java.io.IOException;
import java.io.InterruptedIOException;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/**
 * OkHttp's calls (sdk/protocols/calls.md) through its public interceptor
 * API, for {@code new OkHttpClient.Builder().addInterceptor(platform.okHttpInterceptor())}.
 * As an application interceptor it sees one call however many redirects
 * and retries it took. chain.proceed() returns once the response's headers
 * are in, before its body is read: that is the time counted. A call the app
 * cancelled isn't counted. Loaded only when asked for, so the package needs
 * no OkHttp of its own.
 */
final class OkHttpCalls implements Interceptor {
    private final Platform platform;

    OkHttpCalls(Platform platform) {
        this.platform = platform;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        // Under a RestTemplate or RestClient that times it already: counted there.
        if (!Calls.begin()) {
            return chain.proceed(request);
        }
        try {
            RequestContext context = RequestContext.current();
            long started = System.nanoTime();
            Response response;
            try {
                response = chain.proceed(request);
            } catch (IOException | RuntimeException error) {
                if (!cancelled(chain, error)) {
                    record(request, started, 0, context);
                }
                throw error;
            }
            record(request, started, response.code(), context);
            return response;
        } finally {
            Calls.end();
        }
    }

    /**
     * Cancelled by the app. OkHttp's own callTimeout cancels the call too,
     * but ends it with an InterruptedIOException ("timeout"): that one timed
     * out, and counts as failed.
     */
    private static boolean cancelled(Chain chain, Throwable error) {
        if (error instanceof InterruptedIOException) {
            return false;
        }
        try {
            return chain.call().isCanceled();
        } catch (RuntimeException | LinkageError unknown) {
            return false;
        }
    }

    private void record(Request request, long started, int status, RequestContext context) {
        try {
            platform.recordCall(request.method(), request.url().toString(), started, status, context);
        } catch (RuntimeException | LinkageError ignored) {
            // never in the way of the call
        }
    }
}
