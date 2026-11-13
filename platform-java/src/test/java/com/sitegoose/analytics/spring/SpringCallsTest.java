package com.sitegoose.analytics.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sitegoose.analytics.Platform;
import com.sitegoose.analytics.PlatformOptions;
import com.sitegoose.analytics.Rows;
import java.io.IOException;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;

/** The starter's call hooks (calls.md): RestTemplate/RestClient's interceptor and WebClient's filter, through their public APIs. */
class SpringCallsTest {
    static org.springframework.http.HttpRequest request(HttpMethod method, String url) {
        return new org.springframework.http.HttpRequest() {
            @Override
            public HttpMethod getMethod() {
                return method;
            }

            @Override
            public URI getURI() {
                return URI.create(url);
            }

            @Override
            public org.springframework.http.HttpHeaders getHeaders() {
                return new org.springframework.http.HttpHeaders();
            }
        };
    }

    static org.springframework.http.client.ClientHttpResponse answer(HttpStatus status) {
        return new org.springframework.http.client.ClientHttpResponse() {
            @Override
            public org.springframework.http.HttpStatusCode getStatusCode() {
                return status;
            }

            @Override
            public String getStatusText() {
                return status.getReasonPhrase();
            }

            @Override
            public void close() {
            }

            @Override
            public java.io.InputStream getBody() {
                return new java.io.ByteArrayInputStream(new byte[0]);
            }

            @Override
            public org.springframework.http.HttpHeaders getHeaders() {
                return new org.springframework.http.HttpHeaders();
            }
        };
    }

    static Platform platform() {
        return Platform.create(new PlatformOptions().allOff().performance(true).shutdownHook(false));
    }

    @Test
    void restTemplateCallsAreTimed() throws Exception {
        Platform platform = platform();
        PlatformSpringSupport.Breadcrumbs interceptor = new PlatformSpringSupport.Breadcrumbs(platform);
        org.springframework.http.HttpRequest request = request(HttpMethod.POST, "https://api.stripe.com/v1/charges?x=1");
        interceptor.intercept(request, new byte[0], (r, body) -> answer(HttpStatus.BAD_GATEWAY));
        assertThrows(IOException.class, () -> interceptor.intercept(request, new byte[0], (r, body) -> {
            throw new IOException("refused");
        }));
        interceptor.intercept(request, new byte[0], (r, body) -> answer(HttpStatus.NOT_FOUND));
        assertEquals("POST api.stripe.com count=3 errors=2", Rows.summary(platform));
        platform.close();
    }

    @Test
    void aCallUnderTwoHooksCountsOnce() throws Exception {
        Platform platform = platform();
        PlatformSpringSupport.Breadcrumbs outer = new PlatformSpringSupport.Breadcrumbs(platform);
        PlatformSpringSupport.Breadcrumbs inner = new PlatformSpringSupport.Breadcrumbs(platform);
        org.springframework.http.HttpRequest request = request(HttpMethod.GET, "https://api.example.com/v1");
        // A RestTemplate on OkHttp with the interceptor too: the inner hook leaves it to the outer.
        outer.intercept(request, new byte[0], (r, body) -> inner.intercept(r, body, (r2, b2) -> answer(HttpStatus.OK)));
        assertThrows(IOException.class, () -> outer.intercept(request, new byte[0], (r, body) -> inner.intercept(r, body, (r2, b2) -> {
            throw new IOException("reset");
        })));
        // The flag is gone afterwards: the next call is timed.
        inner.intercept(request, new byte[0], (r, body) -> answer(HttpStatus.OK));
        assertEquals("GET api.example.com count=3 errors=1", Rows.summary(platform));
        platform.close();
    }

    @Test
    void webClientCallsAreTimedUntilTheirResponse() {
        Platform platform = platform();
        PlatformSpringSupport.WebClientCalls filter = new PlatformSpringSupport.WebClientCalls(platform);
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("http://localhost:8080/v1/users/7")).build();
        filter.filter(request, r -> Mono.just(ClientResponse.create(HttpStatus.OK).build())).block();
        filter.filter(request, r -> Mono.just(ClientResponse.create(HttpStatus.SERVICE_UNAVAILABLE).build())).block();
        assertThrows(RuntimeException.class, () -> filter.filter(request, r -> Mono.error(new IllegalStateException("reset"))).block());
        // Cancelled by the app: not counted.
        filter.filter(request, r -> Mono.never()).subscribe().dispose();
        assertEquals("GET localhost:8080 count=3 errors=2", Rows.summary(platform));
        platform.close();
    }
}
