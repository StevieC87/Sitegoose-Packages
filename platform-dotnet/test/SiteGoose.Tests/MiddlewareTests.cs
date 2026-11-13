using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Xunit;

namespace SiteGoose.Tests;

public class MiddlewareTests
{
    private static Platform Make(FakeCollector collector, string rules)
    {
        var platform = new Platform(Shared.Options(collector));
        platform.FirewallModule!.RulesNow = Firewall.Compile(Shared.Parse(rules));
        return platform;
    }

    private static DefaultHttpContext Request(string ip, string method = "GET", string path = "/", string accept = "*/*")
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Headers.Accept = accept;
        context.Request.Headers.UserAgent = "Mozilla/5.0";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static Endpoint Route(string pattern) =>
        new RouteEndpoint(_ => Task.CompletedTask, RoutePatternFactory.Parse(pattern), 0, EndpointMetadataCollection.Empty, pattern);

    [Fact]
    public async Task ABlockedAddressGets403AndTheAppNeverRuns()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.5\"]}");
        var ran = false;
        var middleware = new PlatformMiddleware(_ => { ran = true; return Task.CompletedTask; }, platform);
        var context = Request("::ffff:203.0.113.5");
        await middleware.InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
        Assert.False(ran);
        await middleware.InvokeAsync(Request("198.51.100.1"));
        Assert.True(ran);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task ABlockedPageGets429WithItsWindowAndANote()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":100,\"window\":60},"
            + "\"limits\":{\"rules\":[{\"id\":\"login\",\"action\":\"block\",\"limit\":1,\"window\":300,\"path\":{\"exact\":[\"/login\"]}}]}}");
        var ran = 0;
        var middleware = new PlatformMiddleware(_ => { ran++; return Task.CompletedTask; }, platform);
        await middleware.InvokeAsync(Request("198.51.100.7", "POST", "/login"));
        var context = Request("198.51.100.7", "POST", "/login");
        await middleware.InvokeAsync(context);
        Assert.Equal(1, ran);
        Assert.Equal(429, context.Response.StatusCode);
        Assert.Equal("300", context.Response.Headers.RetryAfter.ToString());
        Assert.StartsWith("text/plain", context.Response.ContentType);
        context.Response.Body.Position = 0;
        Assert.Equal("Too many requests to this page. Please wait a little and try again.", new StreamReader(context.Response.Body).ReadToEnd());
        await platform.CloseAsync();
    }

    [Fact]
    public async Task APageGetsTheCheckAndPassesWithAPass()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"challenge\":{\"skip\":[\"/api/\"]}}");
        var middleware = new PlatformMiddleware(c => { c.Response.StatusCode = 200; return Task.CompletedTask; }, platform);
        var page = Request("203.0.113.7", accept: "text/html");
        await middleware.InvokeAsync(page);
        Assert.Equal(503, page.Response.StatusCode);
        Assert.Contains("nonce-", page.Response.Headers.ContentSecurityPolicy.ToString());
        var pass = Request("203.0.113.7", accept: "text/html");
        pass.Request.Headers.Cookie = "a=b; __sg_pass=" + Challenge.MakePass(platform.FirewallModule!.PassKey, "203.0.113.7");
        await middleware.InvokeAsync(pass);
        Assert.Equal(200, pass.Response.StatusCode);
        var post = Request("203.0.113.7", "POST", "/form", "text/html");
        await middleware.InvokeAsync(post);
        Assert.Equal(200, post.Response.StatusCode);
        var json = Request("203.0.113.7", "GET", "/data", "application/json");
        await middleware.InvokeAsync(json);
        Assert.Equal(200, json.Response.StatusCode);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AnExceptionIsSentWithItsRouteAndTimed()
    {
        var collector = new FakeCollector();
        var platform = Make(collector, "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        var middleware = new PlatformMiddleware(c =>
        {
            c.SetEndpoint(Route("/orders/{id:int}"));
            throw new InvalidOperationException("no stock");
        }, platform);
        var context = Request("198.51.100.1", path: "/orders/5");
        await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));
        var evt = Assert.Single(platform.ErrorsModule!.Queued());
        Assert.Equal("no stock", evt["message"]);
        Assert.Equal("/orders/{id:int}", evt["route"]);
        Assert.Equal("/orders/5", evt["path"]);
        Assert.Equal(500, Convert.ToInt32(evt["status_code"]));
        var row = Assert.Single(platform.PerformanceModule!.Take(true));
        Assert.Equal("/orders/{id:int}", row["route"]);
        Assert.Equal(500, row["status"]);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AnExceptionTheExceptionHandlerTurnedIntoAPageIsSent()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        var error = new InvalidOperationException("handled by the error page");
        var middleware = new PlatformMiddleware(c =>
        {
            c.Features.Set<IExceptionHandlerFeature>(new ExceptionHandlerFeature
            {
                Error = error,
                Path = "/boom",
#if NET7_0_OR_GREATER
                Endpoint = Route("/boom"),
#endif
            });
            c.Response.StatusCode = 500;
            return Task.CompletedTask;
        }, platform);
        await middleware.InvokeAsync(Request("198.51.100.1", path: "/boom"));
        var evt = Assert.Single(platform.ErrorsModule!.Queued());
        Assert.Equal("handled by the error page", evt["message"]);
        // .NET 6 doesn't keep the endpoint the request first matched: the path's route then.
        Assert.Equal("/boom", evt["route"]);
        await platform.CloseAsync();
    }

    [Fact]
    public void ConventionalRoutesNameTheController()
    {
        var context = new DefaultHttpContext();
        context.SetEndpoint(Route("{controller=Home}/{action=Index}/{id?}"));
        context.Request.RouteValues["controller"] = "Orders";
        context.Request.RouteValues["action"] = "List";
        Assert.Equal("/Orders/List/{id?}", PlatformMiddleware.RouteOf(context));
        Assert.Equal("", PlatformMiddleware.RouteOf(new DefaultHttpContext()));
    }

    [Fact]
    public async Task SecurityHeadersAndTheRawTarget()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"requests\":{\"rules\":[{\"id\":\"trav\",\"action\":\"block\",\"path\":{\"contains\":[\"../\"]}}]}}");
        var middleware = new PlatformMiddleware(_ => Task.CompletedTask, platform);
        var context = Request("198.51.100.1", path: "/a/b");
        context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget = "/a/..%2f..%2fetc";
        Assert.Equal("/a/..%2f..%2fetc", PlatformMiddleware.Target(context));
        await middleware.InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
        await platform.CloseAsync();
    }
}
