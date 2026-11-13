using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Xunit;

namespace SiteGoose.Tests;

/// <summary>A static-looking request counted after the response
/// (firewall.md, `rate`): compared with the counts first, so an address
/// already over is refused its files, then counted toward the rate and the
/// page limits it skipped when routing matched an endpoint that isn't a
/// file's ("Home/Search/{q}" took "/Home/Search/x.css") or it answered 400
/// or more.</summary>
public class StaticLateTests
{
    private const string Rules = "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"limits\":{\"rules\":[{\"id\":\"search\",\"action\":\"block\",\"limit\":2,\"window\":60,\"path\":{\"prefix\":[\"/search\",\"/Home/Search\"]}}]}}";

    /// <summary>DefaultHttpContext's own response feature drops OnCompleted:
    /// this one keeps the callbacks, run once the "response is sent".</summary>
    private sealed class Completing : HttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> done = new();

        public override void OnCompleted(Func<object, Task> callback, object state) => done.Add((callback, state));

        public async Task Complete()
        {
            foreach (var (callback, state) in done) await callback(state);
        }
    }

    private static Platform Make(string rules = Rules)
    {
        var platform = new Platform(Shared.Options(new FakeCollector()));
        platform.FirewallModule!.RulesNow = Firewall.Compile(Shared.Parse(rules));
        return platform;
    }

    /// <summary>One request through the middleware: the app sets the
    /// endpoint routing matched (pattern, null for none), the status and the
    /// Content-Type. -> the status answered.</summary>
    private static async Task<int> Ask(Platform platform, string path, string? pattern, int status = 200, string? type = "text/html; charset=utf-8")
    {
        var context = new DefaultHttpContext();
        var response = new Completing();
        context.Features.Set<IHttpResponseFeature>(response);
        context.Features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(new MemoryStream()));
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        context.Request.Method = "GET";
        context.Request.Path = path;
        var middleware = new PlatformMiddleware(c =>
        {
            if (pattern != null) c.SetEndpoint(new RouteEndpoint(_ => Task.CompletedTask, RoutePatternFactory.Parse(pattern), 0, EndpointMetadataCollection.Empty, pattern));
            c.Response.StatusCode = status;
            if (type != null) c.Response.ContentType = type;
            return Task.CompletedTask;
        }, platform);
        await middleware.InvokeAsync(context);
        await response.Complete();
        return context.Response.StatusCode;
    }

    [Fact]
    public async Task ARoutedStaticLookingRequestCountsTowardThePageLimit()
    {
        var platform = Make();
        // MVC's default route takes /Home/Search/x.css as Search with id "x.css".
        Assert.Equal(200, await Ask(platform, "/Home/Search/x.css", "{controller=Home}/{action=Index}/{id?}"));
        Assert.Equal(200, await Ask(platform, "/search/y.css", "/search/{q}"));
        Assert.Equal(200, await Ask(platform, "/search/z.css", "/search/{q}"));
        Assert.Equal(429, await Ask(platform, "/search/w.css", "/search/{q}"));
        await platform.CloseAsync();
    }

    [Fact]
    public async Task StaticFilesAndFileEndpointsAreNotCounted()
    {
        var platform = Make();
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(200, await Ask(platform, "/search/app.css", null, type: "text/css")); // UseStaticFiles: no endpoint
            Assert.Equal(200, await Ask(platform, "/search/a.png", "/search/{id}.png", type: null));
            Assert.Equal(200, await Ask(platform, "/search/b.css", "/search/{**file}", type: "text/css"));
            Assert.Equal(304, await Ask(platform, "/search/c.css", "/search/{**file}", 304, null));
        }
        var wall = platform.FirewallModule!;
        Assert.Equal("", wall.Check("198.51.100.7", "GET", "/search").Rule);
        Assert.Equal("", wall.Check("198.51.100.7", "GET", "/search").Rule);
        Assert.Equal("limit:search", wall.Check("198.51.100.7", "GET", "/search").Rule);
        Assert.Equal(429, await Ask(platform, "/search/app.css", null, type: "text/css")); // over: refused its files too
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AnErrorCountsTowardTheRateWithNoEndpoint()
    {
        var platform = Make("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60}}");
        Assert.Equal(404, await Ask(platform, "/made-up.css", null, 404));
        Assert.Equal(404, await Ask(platform, "/made-up.js", null, 404));
        Assert.Equal(404, await Ask(platform, "/made-up.png", null, 404));
        Assert.Equal(429, await Ask(platform, "/made-up.svg", null, 404));
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AVisitorLeavingWhileItsFilesLoadIsNotAnError()
    {
        var platform = Make("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60}}");
        for (var i = 0; i < 5; i++)
        {
            var context = new DefaultHttpContext();
            var response = new Completing();
            context.Features.Set<IHttpResponseFeature>(response);
            context.Features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(new MemoryStream()));
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
            context.Request.Method = "GET";
            context.Request.Path = "/app" + i + ".css";
            using var gone = new System.Threading.CancellationTokenSource();
            gone.Cancel();
            context.RequestAborted = gone.Token;
            var middleware = new PlatformMiddleware(c => throw new OperationCanceledException(c.RequestAborted), platform);
            await Assert.ThrowsAsync<OperationCanceledException>(() => middleware.InvokeAsync(context));
            await response.Complete();
        }
        Assert.Equal("", platform.FirewallModule!.Check("198.51.100.7", "GET", "/app.css").Rule);
        await platform.CloseAsync();
    }

    [Fact]
    public void ASharedCountSeenOverRefusesTheFilesWithoutAdding()
    {
        var shared = new Dictionary<string, long>();
        var wall = new Firewall(Shared.Core(), counter: (key, ttl) => shared[key] = (shared.TryGetValue(key, out var n) ? n : 0) + 1);
        wall.RulesNow = Firewall.Compile(Shared.Parse(Rules));
        Assert.Equal("", wall.Check("198.51.100.7", "GET", "/search/app.css").Rule);
        Assert.Empty(shared);
        wall.Check("198.51.100.7", "GET", "/search");
        wall.Check("198.51.100.7", "GET", "/search");
        Assert.Equal("limit:search", wall.Check("198.51.100.7", "GET", "/search").Rule);
        Assert.Equal("limit:search", wall.Check("198.51.100.7", "GET", "/search/app.css").Rule);
        Assert.Single(shared);
        Assert.Equal(3, Assert.Single(shared.Values));
    }

    [Theory]
    [InlineData("/search/{q}", "text/html", true)]
    [InlineData("{controller=Home}/{action=Index}/{id?}", null, true)]
    [InlineData("Search", "text/html", true)]
    [InlineData(null, "text/html", false)]
    [InlineData("/avatars/{id}.png", "text/html", false)]
    [InlineData("static/{**path}", null, false)]
    [InlineData("/files/{name}", "application/pdf", false)]
    [InlineData("/files/{name}", "font/woff2", false)]
    public void RoutedToPage(string? pattern, string? type, bool routed) => Assert.Equal(routed, Firewall.RoutedToPage(pattern, type));
}
