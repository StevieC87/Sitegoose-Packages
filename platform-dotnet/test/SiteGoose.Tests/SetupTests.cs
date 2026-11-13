using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace SiteGoose.Tests;

// The one-line setup: AddSiteGoose() puts the middleware first by itself,
// UseSiteGoose() is then optional and adds nothing, and the keys can come
// from the ANALYTICS_* variables every other package reads. Run on a real
// Kestrel host, on a free port.
public class SetupTests
{
    [Fact]
    public void EmptyOptionsAreFilledFromTheAnalyticsVariablesAndSetOnesAreKept()
    {
        var env = new Dictionary<string, string>
        {
            ["ANALYTICS_SITE_ID"] = " bbbbbbbbbbbbbbbbbbbbbbbb ",
            ["ANALYTICS_SITE_SECRET"] = "from-env",
            ["ANALYTICS_FIREWALL_ENDPOINT"] = "http://firewall-name.test",
            ["ANALYTICS_TRUST_PROXY"] = "cloudflare",
            ["ANALYTICS_SERVER_NAME"] = "   ",
        };
        var options = new PlatformOptions { Secret = "from-config", ServerName = "web-1" };
        options.FillFromEnvironment(name => env.TryGetValue(name, out var value) ? value : null);
        Assert.Equal("bbbbbbbbbbbbbbbbbbbbbbbb", options.SiteId);
        Assert.Equal("from-config", options.Secret);
        Assert.Equal("http://firewall-name.test", options.Endpoint);
        Assert.Equal("cloudflare", options.TrustProxy);
        Assert.Equal("web-1", options.ServerName);

        env["ANALYTICS_ENDPOINT"] = "http://endpoint-name.test";
        var second = new PlatformOptions();
        second.FillFromEnvironment(name => env.TryGetValue(name, out var value) ? value : null);
        Assert.Equal("http://endpoint-name.test", second.Endpoint);
        Assert.Null(second.ServerName);
    }

    private static async Task<(WebApplication App, HttpClient Client, Platform Platform)> Start(Action<WebApplicationBuilder, FakeCollector> services, Action<WebApplication> pipeline)
    {
        var collector = new FakeCollector();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        services(builder, collector);
        var app = builder.Build();
        pipeline(app);
        // Was the platform's middleware in front of the app's own?
        app.Use(async (context, next) =>
        {
            context.Response.Headers["x-platform-first"] = context.Items.ContainsKey(Watchers.ItemOurs) ? "yes" : "no";
            await next();
        });
        app.MapGet("/orders/{id}", () => "ok");
        await app.StartAsync();
        var client = new HttpClient { BaseAddress = new Uri(app.Urls.First()) };
        return (app, client, app.Services.GetRequiredService<Platform>());
    }

    private static void AddWithCollector(WebApplicationBuilder builder, FakeCollector collector) =>
        builder.Services.AddSiteGoose(o =>
        {
            var given = Shared.Options(collector);
            o.SiteId = given.SiteId;
            o.Secret = given.Secret;
            o.Endpoint = given.Endpoint;
            o.Handler = collector;
            o.Errors.CaptureUncaught = false;
            o.Errors.SpoolDir = "false";
            o.Inventory.Enabled = false;
            o.Posture.Enabled = false;
            o.Resources.Enabled = false;
        });

    private static async Task<int> CountedRequests(Platform platform)
    {
        var collector = (FakeCollector)platform.Options.Handler!;
        await platform.PerformanceModule!.FlushAsync(true);
        return collector.Requests
            .Where(r => r.Url.EndsWith("/events/server-requests"))
            .SelectMany(r => r.Json.GetProperty("rows").EnumerateArray())
            .Where(row => row.GetProperty("route").GetString() == "/orders/{id}")
            .Sum(row => row.GetProperty("count").GetInt32());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AddSiteGooseAloneRunsTheMiddlewareFirstAndAnExplicitUseAddsNothing(bool explicitUse)
    {
        var (app, client, platform) = await Start(AddWithCollector, a =>
        {
            if (explicitUse) a.UseSiteGoose();
        });
        try
        {
            for (var i = 0; i < 2; i++)
            {
                var res = await client.GetAsync($"/orders/{i}");
                Assert.Equal("ok", await res.Content.ReadAsStringAsync());
                Assert.Equal("yes", res.Headers.GetValues("x-platform-first").Single());
            }
            Assert.Equal(2, await CountedRequests(platform));
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task WithTrustProxyAspNetCoreItRunsWhereUseSiteGooseIsAfterForwardedHeaders()
    {
        var (app, client, _) = await Start(
            (builder, collector) =>
            {
                AddWithCollector(builder, collector);
                builder.Services.Configure<PlatformOptions>(o => o.TrustProxy = "aspnetcore");
            },
            a =>
            {
                // A stand-in for UseForwardedHeaders(): what it settles on.
                a.Use(async (context, next) =>
                {
                    context.Response.Headers["x-platform-before-forwarded"] = context.Items.ContainsKey(Watchers.ItemOurs) ? "yes" : "no";
                    context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
                    await next();
                });
                a.UseSiteGoose();
                a.Use(async (context, next) =>
                {
                    context.Response.Headers["x-seen-address"] = context.RequestServices.GetRequiredService<Platform>().RemoteOf(context);
                    await next();
                });
            });
        try
        {
            var res = await client.GetAsync("/orders/1");
            Assert.Equal("yes", res.Headers.GetValues("x-platform-first").Single());
            Assert.Equal("no", res.Headers.GetValues("x-platform-before-forwarded").Single());
            Assert.Equal("203.0.113.7", res.Headers.GetValues("x-seen-address").Single());
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task WithoutAddSiteGooseUseSiteGooseStillAddsIt()
    {
        var (app, client, _) = await Start(
            (builder, collector) => builder.Services.AddSingleton(new Platform(Shared.Options(collector))),
            a => a.UseSiteGoose());
        try
        {
            // A Platform registered by hand isn't started (no hosted service),
            // so only that the middleware ran in front is checked here.
            var res = await client.GetAsync("/orders/7");
            Assert.Equal("ok", await res.Content.ReadAsStringAsync());
            Assert.Equal("yes", res.Headers.GetValues("x-platform-first").Single());
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }
}
