using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Auth0.AspNetCore.Authentication.Api.IntegrationTests;

/// <summary>
/// Test server factory for integration tests using TestServer.
/// </summary>
public class TestWebApplicationFactory : IAsyncDisposable
{
    private readonly Auth0Scenario _scenario;
    private readonly IHost _host;
    private readonly string[]? _customDomains;
    private readonly string[]? _validAudiences;

    public TestWebApplicationFactory(Auth0Scenario scenario)
    {
        _scenario = scenario;
        _customDomains = null;
        _host = CreateHost();
    }

    /// <summary>
    /// Initializes a new instance for custom domains testing.
    /// </summary>
    /// <param name="scenario">Primary scenario for audience configuration.</param>
    /// <param name="customDomains">Array of allowed custom domains.</param>
    /// <param name="validAudiences">Optional array of valid audiences. When specified, tokens with any of these audiences will be accepted.</param>
    public TestWebApplicationFactory(Auth0Scenario scenario, string[] customDomains, string[]? validAudiences = null)
    {
        _scenario = scenario;
        _customDomains = customDomains ?? throw new ArgumentNullException(nameof(customDomains));
        _validAudiences = validAudiences;
        _host = CreateHost();
    }

    private IHost CreateHost()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();

                webBuilder.ConfigureAppConfiguration(config =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Auth0:Domain"] = _scenario.Domain,
                        ["Auth0:Audience"] = _scenario.Audience
                    });
                });

                webBuilder.ConfigureServices((context, services) =>
                {
                    // Register HttpClient services (required by custom domains)
                    services.AddHttpClient();

                    // Add Auth0 JWT validation
                    var authBuilder = services.AddAuth0ApiAuthentication(options =>
                    {
                        options.Domain = context.Configuration["Auth0:Domain"]
                                       ?? throw new InvalidOperationException("Auth0:Domain is required");
                        options.JwtBearerOptions = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions
                        {
                            Audience = context.Configuration["Auth0:Audience"]
                                     ?? throw new InvalidOperationException("Auth0:Audience is required")
                        };

                        // Support multiple audiences for custom domains testing
                        if (_validAudiences != null && _validAudiences.Length > 0)
                        {
                            options.JwtBearerOptions.TokenValidationParameters.ValidAudiences = _validAudiences;
                        }

                        // Handle authentication failures gracefully for testing
                        options.JwtBearerOptions.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
                        {
                            OnAuthenticationFailed = context =>
                            {
                                // SecurityTokenException from custom domains validation should result in 401
                                // Don't rethrow - let the middleware handle it as authentication failure
                                return Task.CompletedTask;
                            }
                        };
                    });

                    // Configure custom domains if provided
                    if (_customDomains != null && _customDomains.Length > 0)
                    {
                        authBuilder.WithCustomDomains(customDomainsOptions =>
                        {
                            customDomainsOptions.Domains = _customDomains;

                            // Use smaller cache for testing
                            customDomainsOptions.ConfigurationManagerCache =
                                new CustomDomains.MemoryConfigurationManagerCache(
                                    maxSize: 10,
                                    slidingExpiration: TimeSpan.FromMinutes(5));
                        });
                    }

                    // Configure DPoP based on scenario
                    if (_scenario.IsDPoPEnabled)
                    {
                        authBuilder.WithDPoP(dpopOptions =>
                        {
                            dpopOptions.Mode = _scenario.IsDPoPRequired
                                ? DPoP.DPoPModes.Required
                                : DPoP.DPoPModes.Allowed;
                        });
                    }

                    services.AddAuthorization();
                    services.AddRouting();
                });

                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();

                    app.UseEndpoints(endpoints =>
                    {
                        // Open endpoint - no authentication required
                        endpoints.MapGet("/api/public", () => new { message = "This is a public endpoint" })
                           .WithName("PublicEndpoint");

                        // Protected endpoint - authentication required
                        endpoints.MapGet("/api/protected", () => new { message = "This is a protected endpoint" })
                           .WithName("ProtectedEndpoint")
                           .RequireAuthorization();
                    });
                });
            })
            .Build();

        host.Start();
        return host;
    }

    /// <summary>
    /// Creates a new HttpClient instance for a test.
    /// Each client is isolated with its own headers.
    /// </summary>
    public HttpClient CreateClient()
    {
        return _host.GetTestServer().CreateClient();
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }
}
