using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// Configuration options for Auth0 custom domains token validation.
/// </summary>
public class Auth0CustomDomainsOptions
{
    /// <summary>
    /// List of Auth0 domains for multi-tenant scenarios.
    /// Each domain should be in the format: tenant.auth0.com (without <c>https://</c>).
    /// </summary>
    /// <remarks>
    /// Use this for scenarios where a fixed set of issuers is known at configuration time.
    /// Mutually exclusive with <see cref="DomainsResolver"/>.
    /// </remarks>
    public IReadOnlyList<string>? Domains { get; set; }

    /// <summary>
    /// Delegate for dynamically resolving allowed domains at runtime.
    /// </summary>
    /// <remarks>
    /// Use this for fully multi-tenant APIs where domains are determined dynamically
    /// based on request context, database queries, or external APIs.
    /// Mutually exclusive with <see cref="Domains"/>.
    /// The delegate receives the full <see cref="HttpContext"/>.
    /// </remarks>
    public Func<HttpContext, CancellationToken, Task<IReadOnlyList<string>>>? DomainsResolver { get; set; }

    /// <inheritdoc cref="BaseConfigurationManager.AutomaticRefreshInterval"/>
    /// <remarks>Defaults to <c>12</c> hours</remarks>
    public TimeSpan AutomaticRefreshInterval { get; set; } = TimeSpan.FromHours(12);

    /// <inheritdoc cref="BaseConfigurationManager.RefreshInterval"/>
    /// <remarks>Defaults to <c>5</c> minutes </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The cache implementation for ConfigurationManager instances. <br/>
    /// Defaults to <see cref="MemoryConfigurationManagerCache"/> with a max size of 100 entries.
    /// <br/>Set to <see cref="NullConfigurationManagerCache"/> to disable caching.
    /// </summary>
    public IConfigurationManagerCache? ConfigurationManagerCache { get; set; }

    /// <summary>
    /// Custom HTTP message handler for backchannel requests.
    /// </summary>
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }

    /// <summary>
    /// Timeout for backchannel HTTP requests (discovery and JWKS).
    /// <br/><b>Default</b>: <c>60</c> seconds
    /// </summary>
    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);
}
