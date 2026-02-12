using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// A custom implementation of <see cref="IConfigurationManager{T}"/> that maintains
/// separate OpenID Connect configurations per Auth0 custom domain.
/// Resolves the issuer on-demand from the current HTTP request context.
/// </summary>
internal sealed class Auth0CustomDomainsConfigurationManager(
    IHttpContextAccessor httpContextAccessor,
    Auth0CustomDomainsOptions options,
    IConfigurationManagerCache cache,
    IHttpClientFactory? httpClientFactory,
    ILogger<Auth0CustomDomainsConfigurationManager> logger)
    :
        IConfigurationManager<OpenIdConnectConfiguration>,
        IDisposable
{
    private readonly IReadOnlyList<string>? _staticDomains = options.Domains;
    private readonly Func<HttpContext, CancellationToken, Task<IReadOnlyList<string>>>? _domainsResolver = options.DomainsResolver;
    private bool _disposed;

    /// <summary>
    /// Gets the configuration for the issuer resolved from the current HTTP request.
    /// </summary>
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        HttpContext httpContext = httpContextAccessor.HttpContext
                                  ?? throw new InvalidOperationException("No HTTP context available.");

        // Resolve and validate the issuer from the current request
        var issuer = await ResolveAndValidateIssuerAsync(httpContext, cancel);

        // Get or create ConfigurationManager from cache
        var metadataAddress = $"{issuer}/.well-known/openid-configuration";
        IConfigurationManager<OpenIdConnectConfiguration> manager = cache.GetOrCreate(metadataAddress, _ => CreateConfigurationManager(metadataAddress));

        // Fetch configuration (Microsoft handles discovery + JWKS + caching)
        return await manager.GetConfigurationAsync(cancel);
    }

    /// <summary>
    /// Requests that all cached configurations be refreshed on their next access.
    /// </summary>
    /// <remarks>
    /// Clears the cache, forcing new configuration managers to be created on subsequent requests.
    /// </remarks>
    public void RequestRefresh()
    {
        cache.Clear();
    }

    /// <summary>
    /// Resolves allowed domains and validates the token's issuer against them.
    /// All validation happens BEFORE any network calls.
    /// </summary>
    private async Task<string> ResolveAndValidateIssuerAsync(HttpContext httpContext, CancellationToken cancel)
    {
        // Extract token from Authorization header
        var token = TokenValidationHelper.ExtractToken(httpContext);
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new SecurityTokenException("No token found in request.");
        }

        // Decode JWT without verification to get issuer
        if (!TokenValidationHelper.TryDecodeToken(token, out var tokenIssuer, out var algorithm))
        {
            throw new SecurityTokenException("Invalid token format.");
        }

        // Reject symmetric algorithms before any network calls
        if (TokenValidationHelper.IsSymmetricAlgorithm(algorithm))
        {
            logger.LogWarning("Rejected token with symmetric algorithm: {Algorithm}", algorithm);
            throw new SecurityTokenException("Symmetric algorithms are not supported.");
        }

        // Resolve allowed domains
        IReadOnlyList<string>? allowedDomains = await ResolveAllowedDomainsAsync(httpContext, cancel);
        if (allowedDomains == null || allowedDomains.Count == 0)
        {
            throw new SecurityTokenException("No allowed domains configured or resolved.");
        }

        // Pre-validate issuer against allowed domains
        var validatedIssuer = TokenValidationHelper.ValidateIssuer(tokenIssuer, allowedDomains);
        if (validatedIssuer == null)
        {
            logger.LogWarning("Token issuer not in allowed list. Issuer: {Issuer}", tokenIssuer);
            throw new SecurityTokenException("Token issuer is not allowed.");
        }

        return validatedIssuer;
    }

    private async Task<IReadOnlyList<string>?> ResolveAllowedDomainsAsync(
        HttpContext httpContext, CancellationToken cancel)
    {
        // Static domains list
        if (_staticDomains?.Count > 0)
        {
            return _staticDomains;
        }

        // Dynamic resolver with full HttpContext
        if (_domainsResolver != null)
        {
            return await _domainsResolver(httpContext, cancel);
        }

        return null;
    }

    /// <summary>
    /// Creates a <see cref="Microsoft.IdentityModel.Protocols.ConfigurationManager{T}"/> for the specified metadata address.
    /// </summary>
    internal IConfigurationManager<OpenIdConnectConfiguration> CreateConfigurationManager(string metadataAddress)
    {
        HttpClient? httpClientToDispose = null;
        HttpClient httpClient;

        if (httpClientFactory != null)
        {
            // Factory-created clients are managed by the factory (pooling, handler rotation)
            httpClient = httpClientFactory.CreateClient("Auth0CustomDomains");
        }
        else
        {
            // We create it, we own it, we must dispose it
            httpClient = CreateDefaultHttpClient();
            httpClientToDispose = httpClient;
        }

        var docRetriever = new HttpDocumentRetriever(httpClient)
        {
            RequireHttps = true
        };

        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            docRetriever)
        {
            AutomaticRefreshInterval = options.AutomaticRefreshInterval,
            RefreshInterval = options.RefreshInterval
        };

        logger.LogDebug("Created configuration manager for: {MetadataAddress}", metadataAddress);

        // Wrap in disposable wrapper that tracks HttpClient ownership
        // The wrapper will dispose httpClientToDispose (if not null) when disposed
        return new DisposableConfigurationManagerWrapper(manager, httpClientToDispose);
    }

    private HttpClient CreateDefaultHttpClient()
    {
        HttpMessageHandler handler = options.BackchannelHttpHandler ?? new HttpClientHandler();
        var client = new HttpClient(handler)
        {
            Timeout = options.BackchannelTimeout
        };
        client.DefaultRequestHeaders.Add("Auth0-Client", Utils.CreateAgentString());
        return client;
    }

    /// <summary>
    /// Releases all resources used by this instance.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        cache.Dispose();
    }
}
