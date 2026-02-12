using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// Abstraction for caching OpenID Connect configuration managers.
/// </summary>
/// <remarks>
/// Implement this interface to provide custom caching behavior for configuration managers.
/// The SDK provides two built-in implementations:
/// <list type="bullet">
/// <item><description><see cref="MemoryConfigurationManagerCache"/> - Default in-memory cache using MemoryCache</description></item>
/// <item><description><see cref="NullConfigurationManagerCache"/> - Disables caching (No-Ops)</description></item>
/// </list>
/// </remarks>
public interface IConfigurationManagerCache : IDisposable
{
    /// <summary>
    /// Gets an existing configuration manager from the cache or creates a new one using the factory.
    /// </summary>
    /// <param name="metadataAddress">The OIDC metadata endpoint URL, used as the cache key.</param>
    /// <param name="factory">Factory function to create a new configuration manager if not cached.</param>
    /// <returns>The cached or newly created configuration manager.</returns>
    IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory);

    /// <summary>
    /// Clears all cached entries.
    /// </summary>
    void Clear();
}
