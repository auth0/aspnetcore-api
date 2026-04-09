using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// A pass-through cache implementation that does not cache configuration managers. <br/>
/// Use this to disable caching behavior.
/// </summary>
public sealed class NullConfigurationManagerCache : IConfigurationManagerCache
{
    /// <inheritdoc />
    /// <remarks>
    /// This implementation always invokes the factory and never caches the result.
    /// </remarks>
    public IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory)
    {
        return factory(metadataAddress);
    }

    /// <inheritdoc />
    /// <remarks>
    /// This is a no-op since nothing is cached.
    /// </remarks>
    public void Clear()
    {
        // No-op: nothing to clear
    }

    /// <inheritdoc />
    /// <remarks>
    /// This is a no-op since there are no resources to dispose.
    /// </remarks>
    public void Dispose()
    {
        // No-op: nothing to dispose
    }
}
