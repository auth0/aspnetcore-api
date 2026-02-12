using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// A disposable wrapper around ConfigurationManager that properly manages HttpClient lifecycle.
/// </summary>
/// <remarks>
/// Microsoft's ConfigurationManager and HttpDocumentRetriever are not IDisposable.
/// This wrapper tracks HttpClient ownership and disposes only the clients we create,
/// not those provided by IHttpClientFactory (which manages its own lifecycle).
/// </remarks>
internal sealed class DisposableConfigurationManagerWrapper :
    IConfigurationManager<OpenIdConnectConfiguration>,
    IDisposable
{
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _innerManager;
    private readonly HttpClient? _httpClientToDispose;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="DisposableConfigurationManagerWrapper"/> class.
    /// </summary>
    /// <param name="innerManager">The underlying ConfigurationManager to wrap.</param>
    /// <param name="httpClientToDispose">
    /// The HttpClient to dispose when this wrapper is disposed, or null if the HttpClient
    /// is managed by IHttpClientFactory. Only self-created HttpClients should be disposed.
    /// </param>
    public DisposableConfigurationManagerWrapper(
        IConfigurationManager<OpenIdConnectConfiguration> innerManager,
        HttpClient? httpClientToDispose)
    {
        _innerManager = innerManager ?? throw new ArgumentNullException(nameof(innerManager));
        _httpClientToDispose = httpClientToDispose;
    }

    /// <inheritdoc />
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return await _innerManager.GetConfigurationAsync(cancel);
    }

    /// <inheritdoc />
    public void RequestRefresh()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _innerManager.RequestRefresh();
    }

    /// <summary>
    /// Disposes the HttpClient if we created it.
    /// Does NOT dispose factory-created HttpClients (factory manages their lifecycle).
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Only dispose HttpClients we created
        // Factory-created clients are managed by the factory's handler rotation
        _httpClientToDispose?.Dispose();
    }
}
