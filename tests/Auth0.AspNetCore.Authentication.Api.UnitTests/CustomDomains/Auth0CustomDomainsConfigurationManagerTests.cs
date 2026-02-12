using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class Auth0CustomDomainsConfigurationManagerTests
{
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly Mock<IConfigurationManagerCache> _mockCache;
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;
    private readonly Mock<ILogger<Auth0CustomDomainsConfigurationManager>> _mockLogger;
    private readonly Auth0CustomDomainsOptions _options;

    public Auth0CustomDomainsConfigurationManagerTests()
    {
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        _mockCache = new Mock<IConfigurationManagerCache>();
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        _mockLogger = new Mock<ILogger<Auth0CustomDomainsConfigurationManager>>();

        _options = new Auth0CustomDomainsOptions
        {
            Domains = new[] { "tenant1.auth0.com", "tenant2.auth0.com" },
            AutomaticRefreshInterval = TimeSpan.FromHours(12),
            RefreshInterval = TimeSpan.FromMinutes(5),
            BackchannelTimeout = TimeSpan.FromSeconds(60)
        };
    }

    [Fact]
    public void CreateConfigurationManager_WithHttpClientFactory_DoesNotTrackClientForDisposal()
    {
        // Arrange
        var factoryClient = new HttpClient();
        _mockHttpClientFactory
            .Setup(f => f.CreateClient("Auth0CustomDomains"))
            .Returns(factoryClient);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            _mockHttpClientFactory.Object,
            _mockLogger.Object);

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result = manager.CreateConfigurationManager("https://tenant1.auth0.com/.well-known/openid-configuration");

        // Assert
        result.Should().NotBeNull();
        result.Should().BeOfType<DisposableConfigurationManagerWrapper>();

        // Verify factory was used
        _mockHttpClientFactory.Verify(f => f.CreateClient("Auth0CustomDomains"), Times.Once);

        // Dispose wrapper
        if (result is IDisposable disposable)
        {
            disposable.Dispose();
        }

        // Factory-created client should NOT be disposed
        Action act = () => _ = factoryClient.Timeout;
        act.Should().NotThrow("factory-created HttpClient should not be disposed by wrapper");

        // Cleanup
        factoryClient.Dispose();
    }

    [Fact]
    public void CreateConfigurationManager_WithoutHttpClientFactory_TracksClientForDisposal()
    {
        // Arrange
        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null, // No factory
            _mockLogger.Object);

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result = manager.CreateConfigurationManager("https://tenant1.auth0.com/.well-known/openid-configuration");

        // Assert
        result.Should().NotBeNull();
        result.Should().BeOfType<DisposableConfigurationManagerWrapper>();

        // Store a reference to test disposal
        var wrapper = (DisposableConfigurationManagerWrapper)result;

        // Before disposal, we can't directly test the HttpClient, but we can verify the wrapper disposes correctly
        Action act = () => wrapper.Dispose();
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_DisposesCache()
    {
        // Arrange
        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            _mockHttpClientFactory.Object,
            _mockLogger.Object);

        // Act
        manager.Dispose();

        // Assert
        _mockCache.Verify(c => c.Dispose(), Times.Once);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_DisposeCacheOnlyOnce()
    {
        // Arrange
        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            _mockHttpClientFactory.Object,
            _mockLogger.Object);

        // Act
        manager.Dispose();
        manager.Dispose();
        manager.Dispose();

        // Assert
        _mockCache.Verify(c => c.Dispose(), Times.Once,
            "cache should only be disposed once even with multiple Dispose calls");
    }

}
