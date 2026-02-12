using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class Auth0CustomDomainsConfigurationManagerIntegrationTests
{
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly Mock<IConfigurationManagerCache> _mockCache;
    private readonly Mock<ILogger<Auth0CustomDomainsConfigurationManager>> _mockLogger;
    private readonly Auth0CustomDomainsOptions _options;

    public Auth0CustomDomainsConfigurationManagerIntegrationTests()
    {
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        _mockCache = new Mock<IConfigurationManagerCache>();
        _mockLogger = new Mock<ILogger<Auth0CustomDomainsConfigurationManager>>();

        _options = new Auth0CustomDomainsOptions
        {
            Domains = ["tenant1.auth0.com", "tenant2.auth0.com"],
            AutomaticRefreshInterval = TimeSpan.FromHours(12),
            RefreshInterval = TimeSpan.FromMinutes(5)
        };
    }

    [Fact]
    public async Task GetConfigurationAsync_WithNoHttpContext_ThrowsInvalidOperationException()
    {
        // Arrange
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns((HttpContext?)null);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("No HTTP context available.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithNoAuthorizationHeader_ThrowsSecurityTokenException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("No token found in request.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithEmptyAuthorizationHeader_ThrowsSecurityTokenException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = string.Empty;
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("No token found in request.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithInvalidTokenFormat_ThrowsSecurityTokenException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "Bearer invalid-token";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Invalid token format.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithSymmetricAlgorithm_ThrowsSecurityTokenException()
    {
        // Arrange
        var token = CreateJwtToken("https://tenant1.auth0.com", "HS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Symmetric algorithms are not supported.");

        // Verify warning was logged
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("HS256")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    [InlineData("hs256")]
    [InlineData("Hs512")]
    public async Task GetConfigurationAsync_WithVariousSymmetricAlgorithms_ThrowsSecurityTokenException(string algorithm)
    {
        // Arrange
        var token = CreateJwtToken("https://tenant1.auth0.com", algorithm.ToUpper());
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Symmetric algorithms are not supported.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithIssuerNotInAllowedList_ThrowsSecurityTokenException()
    {
        // Arrange
        var token = CreateJwtToken("https://unknown.auth0.com", "RS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Token issuer is not allowed.");

        // Verify warning was logged
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("unknown.auth0.com")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithDPoPToken_ExtractsTokenCorrectly()
    {
        // Arrange
        var token = CreateJwtToken("https://tenant1.auth0.com", "RS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"DPoP {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIdConnectConfiguration());

        _mockCache
            .Setup(c => c.GetOrCreate(It.IsAny<string>(), It.IsAny<Func<string, IConfigurationManager<OpenIdConnectConfiguration>>>()))
            .Returns(mockInnerManager.Object);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        OpenIdConnectConfiguration result = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        mockInnerManager.Verify(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithNoDomains_ThrowsSecurityTokenException()
    {
        // Arrange
        var optionsWithNoDomains = new Auth0CustomDomainsOptions
        {
            Domains = null,
            DomainsResolver = null
        };

        var token = CreateJwtToken("https://tenant1.auth0.com", "RS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            optionsWithNoDomains,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("No allowed domains configured or resolved.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithDomainsResolver_CallsResolver()
    {
        // Arrange
        var resolverCalled = false;
        var optionsWithResolver = new Auth0CustomDomainsOptions
        {
            DomainsResolver = (ctx, cancel) =>
            {
                resolverCalled = true;
                return Task.FromResult<IReadOnlyList<string>>(["tenant1.auth0.com"]);
            }
        };

        var token = CreateJwtToken("https://tenant1.auth0.com", "RS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIdConnectConfiguration());

        _mockCache
            .Setup(c => c.GetOrCreate(It.IsAny<string>(), It.IsAny<Func<string, IConfigurationManager<OpenIdConnectConfiguration>>>()))
            .Returns(mockInnerManager.Object);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            optionsWithResolver,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        resolverCalled.Should().BeTrue("DomainsResolver should be called");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithIssuerHavingTrailingSlash_NormalizesAndMatches()
    {
        // Arrange
        var token = CreateJwtToken("https://tenant1.auth0.com/", "RS256"); // Note trailing slash
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIdConnectConfiguration());

        _mockCache
            .Setup(c => c.GetOrCreate(It.IsAny<string>(), It.IsAny<Func<string, IConfigurationManager<OpenIdConnectConfiguration>>>()))
            .Returns(mockInnerManager.Object);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        OpenIdConnectConfiguration result = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        result.Should().NotBeNull("trailing slash should be normalized");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithDomainWithoutHttpsPrefix_AddsPrefix()
    {
        // Arrange
        var token = CreateJwtToken("https://tenant1.auth0.com", "RS256");
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIdConnectConfiguration());

        _mockCache
            .Setup(c => c.GetOrCreate(It.IsAny<string>(), It.IsAny<Func<string, IConfigurationManager<OpenIdConnectConfiguration>>>()))
            .Returns(mockInnerManager.Object);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        OpenIdConnectConfiguration result = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public void RequestRefresh_CallsCacheClear()
    {
        // Arrange
        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        manager.RequestRefresh();

        // Assert
        _mockCache.Verify(c => c.Clear(), Times.Once);
    }

    [Fact]
    public void RequestRefresh_CanBeCalledMultipleTimes()
    {
        // Arrange
        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        manager.RequestRefresh();
        manager.RequestRefresh();
        manager.RequestRefresh();

        // Assert
        _mockCache.Verify(c => c.Clear(), Times.Exactly(3));
    }

    [Theory]
    [InlineData("Bearer token123")]
    [InlineData("bearer token123")]
    [InlineData("BEARER token123")]
    [InlineData("BeArEr token123")]
    public async Task GetConfigurationAsync_WithVariousBearerCasing_ExtractsToken(string authHeader)
    {
        // Arrange - Create a malformed token that will fail parsing
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = authHeader;
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert - Should fail at token parsing, not extraction
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Invalid token format.");
    }

    [Theory]
    [InlineData("DPoP token123")]
    [InlineData("dpop token123")]
    [InlineData("DPOP token123")]
    [InlineData("DpOp token123")]
    public async Task GetConfigurationAsync_WithVariousDPoPCasing_ExtractsToken(string authHeader)
    {
        // Arrange - Create a malformed token that will fail parsing
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = authHeader;
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert - Should fail at token parsing, not extraction
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("Invalid token format.");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithUnsupportedAuthScheme_ThrowsSecurityTokenException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "Basic dXNlcjpwYXNz"; // Not Bearer or DPoP
        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var manager = new Auth0CustomDomainsConfigurationManager(
            _mockHttpContextAccessor.Object,
            _options,
            _mockCache.Object,
            null,
            _mockLogger.Object);

        // Act
        Func<Task> act = async () => await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityTokenException>()
            .WithMessage("No token found in request.");
    }

    private static string CreateJwtToken(string issuer, string algorithm)
    {
        var securityKey = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: "test-audience",
            claims: [new Claim("sub", "test-user")],
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        // Override the algorithm in the header
        token.Header["alg"] = algorithm;

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
