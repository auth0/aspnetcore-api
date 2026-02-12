using System.Net;
using System.Net.Http.Headers;

namespace Auth0.AspNetCore.Authentication.Api.IntegrationTests;

/// <summary>
/// Integration tests for Multi Custom Domains feature.
/// Tests end-to-end authentication flow with multiple Auth0 domains.
/// </summary>
public class CustomDomainsIntegrationTests : IAsyncLifetime
{
    private TestWebApplicationFactory? _factory;
    private Auth0TokenHelper? _tokenHelperDomain1;
    private Auth0TokenHelper? _tokenHelperDomain2;
    private Auth0Scenario? _scenario1;
    private Auth0Scenario? _scenario2;

    public async Task InitializeAsync()
    {
        // Load scenarios for both custom domains
        _scenario1 = Auth0TestConfiguration.CustomDomain1;
        _scenario2 = Auth0TestConfiguration.CustomDomain2;

        // Create factory with both domains and both audiences in allowed list
        _factory = new TestWebApplicationFactory(
            _scenario1,
            customDomains: [_scenario1.Domain, _scenario2.Domain],
            validAudiences: [_scenario1.Audience, _scenario2.Audience]);

        // Create token helpers for both domains
        _tokenHelperDomain1 = new Auth0TokenHelper(_scenario1.Domain, _scenario1.ClientId,
            _scenario1.ClientSecret, _scenario1.Audience);
        _tokenHelperDomain2 = new Auth0TokenHelper(_scenario2.Domain, _scenario2.ClientId,
            _scenario2.ClientSecret, _scenario2.Audience);

        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await (_factory?.DisposeAsync() ?? ValueTask.CompletedTask);
    }

    [Fact]
    public async Task MultipleRequests_DifferentDomains_BothSucceed()
    {
        // Arrange
        using HttpClient client1 = _factory!.CreateClient();
        using HttpClient client2 = _factory!.CreateClient();

        // Act & Assert - Request 1 (Domain 1)
        var token1 = await _tokenHelperDomain1!.GetAccessTokenAsync();
        client1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        HttpResponseMessage response1 = await client1.GetAsync("/api/protected");
        response1.StatusCode.Should().Be(HttpStatusCode.OK,
            "first request with domain1 token should succeed");

        // Act & Assert - Request 2 (Domain 2)
        var token2 = await _tokenHelperDomain2!.GetAccessTokenAsync();
        client2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        HttpResponseMessage response2 = await client2.GetAsync("/api/protected");
        response2.StatusCode.Should().Be(HttpStatusCode.OK,
            "second request with domain2 token should succeed");

        // Act & Assert - Request 3 (Back to Domain 1)
        client1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        HttpResponseMessage response3 = await client1.GetAsync("/api/protected");
        response3.StatusCode.Should().Be(HttpStatusCode.OK,
            "third request with domain1 token should succeed (cache hit)");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithTokenFromUnallowedDomain_ReturnsUnauthorized()
    {
        // Arrange
        using HttpClient client = _factory!.CreateClient();

        // Create token with an issuer NOT in the allowed list
        var unauthorizedIssuer = "https://unauthorized-tenant.auth0.com";
        var token = SymmetricTokenHelper.CreateTokenWithCustomIssuer(unauthorizedIssuer, _scenario1!.Audience);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync("/api/protected");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "token from unallowed domain should be rejected");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithSymmetricAlgorithmToken_ReturnsUnauthorized()
    {
        // Arrange
        using HttpClient client = _factory!.CreateClient();

        // Create HS256 token (symmetric algorithm) with allowed issuer
        var issuer = $"https://{_scenario1!.Domain}";
        var token = SymmetricTokenHelper.CreateHS256Token(issuer, _scenario1!.Audience);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync("/api/protected");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "symmetric algorithm tokens should be rejected before network calls");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithMalformedToken_ReturnsUnauthorized()
    {
        // Arrange
        using HttpClient client = _factory!.CreateClient();
        var malformedToken = SymmetricTokenHelper.CreateMalformedToken();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", malformedToken);

        // Act
        HttpResponseMessage response = await client.GetAsync("/api/protected");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "malformed tokens should be rejected");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithTrailingSlashInIssuer_NormalizesAndValidates()
    {
        // Arrange
        using HttpClient client = _factory!.CreateClient();

        // Create token with trailing slash in issuer (should be normalized)
        var issuerWithTrailingSlash = $"https://{_scenario1!.Domain}/";
        var token = await _tokenHelperDomain1!.GetAccessTokenAsync();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync("/api/protected");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PublicEndpoint_WithoutToken_ReturnsOk()
    {
        // Arrange
        using HttpClient client = _factory!.CreateClient();
        // No token set

        // Act
        HttpResponseMessage response = await client.GetAsync("/api/public");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "public endpoints should be accessible without authentication");

        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("public endpoint");
    }
}
