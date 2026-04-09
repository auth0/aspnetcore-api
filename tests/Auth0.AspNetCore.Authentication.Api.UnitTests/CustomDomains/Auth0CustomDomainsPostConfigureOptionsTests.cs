using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class Auth0CustomDomainsPostConfigureOptionsTests
{
    private Auth0CustomDomainsConfigurationManager CreateConfigurationManager()
    {
        var mockHttpContextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var mockCache = new Mock<IConfigurationManagerCache>();
        var mockLogger = new Mock<Microsoft.Extensions.Logging.ILogger<Auth0CustomDomainsConfigurationManager>>();
        var options = new Auth0CustomDomainsOptions { Domains = ["test.auth0.com"] };

        return new Auth0CustomDomainsConfigurationManager(
            mockHttpContextAccessor.Object,
            options,
            mockCache.Object,
            null,
            mockLogger.Object);
    }

    [Fact]
    public void Constructor_WithNullConfigurationManager_ThrowsArgumentNullException()
    {
        // Act
        Action act = () => new Auth0CustomDomainsPostConfigureOptions(null!, "Auth0");

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("configurationManager");
    }

    [Fact]
    public void Constructor_WithNullAuthenticationScheme_ThrowsArgumentNullException()
    {
        // Arrange
        var configurationManager = CreateConfigurationManager();

        // Act
        Action act = () => new Auth0CustomDomainsPostConfigureOptions(configurationManager, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("authenticationScheme");
    }

    [Fact]
    public void PostConfigure_WithMatchingScheme_InjectsConfigurationManager()
    {
        // Arrange
        var configurationManager = CreateConfigurationManager();
        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager, "Auth0");
        var jwtBearerOptions = new JwtBearerOptions();

        // Act
        postConfigure.PostConfigure("Auth0", jwtBearerOptions);

        // Assert
        jwtBearerOptions.ConfigurationManager.Should().BeSameAs(configurationManager,
            "the singleton configuration manager should be injected into JwtBearerOptions");
    }

    [Fact]
    public void PostConfigure_WithNonMatchingScheme_DoesNotSetConfigurationManager()
    {
        // Arrange
        var configurationManager = CreateConfigurationManager();
        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager, "Auth0");
        var jwtBearerOptions = new JwtBearerOptions();

        // Act
        postConfigure.PostConfigure("OtherIdP", jwtBearerOptions);

        // Assert
        jwtBearerOptions.ConfigurationManager.Should().BeNull(
            "a non-matching scheme should not have its ConfigurationManager replaced");
    }

    [Fact]
    public void PostConfigure_OverwritesExistingConfigurationManager()
    {
        // Arrange
        var configurationManager = CreateConfigurationManager();
        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager, "Auth0");

        var existingConfigurationManager = new Mock<Microsoft.IdentityModel.Protocols.IConfigurationManager<
            Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>>();

        var jwtBearerOptions = new JwtBearerOptions
        {
            ConfigurationManager = existingConfigurationManager.Object
        };

        // Act
        postConfigure.PostConfigure("Auth0", jwtBearerOptions);

        // Assert
        jwtBearerOptions.ConfigurationManager.Should().NotBeSameAs(existingConfigurationManager.Object,
            "existing configuration manager should be replaced");
        jwtBearerOptions.ConfigurationManager.Should().BeSameAs(configurationManager,
            "new singleton configuration manager should be set");
    }
}
