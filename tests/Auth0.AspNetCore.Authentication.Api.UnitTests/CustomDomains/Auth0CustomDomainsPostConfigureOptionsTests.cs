using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class Auth0CustomDomainsPostConfigureOptionsTests
{
    [Fact]
    public void Constructor_WithNullConfigurationManager_ThrowsArgumentNullException()
    {
        // Act
        Action act = () => new Auth0CustomDomainsPostConfigureOptions(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("configurationManager");
    }

    [Fact]
    public void PostConfigure_InjectsConfigurationManagerIntoJwtBearerOptions()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var mockCache = new Mock<IConfigurationManagerCache>();
        var mockLogger = new Mock<Microsoft.Extensions.Logging.ILogger<Auth0CustomDomainsConfigurationManager>>();
        var options = new Auth0CustomDomainsOptions { Domains = ["test.auth0.com"] };

        var configurationManager = new Auth0CustomDomainsConfigurationManager(
            mockHttpContextAccessor.Object,
            options,
            mockCache.Object,
            null,
            mockLogger.Object);

        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager);
        var jwtBearerOptions = new JwtBearerOptions();

        // Act
        postConfigure.PostConfigure("TestScheme", jwtBearerOptions);

        // Assert
        jwtBearerOptions.ConfigurationManager.Should().BeSameAs(configurationManager,
            "the singleton configuration manager should be injected into JwtBearerOptions");
    }

    [Fact]
    public void PostConfigure_CalledMultipleTimes_UsesSameSingletonInstance()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var mockCache = new Mock<IConfigurationManagerCache>();
        var mockLogger = new Mock<Microsoft.Extensions.Logging.ILogger<Auth0CustomDomainsConfigurationManager>>();
        var options = new Auth0CustomDomainsOptions { Domains = ["test.auth0.com"] };

        var configurationManager = new Auth0CustomDomainsConfigurationManager(
            mockHttpContextAccessor.Object,
            options,
            mockCache.Object,
            null,
            mockLogger.Object);

        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager);
        var jwtBearerOptions1 = new JwtBearerOptions();
        var jwtBearerOptions2 = new JwtBearerOptions();

        // Act
        postConfigure.PostConfigure("Scheme1", jwtBearerOptions1);
        postConfigure.PostConfigure("Scheme2", jwtBearerOptions2);

        // Assert
        jwtBearerOptions1.ConfigurationManager.Should().BeSameAs(configurationManager);
        jwtBearerOptions2.ConfigurationManager.Should().BeSameAs(configurationManager);
        jwtBearerOptions1.ConfigurationManager.Should().BeSameAs(jwtBearerOptions2.ConfigurationManager,
            "both options should reference the same singleton instance");
    }

    [Fact]
    public void PostConfigure_OverwritesExistingConfigurationManager()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var mockCache = new Mock<IConfigurationManagerCache>();
        var mockLogger = new Mock<Microsoft.Extensions.Logging.ILogger<Auth0CustomDomainsConfigurationManager>>();
        var options = new Auth0CustomDomainsOptions { Domains = ["test.auth0.com"] };

        var configurationManager = new Auth0CustomDomainsConfigurationManager(
            mockHttpContextAccessor.Object,
            options,
            mockCache.Object,
            null,
            mockLogger.Object);

        var postConfigure = new Auth0CustomDomainsPostConfigureOptions(configurationManager);

        var existingConfigurationManager = new Mock<Microsoft.IdentityModel.Protocols.IConfigurationManager<
            Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>>();

        var jwtBearerOptions = new JwtBearerOptions
        {
            ConfigurationManager = existingConfigurationManager.Object
        };

        // Act
        postConfigure.PostConfigure("TestScheme", jwtBearerOptions);

        // Assert
        jwtBearerOptions.ConfigurationManager.Should().NotBeSameAs(existingConfigurationManager.Object,
            "existing configuration manager should be replaced");
        jwtBearerOptions.ConfigurationManager.Should().BeSameAs(configurationManager,
            "new singleton configuration manager should be set");
    }
}
