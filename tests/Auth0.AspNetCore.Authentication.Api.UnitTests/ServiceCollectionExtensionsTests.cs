using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuth0ApiAuthentication_With_Null_ConfigureOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act & Assert
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
            services.AddAuth0ApiAuthentication((Action<Auth0ApiOptions>)null!));
        exception.ParamName.Should().Be("configureOptions");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_With_Null_ConfigurationSection_ThrowsArgumentNullException()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act & Assert
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
            services.AddAuth0ApiAuthentication((IConfigurationSection)null!));
        exception.ParamName.Should().Be("configurationSection");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_With_NullOrEmpty_AuthenticationScheme_ThrowsArgumentException()
    {
        // Arrange
        var services = new ServiceCollection();
        Action<Auth0ApiOptions> configureOptions = _ => { };

        // Act & Assert
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            services.AddAuth0ApiAuthentication("", configureOptions));
        exception.ParamName.Should().Be("authenticationScheme");

        exception = Assert.Throws<ArgumentNullException>(() =>
            services.AddAuth0ApiAuthentication(null!, configureOptions));
        exception.ParamName.Should().Be("authenticationScheme");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_With_Valid_Parameters_Returns_Auth0ApiAuthenticationBuilder()
    {
        // Arrange
        var services = new ServiceCollection();
        Action<Auth0ApiOptions> configureOptions = options =>
        {
            options.Domain = "example.auth0.com";
            options.Audience = "https://api.example.com";
        };

        // Act
        Auth0ApiAuthenticationBuilder result = services.AddAuth0ApiAuthentication(configureOptions);

        // Assert
        result.Should().NotBeNull();
        result.Should().BeOfType<Auth0ApiAuthenticationBuilder>();
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithScheme_With_Valid_Parameters_Returns_Auth0ApiAuthenticationBuilder()
    {
        // Arrange
        var services = new ServiceCollection();
        var authenticationScheme = "TestScheme";
        Action<Auth0ApiOptions> configureOptions = options =>
        {
            options.Domain = "example.auth0.com";
            options.Audience = "https://api.example.com";
        };

        // Act
        Auth0ApiAuthenticationBuilder result =
            services.AddAuth0ApiAuthentication(authenticationScheme, configureOptions);

        // Assert
        result.Should().NotBeNull();
        result.Should().BeOfType<Auth0ApiAuthenticationBuilder>();
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigurationSection_Returns_Auth0ApiAuthenticationBuilder()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth0:Domain"] = "example.auth0.com",
                ["Auth0:Audience"] = "https://api.example.com"
            })
            .Build();

        // Act
        Auth0ApiAuthenticationBuilder result =
            services.AddAuth0ApiAuthentication(configuration.GetSection("Auth0"));

        // Assert
        result.Should().NotBeNull();
        result.Should().BeOfType<Auth0ApiAuthenticationBuilder>();
    }
}
