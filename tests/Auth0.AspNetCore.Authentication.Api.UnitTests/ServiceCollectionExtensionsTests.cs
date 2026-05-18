using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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

    #region Startup Validation Failure Tests

    [Fact]
    public void AddAuth0ApiAuthentication_WithMissingDomain_ThrowsOptionsValidationException_AtStartup()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth0:Audience"] = "https://api.example.com"
                // Domain is missing
            })
            .Build();

        services.AddAuth0ApiAuthentication(configuration.GetSection("Auth0"));
        var serviceProvider = services.BuildServiceProvider();

        // Act — trigger options validation by resolving Auth0ApiOptions
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*Domain*");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithMissingAudience_ThrowsOptionsValidationException_AtStartup()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth0:Domain"] = "example.auth0.com"
                // Audience is missing
            })
            .Build();

        services.AddAuth0ApiAuthentication(configuration.GetSection("Auth0"));
        var serviceProvider = services.BuildServiceProvider();

        // Act — trigger options validation by resolving JwtBearerOptions
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*Audience*");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithDomainContainingScheme_ThrowsOptionsValidationException_AtStartup()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth0:Domain"] = "https://example.auth0.com",
                ["Auth0:Audience"] = "https://api.example.com"
            })
            .Build();

        services.AddAuth0ApiAuthentication(configuration.GetSection("Auth0"));
        var serviceProvider = services.BuildServiceProvider();

        // Act — trigger options validation
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*hostname only*");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Delegate_WithMissingDomain_ThrowsOptionsValidationException_AtStartup()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddAuth0ApiAuthentication(options =>
        {
            options.Domain = "";
            options.Audience = "https://api.example.com";
        });
        var serviceProvider = services.BuildServiceProvider();

        // Act
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*Domain*");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Delegate_WithMissingAudience_ThrowsOptionsValidationException_AtStartup()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddAuth0ApiAuthentication(options =>
        {
            options.Domain = "example.auth0.com";
            options.Audience = "";
        });
        var serviceProvider = services.BuildServiceProvider();

        // Act
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*Audience*");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithValidAudiences_InCallback_DoesNotThrow()
    {
        // Arrange — multi-audience scenario: Audience is empty but ValidAudiences is set via callback
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth0:Domain"] = "example.auth0.com"
                // Audience intentionally missing — using ValidAudiences instead
            })
            .Build();

        services.AddAuth0ApiAuthentication(
            configuration.GetSection("Auth0"),
            configureJwtBearer: jwt =>
            {
                jwt.TokenValidationParameters.ValidAudiences = new[] { "https://api1.example.com", "https://api2.example.com" };
            });
        var serviceProvider = services.BuildServiceProvider();

        // Act — resolving JwtBearerOptions should NOT throw because ValidAudiences is set
        Action act = () => serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        // Assert
        act.Should().NotThrow();
    }

    #endregion
}
