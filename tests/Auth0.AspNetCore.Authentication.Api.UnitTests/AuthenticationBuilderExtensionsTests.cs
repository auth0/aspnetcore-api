using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class AuthenticationBuilderExtensionsTest
{
    private readonly AuthenticationBuilder _authenticationBuilder;
    private readonly ServiceCollection _services;

    public AuthenticationBuilderExtensionsTest()
    {
        _services = new ServiceCollection();
        _authenticationBuilder = new AuthenticationBuilder(_services);
    }

    #region ValidateAuth0ApiOptionsTests

    [Fact]
    public void ValidateAuth0ApiOptions_ShouldNotThrow_When_Domain_And_Audience_Are_Set()
    {
        // Arrange
        var options = new Auth0ApiOptions
        {
            Domain = "example.auth0.com",
            JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "https://api.example.com"
            }
        };

        // Act
        Action act = () => AuthenticationBuilderExtensions.ValidateAuth0ApiOptions(options);

        // Assert
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateAuth0ApiOptions_ShouldThrow_When_Domain_Is_Null_Or_WhiteSpace(string? domain)
    {
        // Arrange
        var options = new Auth0ApiOptions
        {
            Domain = domain,
            JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "https://api.example.com"
            }
        };

        // Act
        Action act = () => AuthenticationBuilderExtensions.ValidateAuth0ApiOptions(options);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("Auth0 Domain is required. Please set the Domain property in Auth0ApiOptions.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateAuth0ApiOptions_ShouldThrow_When_Audience_Is_Null_Or_WhiteSpace(string? audience)
    {
        // Arrange
        var options = new Auth0ApiOptions
        {
            Domain = "example.auth0.com",
            JwtBearerOptions = new JwtBearerOptions
            {
                Audience = audience
            }
        };

        // Act
        Action act = () => AuthenticationBuilderExtensions.ValidateAuth0ApiOptions(options);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("Auth0 Audience is required. Please set the Audience property in Auth0ApiOptions.");
    }

    #endregion

    #region ConfigureJwtBearerOptionsTests

    [Fact]
    public void ConfigureJwtBearerOptions_With_Null_JwtBearerOptions_ThrowsArgumentNullException()
    {
        // Arrange
        JwtBearerOptions? jwtBearerOptions = null;
        var auth0Options = new Auth0ApiOptions();

        // Act & Assert
        Action action = () => AuthenticationBuilderExtensions.ConfigureJwtBearerOptions(jwtBearerOptions, auth0Options);
        action.Should().Throw<ArgumentNullException>().WithParameterName("jwtBearerOptions");
    }

    [Fact]
    public void ConfigureJwtBearerOptions_With_Null_Auth0Options_Throws_ArgumentNullException()
    {
        // Arrange
        var jwtBearerOptions = new JwtBearerOptions();
        Auth0ApiOptions? auth0Options = null;

        // Act & Assert
        Action action = () => AuthenticationBuilderExtensions.ConfigureJwtBearerOptions(jwtBearerOptions, auth0Options);
        action.Should().Throw<ArgumentNullException>().WithParameterName("auth0ApiOptions");
    }

    [Fact]
    public void ConfigureJwtBearerOptions_With_Valid_Options_Configures_All()
    {
        // Arrange
        var jwtBearerOptions = new JwtBearerOptions();
        var customConfiguration = new OpenIdConnectConfiguration();
        var customConfigurationManager =
            new ConfigurationManager<OpenIdConnectConfiguration>("https://test.com",
                new OpenIdConnectConfigurationRetriever());
        var customHandler = new HttpClientHandler();
        var customBackchannel = new HttpClient();
        Func<HttpContext, string> customSelector = _ => "custom";
        var customTokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false
        };
        var auth0Options = new Auth0ApiOptions
        {
            Domain = "test.auth0.com",
            JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "test-audience",
                ClaimsIssuer = "test-issuer",
                Challenge = "test-challenge",
                SaveToken = true,
                IncludeErrorDetails = true,
                RequireHttpsMetadata = false,
                MetadataAddress = "https://test.com/.well-known/openid_configuration",
                RefreshOnIssuerKeyNotFound = false,
                MapInboundClaims = false,
                BackchannelTimeout = TimeSpan.FromSeconds(30),
                AutomaticRefreshInterval = TimeSpan.FromHours(1),
                RefreshInterval = TimeSpan.FromMinutes(30),
                UseSecurityTokenValidators = true,
                ForwardDefault = "Default",
                ForwardAuthenticate = "Authenticate",
                ForwardChallenge = "Challenge",
                ForwardForbid = "Forbid",
                ForwardSignIn = "SignIn",
                ForwardSignOut = "SignOut",
                Events = new JwtBearerEvents(),
                Configuration = customConfiguration,
                ConfigurationManager = customConfigurationManager,
                BackchannelHttpHandler = customHandler,
                Backchannel = customBackchannel,
                ForwardDefaultSelector = customSelector,
                TokenValidationParameters = customTokenValidationParameters
            }
        };

        // Act
        AuthenticationBuilderExtensions.ConfigureJwtBearerOptions(jwtBearerOptions, auth0Options);

        // Assert
        jwtBearerOptions.Authority.Should().Be("https://test.auth0.com");
        jwtBearerOptions.Audience.Should().Be("test-audience");
        jwtBearerOptions.ClaimsIssuer.Should().Be("test-issuer");
        jwtBearerOptions.Challenge.Should().Be("test-challenge");
        jwtBearerOptions.SaveToken.Should().BeTrue();
        jwtBearerOptions.IncludeErrorDetails.Should().BeTrue();
        jwtBearerOptions.RequireHttpsMetadata.Should().BeFalse();
        jwtBearerOptions.MetadataAddress.Should().Be("https://test.com/.well-known/openid_configuration");
        jwtBearerOptions.RefreshOnIssuerKeyNotFound.Should().BeFalse();
        jwtBearerOptions.MapInboundClaims.Should().BeFalse();
        jwtBearerOptions.BackchannelTimeout.Should().Be(TimeSpan.FromSeconds(30));
        jwtBearerOptions.AutomaticRefreshInterval.Should().Be(TimeSpan.FromHours(1));
        jwtBearerOptions.RefreshInterval.Should().Be(TimeSpan.FromMinutes(30));
        jwtBearerOptions.UseSecurityTokenValidators.Should().BeTrue();
        jwtBearerOptions.ForwardDefault.Should().Be("Default");
        jwtBearerOptions.ForwardAuthenticate.Should().Be("Authenticate");
        jwtBearerOptions.ForwardChallenge.Should().Be("Challenge");
        jwtBearerOptions.ForwardForbid.Should().Be("Forbid");
        jwtBearerOptions.ForwardSignIn.Should().Be("SignIn");
        jwtBearerOptions.ForwardSignOut.Should().Be("SignOut");
        jwtBearerOptions.Events.Should().NotBeNull();
        jwtBearerOptions.ConfigurationManager.Should().Be(customConfigurationManager);
        jwtBearerOptions.Configuration.Should().Be(customConfiguration);
        jwtBearerOptions.BackchannelHttpHandler.Should().Be(customHandler);
        jwtBearerOptions.Backchannel.Should().Be(customBackchannel);
        jwtBearerOptions.ForwardDefaultSelector.Should().Be(customSelector);
        jwtBearerOptions.TokenValidationParameters.Should().Be(customTokenValidationParameters);
    }

    [Fact]
    public void ConfigureJwtBearerOptions_With_Default_Values_Configures_Correctly()
    {
        // Arrange
        var jwtBearerOptions = new JwtBearerOptions();
        var auth0Options = new Auth0ApiOptions
        {
            Domain = "test.auth0.com",
            JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "test-audience"
            }
        };

        // Act
        AuthenticationBuilderExtensions.ConfigureJwtBearerOptions(jwtBearerOptions, auth0Options);

        // Assert
        jwtBearerOptions.Authority.Should().Be("https://test.auth0.com");
        jwtBearerOptions.Audience.Should().Be("test-audience");
        jwtBearerOptions.ClaimsIssuer.Should().BeNull();
        jwtBearerOptions.Challenge.Should().Be("Bearer");
        jwtBearerOptions.SaveToken.Should().BeTrue();
        jwtBearerOptions.IncludeErrorDetails.Should().BeTrue();
        jwtBearerOptions.RequireHttpsMetadata.Should().BeTrue();
        jwtBearerOptions.RefreshOnIssuerKeyNotFound.Should().BeTrue();
        jwtBearerOptions.MapInboundClaims.Should().BeTrue();
    }

    #endregion

    #region AddAuth0ApiAuthentication

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData("\n")]
    public void AddAuth0ApiAuthentication_With_Invalid_AuthenticationScheme_Should_Throw_ArgumentException(
        string scheme)
    {
        // Arrange
        Action<Auth0ApiOptions> configureOptions = opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "test-audience"
            };
        };

        // Act & Assert
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            _authenticationBuilder.AddAuth0ApiAuthentication(scheme, configureOptions));

        exception.ParamName.Should().Be("authenticationScheme");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_With_Null_ConfigureOptions_Should_ThrowArgumentNullException()
    {
        // Act & Assert
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
            _authenticationBuilder.AddAuth0ApiAuthentication(null));

        exception.ParamName.Should().Be("configureOptions");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Should_Register_Configuration_Successfully()
    {
        // Arrange & Act
        _authenticationBuilder.AddAuth0ApiAuthentication(opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.JwtBearerOptions = new JwtBearerOptions
            {
                Audience = "test-audience"
            };
        });

        // Assert
        ServiceProvider serviceProvider = _services.BuildServiceProvider();
        IOptionsMonitor<Auth0ApiOptions> optionsMonitor =
            serviceProvider.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>();
        Auth0ApiOptions options = optionsMonitor.Get(Auth0Constants.AuthenticationScheme.Auth0);

        options.Domain.Should().Be("test.auth0.com");
        options.JwtBearerOptions?.Audience.Should().Be("test-audience");

        // Assert for IPostConfigureOptions<JwtBearerOptions> registration
        ServiceDescriptor? serviceDescriptor = _services.FirstOrDefault(s =>
            s.ServiceType == typeof(IPostConfigureOptions<JwtBearerOptions>) &&
            s.ImplementationType == typeof(Auth0JwtBearerPostConfigureOptions));

        serviceDescriptor.Should().NotBeNull();
        serviceDescriptor.Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    #endregion

    #region ValidateCustomDomainsOptionsTests

    private Auth0ApiAuthenticationBuilder CreateAuth0Builder()
    {
        return _authenticationBuilder.AddAuth0ApiAuthentication(options =>
        {
            options.Domain = "tenant.auth0.com";
            options.JwtBearerOptions = new JwtBearerOptions { Audience = "https://api.example.com" };
        });
    }

    [Theory]
    [InlineData("tenant.auth0.com")]
    [InlineData("https://tenant.auth0.com")]
    [InlineData("http://tenant.auth0.com")]
    [InlineData("tenant.auth0.com/")]
    [InlineData("https://tenant.auth0.com/")]
    public void WithCustomDomains_WithValidDomainFormat_DoesNotThrow(string domain)
    {
        // Arrange
        Auth0ApiAuthenticationBuilder builder = CreateAuth0Builder();

        // Act
        Action act = () => builder.WithCustomDomains(opts => opts.Domains = [domain]);

        // Assert
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("tenant.auth0.com/path")]
    [InlineData("https://tenant.auth0.com/path")]
    [InlineData("http://tenant.auth0.com/path")]
    public void WithCustomDomains_WithPathComponent_ThrowsInvalidOperationException(string domain)
    {
        // Arrange
        Auth0ApiAuthenticationBuilder builder = CreateAuth0Builder();

        // Act
        Action act = () => builder.WithCustomDomains(opts => opts.Domains = [domain]);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"Invalid domain format: '{domain}'*");
    }

    [Fact]
    public void WithCustomDomains_WithQueryString_ThrowsInvalidOperationException()
    {
        // Arrange
        Auth0ApiAuthenticationBuilder builder = CreateAuth0Builder();
        const string domain = "tenant.auth0.com?q=1"; // query string

        // Act
        Action act = () => builder.WithCustomDomains(opts => opts.Domains = [domain]);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"Invalid domain format: '{domain}'*");
    }

    [Fact]
    public void WithCustomDomains_WithEmbeddedWhitespace_ThrowsInvalidOperationException()
    {
        // Arrange
        Auth0ApiAuthenticationBuilder builder = CreateAuth0Builder();
        const string domain = "tenant .auth0.com";

        // Act
        Action act = () => builder.WithCustomDomains(opts => opts.Domains = [domain]);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"Invalid domain format: '{domain}'*");
    }

    #endregion
}
