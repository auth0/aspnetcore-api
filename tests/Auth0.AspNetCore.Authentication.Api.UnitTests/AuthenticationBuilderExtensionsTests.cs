using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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

    #region Auth0ApiOptionsValidatorTests

    [Fact]
    public void Auth0ApiOptionsValidator_ShouldSucceed_When_Domain_Is_Set()
    {
        // Arrange
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = "example.auth0.com" };

        // Act
        ValidateOptionsResult result = validator.Validate(null, options);

        // Assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Is_Empty_Or_WhiteSpace(string domain)
    {
        // Arrange
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        // Act
        ValidateOptionsResult result = validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("Domain"));
    }

    [Fact]
    public void Auth0ApiOptionsValidator_ShouldSucceed_Regardless_Of_Audience()
    {
        // Audience is validated separately on JwtBearerOptions; Auth0ApiOptionsValidator
        // only enforces Domain.
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = "example.auth0.com", Audience = string.Empty };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("https://tenant.auth0.com")]
    [InlineData("http://tenant.auth0.com")]
    [InlineData("HTTPS://tenant.auth0.com")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Contains_Scheme(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("hostname only"));
    }

    [Theory]
    [InlineData("tenant.auth0.com/path")]
    [InlineData("tenant.auth0.com/some/path")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Contains_Path(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("hostname only"));
    }

    [Theory]
    [InlineData("tenant.auth0.com:443")]
    [InlineData("tenant.auth0.com:8080")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Contains_Port(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("port"));
    }

    [Theory]
    [InlineData("tenant.auth0.com?q=1")]
    [InlineData("tenant.auth0.com#fragment")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Contains_QueryOrFragment(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("hostname only"));
    }

    [Theory]
    [InlineData("tenant auth0.com")]
    [InlineData("tenant\tauth0.com")]
    public void Auth0ApiOptionsValidator_ShouldFail_When_Domain_Contains_Whitespace(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.Should().BeTrue();
    }

    [Theory]
    [InlineData("tenant.us.auth0.com")]
    [InlineData("my-tenant.auth0.com")]
    [InlineData("example.com")]
    [InlineData("tenant.auth0.com/")]
    public void Auth0ApiOptionsValidator_ShouldSucceed_For_Valid_Domain(string domain)
    {
        var validator = new Auth0ApiOptionsValidator();
        var options = new Auth0ApiOptions { Domain = domain };

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    #endregion

    #region Auth0JwtBearerOptionsValidatorTests

    [Fact]
    public void JwtBearerOptionsValidator_ShouldSucceed_When_Audience_Is_Set()
    {
        // Arrange
        var validator = new Auth0JwtBearerOptionsValidator("Auth0");
        var options = new JwtBearerOptions { Audience = "https://api.example.com" };

        // Act
        ValidateOptionsResult result = validator.Validate("Auth0", options);

        // Assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void JwtBearerOptionsValidator_ShouldSucceed_When_ValidAudiences_Is_Set()
    {
        // This is the multi-audience scenario — Audience is empty but ValidAudiences covers it.
        var validator = new Auth0JwtBearerOptionsValidator("Auth0");
        var options = new JwtBearerOptions();
        options.TokenValidationParameters.ValidAudiences = ["https://api1.example.com", "https://api2.example.com"];

        ValidateOptionsResult result = validator.Validate("Auth0", options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void JwtBearerOptionsValidator_ShouldFail_When_Neither_Audience_Nor_ValidAudiences_Is_Set()
    {
        // Arrange
        var validator = new Auth0JwtBearerOptionsValidator("Auth0");
        var options = new JwtBearerOptions();

        // Act
        ValidateOptionsResult result = validator.Validate("Auth0", options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("Audience"));
    }

    [Fact]
    public void JwtBearerOptionsValidator_ShouldSkip_For_Different_Scheme()
    {
        // Should not interfere with JwtBearerOptions registered for a different scheme.
        var validator = new Auth0JwtBearerOptionsValidator("Auth0");
        var options = new JwtBearerOptions(); // no audience

        ValidateOptionsResult result = validator.Validate("SomeOtherScheme", options);

        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void JwtBearerOptionsValidator_ShouldFail_When_EventsType_Is_Set()
    {
        // EventsType takes precedence over Events at runtime in ASP.NET Core,
        // which would silently bypass the SDK's event handler chain (DPoP, custom domains).
        var validator = new Auth0JwtBearerOptionsValidator("Auth0");
        var options = new JwtBearerOptions
        {
            Audience = "https://api.example.com",
            EventsType = typeof(JwtBearerEvents)
        };

        ValidateOptionsResult result = validator.Validate("Auth0", options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().ContainSingle(f => f.Contains("EventsType"));
    }

    #endregion

    #region Auth0JwtBearerConfigureOptionsTests

    [Fact]
    public void Auth0JwtBearerConfigureOptions_Sets_Authority_And_Audience_From_Auth0Options()
    {
        // Arrange
        var services = new ServiceCollection();
        services.Configure<Auth0ApiOptions>("Auth0", opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "test-audience";
        });
        var sp = services.BuildServiceProvider();

        var configurator = new Auth0JwtBearerConfigureOptions(
            "Auth0",
            sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>(),
            configureJwtBearer: null);
        var jwtBearerOptions = new JwtBearerOptions();

        // Act
        configurator.Configure("Auth0", jwtBearerOptions);

        // Assert
        jwtBearerOptions.Authority.Should().Be("https://test.auth0.com");
        jwtBearerOptions.Audience.Should().Be("test-audience");
    }

    [Fact]
    public void Auth0JwtBearerConfigureOptions_Applies_ConfigureJwtBearer_Callback()
    {
        // The user's callback runs after Domain/Audience are applied, so it can override them.
        var services = new ServiceCollection();
        services.Configure<Auth0ApiOptions>("Auth0", opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "from-options";
        });
        var sp = services.BuildServiceProvider();

        var configurator = new Auth0JwtBearerConfigureOptions(
            "Auth0",
            sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>(),
            configureJwtBearer: jwt => jwt.Audience = "overridden-by-callback");
        var jwtBearerOptions = new JwtBearerOptions();

        configurator.Configure("Auth0", jwtBearerOptions);

        jwtBearerOptions.Audience.Should().Be("overridden-by-callback");
    }

    [Fact]
    public void Auth0JwtBearerConfigureOptions_SkipsOtherSchemes()
    {
        // Should not modify JwtBearerOptions for a scheme it doesn't own.
        var services = new ServiceCollection();
        services.Configure<Auth0ApiOptions>("Auth0", opts => { opts.Domain = "test.auth0.com"; opts.Audience = "test"; });
        var sp = services.BuildServiceProvider();

        var configurator = new Auth0JwtBearerConfigureOptions(
            "Auth0",
            sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>(),
            configureJwtBearer: null);
        var jwtBearerOptions = new JwtBearerOptions();

        configurator.Configure("SomeOtherScheme", jwtBearerOptions);

        jwtBearerOptions.Authority.Should().BeNull();
        jwtBearerOptions.Audience.Should().BeNull();
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
        // Act & Assert
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            _authenticationBuilder.AddAuth0ApiAuthentication(scheme));

        exception.ParamName.Should().Be("authenticationScheme");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Should_Register_Configuration_Successfully()
    {
        // Arrange
        _services.Configure<Auth0ApiOptions>(Auth0Constants.AuthenticationScheme.Auth0, opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "test-audience";
        });

        // Act
        _authenticationBuilder.AddAuth0ApiAuthentication();

        // Assert
        ServiceProvider serviceProvider = _services.BuildServiceProvider();
        IOptionsMonitor<Auth0ApiOptions> optionsMonitor =
            serviceProvider.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>();
        Auth0ApiOptions options = optionsMonitor.Get(Auth0Constants.AuthenticationScheme.Auth0);

        options.Domain.Should().Be("test.auth0.com");
        options.Audience.Should().Be("test-audience");

        // Assert for IPostConfigureOptions<JwtBearerOptions> registration
        ServiceDescriptor? serviceDescriptor = _services.FirstOrDefault(s =>
            s.ServiceType == typeof(IPostConfigureOptions<JwtBearerOptions>) &&
            s.ImplementationType == typeof(Auth0JwtBearerPostConfigureOptions));

        serviceDescriptor.Should().NotBeNull();
        serviceDescriptor!.Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Should_Register_Auth0ApiOptions_Validator()
    {
        // Arrange
        _services.Configure<Auth0ApiOptions>(Auth0Constants.AuthenticationScheme.Auth0, opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "test-audience";
        });

        // Act
        _authenticationBuilder.AddAuth0ApiAuthentication();

        // Assert
        ServiceDescriptor? validatorDescriptor = _services.FirstOrDefault(s =>
            s.ServiceType == typeof(IValidateOptions<Auth0ApiOptions>));

        validatorDescriptor.Should().NotBeNull();
        validatorDescriptor!.ImplementationType.Should().Be(typeof(Auth0ApiOptionsValidator));
    }

    [Fact]
    public void AddAuth0ApiAuthentication_Should_Register_JwtBearerOptions_Validator()
    {
        // Arrange
        _services.Configure<Auth0ApiOptions>(Auth0Constants.AuthenticationScheme.Auth0, opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "test-audience";
        });

        // Act
        _authenticationBuilder.AddAuth0ApiAuthentication();

        // Assert — an Auth0JwtBearerOptionsValidator instance is registered
        ServiceDescriptor? validatorDescriptor = _services.FirstOrDefault(s =>
            s.ServiceType == typeof(IValidateOptions<JwtBearerOptions>) &&
            s.ImplementationInstance is Auth0JwtBearerOptionsValidator);

        validatorDescriptor.Should().NotBeNull();
    }

    [Fact]
    public void AddAuth0ApiAuthentication_ConfigureJwtBearer_Registers_JwtBearerScheme()
    {
        // Arrange
        _services.Configure<Auth0ApiOptions>(Auth0Constants.AuthenticationScheme.Auth0, opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "test-audience";
        });

        // Act
        Auth0ApiAuthenticationBuilder result = _authenticationBuilder.AddAuth0ApiAuthentication(configureJwtBearer: jwt =>
        {
            jwt.SaveToken = true;
            jwt.RequireHttpsMetadata = false;
        });

        // Assert - the builder is returned with the correct scheme
        result.Should().NotBeNull();
        result.AuthenticationScheme.Should().Be(Auth0Constants.AuthenticationScheme.Auth0);

        // Verify JwtBearer configuration was registered
        ServiceDescriptor? jwtBearerDescriptor = _services.FirstOrDefault(s =>
            s.ServiceType == typeof(IConfigureOptions<JwtBearerOptions>));
        jwtBearerDescriptor.Should().NotBeNull();
    }

    #endregion

    #region AddAuth0ApiAuthentication_WithConfigurationSection

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigurationSection_Should_Register_Options()
    {
        // Arrange
        var configData = new Dictionary<string, string?>
        {
            { "Auth0:Domain", "test.auth0.com" },
            { "Auth0:Audience", "https://api.example.com" }
        };
        IConfigurationSection section = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build()
            .GetSection("Auth0");

        // Act
        Auth0ApiAuthenticationBuilder result = _authenticationBuilder.AddAuth0ApiAuthentication(section);

        // Assert
        result.AuthenticationScheme.Should().Be(Auth0Constants.AuthenticationScheme.Auth0);

        ServiceProvider sp = _services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        options.Domain.Should().Be("test.auth0.com");
        options.Audience.Should().Be("https://api.example.com");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigurationSection_And_CustomScheme_Should_Register_Options()
    {
        // Arrange
        var configData = new Dictionary<string, string?>
        {
            { "Auth0:Domain", "test.auth0.com" },
            { "Auth0:Audience", "https://api.example.com" }
        };
        IConfigurationSection section = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build()
            .GetSection("Auth0");

        // Act
        Auth0ApiAuthenticationBuilder result =
            _authenticationBuilder.AddAuth0ApiAuthentication("CustomScheme", section);

        // Assert
        result.AuthenticationScheme.Should().Be("CustomScheme");

        ServiceProvider sp = _services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get("CustomScheme");

        options.Domain.Should().Be("test.auth0.com");
        options.Audience.Should().Be("https://api.example.com");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigurationSection_Null_Should_Throw()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _authenticationBuilder.AddAuth0ApiAuthentication((IConfigurationSection)null!));
    }

    #endregion

    #region AddAuth0ApiAuthentication_WithConfigureOptions

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigureOptions_Should_Register_Options()
    {
        // Act
        Auth0ApiAuthenticationBuilder result = _authenticationBuilder.AddAuth0ApiAuthentication(opts =>
        {
            opts.Domain = "test.auth0.com";
            opts.Audience = "https://api.example.com";
        });

        // Assert
        result.AuthenticationScheme.Should().Be(Auth0Constants.AuthenticationScheme.Auth0);

        ServiceProvider sp = _services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get(Auth0Constants.AuthenticationScheme.Auth0);

        options.Domain.Should().Be("test.auth0.com");
        options.Audience.Should().Be("https://api.example.com");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigureOptions_And_CustomScheme_Should_Register_Options()
    {
        // Act
        Auth0ApiAuthenticationBuilder result =
            _authenticationBuilder.AddAuth0ApiAuthentication("CustomScheme", opts =>
            {
                opts.Domain = "test.auth0.com";
                opts.Audience = "https://api.example.com";
            });

        // Assert
        result.AuthenticationScheme.Should().Be("CustomScheme");

        ServiceProvider sp = _services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>()
            .Get("CustomScheme");

        options.Domain.Should().Be("test.auth0.com");
        options.Audience.Should().Be("https://api.example.com");
    }

    [Fact]
    public void AddAuth0ApiAuthentication_WithConfigureOptions_Null_Should_Throw()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _authenticationBuilder.AddAuth0ApiAuthentication((Action<Auth0ApiOptions>)null!));
    }

    #endregion

    #region ValidateCustomDomainsOptionsTests

    private Auth0ApiAuthenticationBuilder CreateAuth0Builder()
    {
        _services.Configure<Auth0ApiOptions>(Auth0Constants.AuthenticationScheme.Auth0, opts =>
        {
            opts.Domain = "tenant.auth0.com";
            opts.Audience = "https://api.example.com";
        });

        return _authenticationBuilder.AddAuth0ApiAuthentication();
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
