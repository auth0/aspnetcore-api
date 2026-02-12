using System.Runtime.CompilerServices;

using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Auth0.AspNetCore.Authentication.Api.DPoP;
using Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

[assembly: InternalsVisibleTo("Auth0.AspNetCore.Authentication.Api.UnitTests")]

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Provides extension methods for
///     <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">
///         AuthenticationBuilder
///     </see>
///     to simplify the registration and configuration of Auth0 authentication.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    ///     Adds Auth0 authentication for API
    /// </summary>
    /// <param name="builder">
    ///     The
    ///     <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">
    ///         AuthenticationBuilder
    ///     </see>
    ///     instance to configure.
    /// </param>
    /// <param name="configureOptions">
    ///     A delegate to configure the <see cref="Auth0ApiOptions" /> for Auth0 integration.
    /// </param>
    /// <returns>
    ///     The configured
    ///     <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">
    ///         AuthenticationBuilder
    ///     </see>
    ///     instance.
    /// </returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder, Action<Auth0ApiOptions>? configureOptions)
    {
        return AddAuth0ApiAuthentication(builder, Auth0Constants.AuthenticationScheme.Auth0, configureOptions);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API
    ///     specified <see cref="AuthenticationBuilder" />.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="AuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <param name="authenticationScheme">
    ///     The authentication scheme to use for Auth0 authentication.
    /// </param>
    /// <param name="configureOptions">
    ///     A delegate used to configure the <see cref="Auth0ApiOptions" /> for Auth0 integration.
    /// </param>
    /// <returns>
    ///     The configured <see cref="AuthenticationBuilder" /> instance.
    /// </returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder, string authenticationScheme, Action<Auth0ApiOptions>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var auth0Options = new Auth0ApiOptions();

        configureOptions(auth0Options);

        ValidateAuth0ApiOptions(auth0Options);

        builder.AddJwtBearer(
            authenticationScheme, options => ConfigureJwtBearerOptions(options, auth0Options));

        builder.Services.Configure(authenticationScheme, configureOptions);
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, Auth0JwtBearerPostConfigureOptions>());

        return new Auth0ApiAuthenticationBuilder(builder.Services, authenticationScheme, auth0Options);
    }


    /// <summary>
    ///     Enables DPoP (Demonstration of Proof-of-Possession) support
    ///     with default configuration using the default Auth0 authentication scheme.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="Auth0ApiAuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <returns>
    ///     The configured <see cref="Auth0ApiAuthenticationBuilder" /> instance.
    /// </returns>
    public static Auth0ApiAuthenticationBuilder WithDPoP(
        this Auth0ApiAuthenticationBuilder builder)
    {
        return WithDPoP(builder, Auth0Constants.AuthenticationScheme.Auth0);
    }

    /// <summary>
    ///     Enables DPoP (Demonstration of Proof-of-Possession) support
    ///     with default configuration using a specified authentication scheme.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="Auth0ApiAuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <param name="authenticationScheme">
    ///     The authentication scheme to use for DPoP integration.
    /// </param>
    /// <returns>
    ///     The configured <see cref="Auth0ApiAuthenticationBuilder" /> instance.
    /// </returns>
    public static Auth0ApiAuthenticationBuilder WithDPoP(
        this Auth0ApiAuthenticationBuilder builder,
        string authenticationScheme)
    {
        return WithDPoP(builder, authenticationScheme, _ => { });
    }

    /// <summary>
    ///     Enables DPoP (Demonstration of Proof-of-Possession) support
    ///     using the default Auth0 authentication scheme.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="Auth0ApiAuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <param name="configureDPoPOptions">
    ///     A delegate to configure the <see cref="DPoPOptions" /> for DPoP integration.
    /// </param>
    /// <returns>
    ///     The configured <see cref="Auth0ApiAuthenticationBuilder" /> instance.
    /// </returns>
    public static Auth0ApiAuthenticationBuilder WithDPoP(
        this Auth0ApiAuthenticationBuilder builder,
        Action<DPoPOptions> configureDPoPOptions)
    {
        return WithDPoP(builder, Auth0Constants.AuthenticationScheme.Auth0, configureDPoPOptions);
    }

    /// <summary>
    ///     Enables DPoP (Demonstration of Proof-of-Possession) support for the Auth0 API authentication builder
    ///     using a specified authentication scheme.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="Auth0ApiAuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <param name="authenticationScheme">
    ///     The authentication scheme to use for DPoP integration.
    /// </param>
    /// <param name="configureDPoPOptions">
    ///     A delegate to configure the <see cref="DPoPOptions" /> for DPoP integration.
    /// </param>
    /// <returns>
    ///     The configured <see cref="Auth0ApiAuthenticationBuilder" /> instance.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    ///     Thrown when <paramref name="builder" /> or
    ///     <paramref name="configureDPoPOptions" /> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Thrown when <paramref name="authenticationScheme" /> is empty or null.
    /// </exception>
    public static Auth0ApiAuthenticationBuilder WithDPoP(
        this Auth0ApiAuthenticationBuilder builder,
        string authenticationScheme,
        Action<DPoPOptions> configureDPoPOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configureDPoPOptions);

        var dPoPOptions = new DPoPOptions();
        configureDPoPOptions(dPoPOptions);

        builder.Services.Configure<JwtBearerOptions>(builder.AuthenticationScheme,
            jwtBearerOptions => { jwtBearerOptions.Events = DPoPEventsFactory.Create(builder.Options); });

        builder.Services.TryAddSingleton(dPoPOptions);
        builder.Services.TryAddScoped<IDPoPProofValidationService, DPoPProofValidationService>();
        builder.Services.TryAddScoped<MessageReceivedHandler>();
        builder.Services.TryAddScoped<TokenValidationHandler>();
        builder.Services.TryAddScoped<ChallengeHandler>();
        return builder;
    }

    /// <summary>
    ///     Configures custom domains options for Auth0 API authentication.
    /// </summary>
    /// <param name="builder">
    ///     The <see cref="Auth0ApiAuthenticationBuilder" /> instance to configure.
    /// </param>
    /// <param name="configureOptions">
    ///     A delegate to configure the <see cref="Auth0CustomDomainsOptions" /> for custom domains integration.
    /// </param>
    /// <returns>
    ///     The configured <see cref="Auth0ApiAuthenticationBuilder" /> instance.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    ///     Thrown when <paramref name="builder" /> is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when custom domains configuration is invalid.
    /// </exception>
    public static Auth0ApiAuthenticationBuilder WithCustomDomains(
        this Auth0ApiAuthenticationBuilder builder,
        Action<Auth0CustomDomainsOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new Auth0CustomDomainsOptions();
        configureOptions?.Invoke(options);

        ValidateCustomDomainsOptions(options);

        // Use default cache if none specified
        options.ConfigurationManagerCache ??= new MemoryConfigurationManagerCache(slidingExpiration: TimeSpan.FromMinutes(10));

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(options.ConfigurationManagerCache);
        builder.Services.AddHttpContextAccessor();

        builder.Services.TryAddSingleton<Auth0CustomDomainsConfigurationManager>();

        // Register event handler for OnMessageReceived validation
        builder.Services.TryAddScoped<CustomDomains.EventHandlers.MessageReceivedHandler>();

        builder.Services.Configure<JwtBearerOptions>(builder.AuthenticationScheme, jwtBearerOptions =>
        {
            // Chain custom domains validation before any existing event handlers (user or DPoP)
            // The handler will be resolved from DI at runtime during the event execution
            jwtBearerOptions.Events = CustomDomainsEventsFactory.Create(
                jwtBearerOptions.Events);
        });

        // Register IPostConfigureOptions for setting ConfigurationManager
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>,
                Auth0CustomDomainsPostConfigureOptions>());

        return builder;
    }

    /// <summary>
    ///     Configures the <see cref="JwtBearerOptions" /> instance using the provided <see cref="Auth0ApiOptions" />.
    /// </summary>
    internal static void ConfigureJwtBearerOptions(JwtBearerOptions? jwtBearerOptions, Auth0ApiOptions? auth0ApiOptions)
    {
        ArgumentNullException.ThrowIfNull(jwtBearerOptions);
        ArgumentNullException.ThrowIfNull(auth0ApiOptions);
        ArgumentNullException.ThrowIfNull(auth0ApiOptions.JwtBearerOptions);

        jwtBearerOptions.ClaimsIssuer = auth0ApiOptions.JwtBearerOptions.ClaimsIssuer;
        jwtBearerOptions.TimeProvider = auth0ApiOptions.JwtBearerOptions.TimeProvider;

        jwtBearerOptions.Authority = $"https://{auth0ApiOptions.Domain}";
        jwtBearerOptions.Audience = auth0ApiOptions.JwtBearerOptions.Audience;
        jwtBearerOptions.Challenge = auth0ApiOptions.JwtBearerOptions.Challenge;
        jwtBearerOptions.SaveToken = auth0ApiOptions.JwtBearerOptions.SaveToken;
        jwtBearerOptions.IncludeErrorDetails = auth0ApiOptions.JwtBearerOptions.IncludeErrorDetails;
        jwtBearerOptions.RequireHttpsMetadata = auth0ApiOptions.JwtBearerOptions.RequireHttpsMetadata;
        jwtBearerOptions.MetadataAddress = auth0ApiOptions.JwtBearerOptions.MetadataAddress;
        jwtBearerOptions.Configuration = auth0ApiOptions.JwtBearerOptions.Configuration;
        jwtBearerOptions.ConfigurationManager = auth0ApiOptions.JwtBearerOptions.ConfigurationManager;
        jwtBearerOptions.RefreshOnIssuerKeyNotFound = auth0ApiOptions.JwtBearerOptions.RefreshOnIssuerKeyNotFound;
        jwtBearerOptions.MapInboundClaims = auth0ApiOptions.JwtBearerOptions.MapInboundClaims;
        jwtBearerOptions.BackchannelTimeout = auth0ApiOptions.JwtBearerOptions.BackchannelTimeout;
        jwtBearerOptions.BackchannelHttpHandler = auth0ApiOptions.JwtBearerOptions.BackchannelHttpHandler;
        jwtBearerOptions.Backchannel = auth0ApiOptions.JwtBearerOptions.Backchannel;
        jwtBearerOptions.AutomaticRefreshInterval = auth0ApiOptions.JwtBearerOptions.AutomaticRefreshInterval;
        jwtBearerOptions.RefreshInterval = auth0ApiOptions.JwtBearerOptions.RefreshInterval;
        jwtBearerOptions.UseSecurityTokenValidators = auth0ApiOptions.JwtBearerOptions.UseSecurityTokenValidators;

        jwtBearerOptions.ForwardDefault = auth0ApiOptions.JwtBearerOptions.ForwardDefault;
        jwtBearerOptions.ForwardAuthenticate = auth0ApiOptions.JwtBearerOptions.ForwardAuthenticate;
        jwtBearerOptions.ForwardChallenge = auth0ApiOptions.JwtBearerOptions.ForwardChallenge;
        jwtBearerOptions.ForwardForbid = auth0ApiOptions.JwtBearerOptions.ForwardForbid;
        jwtBearerOptions.ForwardSignIn = auth0ApiOptions.JwtBearerOptions.ForwardSignIn;
        jwtBearerOptions.ForwardSignOut = auth0ApiOptions.JwtBearerOptions.ForwardSignOut;
        jwtBearerOptions.ForwardDefaultSelector = auth0ApiOptions.JwtBearerOptions.ForwardDefaultSelector;

        jwtBearerOptions.TokenValidationParameters = auth0ApiOptions.JwtBearerOptions.TokenValidationParameters;
        jwtBearerOptions.Events = JwtBearerEventsFactory.Create(auth0ApiOptions);
    }

    /// <summary>
    ///     Validates the Auth0 configuration options.
    /// </summary>
    /// <param name="options">The <see cref="Auth0ApiOptions" /> to validate.</param>
    /// <exception cref="InvalidOperationException">Thrown when required Auth0 configuration is missing or invalid.</exception>
    internal static void ValidateAuth0ApiOptions(Auth0ApiOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Domain))
        {
            throw new InvalidOperationException(
                "Auth0 Domain is required. Please set the Domain property in Auth0ApiOptions.");
        }

        if (string.IsNullOrWhiteSpace(options.JwtBearerOptions?.Audience))
        {
            throw new InvalidOperationException(
                "Auth0 Audience is required. Please set the Audience property in Auth0ApiOptions.");
        }
    }

    /// <summary>
    ///     Validates the custom domains configuration options.
    /// </summary>
    /// <param name="options">The <see cref="Auth0CustomDomainsOptions" /> to validate.</param>
    /// <exception cref="InvalidOperationException">Thrown when custom domains configuration is invalid.</exception>
    private static void ValidateCustomDomainsOptions(Auth0CustomDomainsOptions options)
    {
        // Mutually exclusive check
        if (options.Domains?.Count > 0 && options.DomainsResolver != null)
        {
            throw new InvalidOperationException(
                "Cannot configure both Domains and DomainsResolver. Choose one approach.");
        }

        // At least one must be configured when using custom domains
        if ((options.Domains == null || options.Domains.Count == 0) && options.DomainsResolver == null)
        {
            throw new InvalidOperationException(
                "When using .WithCustomDomains(), you must configure either Domains or DomainsResolver.");
        }

        // Validate domain formats in Domains list
        if (options.Domains != null)
        {
            foreach (var domain in options.Domains)
            {
                if (string.IsNullOrWhiteSpace(domain))
                {
                    throw new InvalidOperationException(
                        "Domains list contains null or empty entries.");
                }
            }
        }

        // Validate intervals
        if (options.AutomaticRefreshInterval <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "AutomaticRefreshInterval must be greater than zero.");
        }

        if (options.RefreshInterval <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "RefreshInterval must be greater than zero.");
        }
    }
}
