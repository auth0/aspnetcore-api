using System.Runtime.CompilerServices;

using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Auth0.AspNetCore.Authentication.Api.DPoP;
using Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
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
    ///     Adds Auth0 authentication for API using the default Auth0 scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder, Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        return AddAuth0ApiAuthentication(builder, Auth0Constants.AuthenticationScheme.Auth0, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API using configuration from an <see cref="IConfigurationSection" />
    ///     with the default Auth0 scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="configurationSection">
    ///     The configuration section containing Auth0 settings (Domain and Audience).
    /// </param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder,
        IConfigurationSection configurationSection,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        return AddAuth0ApiAuthentication(builder, Auth0Constants.AuthenticationScheme.Auth0, configurationSection,
            configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API using configuration from an <see cref="IConfigurationSection" />
    ///     with a specified authentication scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="authenticationScheme">The authentication scheme to use for Auth0 authentication.</param>
    /// <param name="configurationSection">
    ///     The configuration section containing Auth0 settings (Domain and Audience).
    /// </param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        IConfigurationSection configurationSection,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configurationSection);

        builder.Services.Configure<Auth0ApiOptions>(authenticationScheme, configurationSection);

        return AddAuth0ApiAuthentication(builder, authenticationScheme, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API using a delegate to configure options programmatically
    ///     with the default Auth0 scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="configureOptions">An action to configure the <see cref="Auth0ApiOptions" />.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder,
        Action<Auth0ApiOptions> configureOptions,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        return AddAuth0ApiAuthentication(builder, Auth0Constants.AuthenticationScheme.Auth0, configureOptions,
            configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API using a delegate to configure options programmatically
    ///     with a specified authentication scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="authenticationScheme">The authentication scheme to use for Auth0 authentication.</param>
    /// <param name="configureOptions">An action to configure the <see cref="Auth0ApiOptions" />.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<Auth0ApiOptions> configureOptions,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configureOptions);

        builder.Services.Configure<Auth0ApiOptions>(authenticationScheme, configureOptions);

        return AddAuth0ApiAuthentication(builder, authenticationScheme, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 authentication for API using a specified authentication scheme.
    ///     Auth0ApiOptions must already be registered in the DI container via
    ///     <c>services.Configure&lt;Auth0ApiOptions&gt;</c> before calling this method.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> instance to configure.</param>
    /// <param name="authenticationScheme">The authentication scheme to use for Auth0 authentication.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this AuthenticationBuilder builder, string authenticationScheme,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);

        // Validate Auth0ApiOptions (Domain) at startup
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<Auth0ApiOptions>, Auth0ApiOptionsValidator>());
        builder.Services.AddOptionsWithValidateOnStart<Auth0ApiOptions>(authenticationScheme);

        // Register the JWT Bearer scheme (empty configure — actual config comes from IConfigureNamedOptions below)
        builder.AddJwtBearer(authenticationScheme, _ => { });

        // Register our named options configurator that resolves Auth0ApiOptions at resolution time
        builder.Services.AddSingleton<IConfigureOptions<JwtBearerOptions>>(sp =>
            new Auth0JwtBearerConfigureOptions(
                authenticationScheme,
                sp.GetRequiredService<IOptionsMonitor<Auth0ApiOptions>>(),
                configureJwtBearer));

        // Validate audience on the final JwtBearerOptions — after the user's configureJwtBearer callback
        // has run, so ValidAudiences (multi-audience) is also accepted.
        builder.Services.AddSingleton<IValidateOptions<JwtBearerOptions>>(
            new Auth0JwtBearerOptionsValidator(authenticationScheme));
        builder.Services.AddOptionsWithValidateOnStart<JwtBearerOptions>(authenticationScheme);

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, Auth0JwtBearerPostConfigureOptions>());

        return new Auth0ApiAuthenticationBuilder(builder.Services, authenticationScheme);
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
        return WithDPoP(builder, _ => { });
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
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureDPoPOptions);

        var dPoPOptions = new DPoPOptions();
        configureDPoPOptions(dPoPOptions);

        builder.Services.TryAddSingleton(dPoPOptions);
        builder.Services.TryAddScoped<IDPoPProofValidationService, DPoPProofValidationService>();
        builder.Services.TryAddScoped<DPoP.EventHandlers.MessageReceivedHandler>();
        builder.Services.TryAddScoped<TokenValidationHandler>();
        builder.Services.TryAddScoped<ChallengeHandler>();

        // Configure DPoP events - wraps existing events (user + JwtBearerEventsFactory) with DPoP handlers
        builder.Services.Configure<JwtBearerOptions>(builder.AuthenticationScheme,
            jwtBearerOptions =>
            {
                jwtBearerOptions.Events = DPoPEventsFactory.Create(jwtBearerOptions.Events);
            });

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
        builder.Services.AddHttpClient();

        builder.Services.TryAddSingleton<Auth0CustomDomainsConfigurationManager>();

        // Register event handler for OnMessageReceived validation
        builder.Services.TryAddScoped<CustomDomains.EventHandlers.MessageReceivedHandler>();

        // Configure CustomDomains events - reads current state and chains properly
        builder.Services.Configure<JwtBearerOptions>(builder.AuthenticationScheme, jwtBearerOptions =>
        {
            jwtBearerOptions.Events = CustomDomainsEventsFactory.Create(jwtBearerOptions);
        });

        // Register IPostConfigureOptions for setting ConfigurationManager.
        // Uses AddSingleton with a factory so the scheme name is captured and only the matching scheme is configured.
        // TryAddEnumerable cannot be used with factory registrations as it requires a concrete implementation type.
        builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>>(sp =>
            new Auth0CustomDomainsPostConfigureOptions(
                sp.GetRequiredService<Auth0CustomDomainsConfigurationManager>(),
                builder.AuthenticationScheme));

        return builder;
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

                var domainTrimmed = domain.TrimEnd('/');

                // Determine the hostname portion to validate
                // BuildIssuerUrl supports bare hostnames, https://, and http:// (for testing/localhost)
                string hostname;
                if (domainTrimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    hostname = domainTrimmed[8..];
                }
                else if (domainTrimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    hostname = domainTrimmed[7..];
                }
                else
                {
                    hostname = domainTrimmed;
                }

                if (!Uri.TryCreate($"https://{hostname}", UriKind.Absolute, out Uri? uri)
                    || uri.Host != hostname
                    || uri.PathAndQuery != "/")
                {
                    throw new InvalidOperationException(
                        $"Invalid domain format: '{domain}'. Must be a plain hostname (e.g. 'tenant.auth0.com').");
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
