using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Contains
///     <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see>
///     extension(s) for registering Auth0.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    ///     Adds Auth0 API authentication using configuration from an <see cref="IConfigurationSection" />.
    ///     This is the recommended approach as it supports appsettings.json, environment variables,
    ///     and other configuration providers out of the box.
    /// </summary>
    /// <param name="services">The service collection to add authentication to.</param>
    /// <param name="configurationSection">
    ///     The configuration section containing Auth0 settings (Domain and Audience).
    /// </param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this IServiceCollection services,
        IConfigurationSection configurationSection,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentNullException.ThrowIfNull(configurationSection, nameof(configurationSection));

        return services.AddAuth0ApiAuthentication(
            Auth0Constants.AuthenticationScheme.Auth0, configurationSection, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 API authentication using configuration from an <see cref="IConfigurationSection" />
    ///     with a custom authentication scheme.
    /// </summary>
    /// <param name="services">The service collection to add authentication to.</param>
    /// <param name="authenticationScheme">The authentication scheme to use.</param>
    /// <param name="configurationSection">
    ///     The configuration section containing Auth0 settings (Domain and Audience).
    /// </param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this IServiceCollection services,
        string authenticationScheme,
        IConfigurationSection configurationSection,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme, nameof(authenticationScheme));
        ArgumentNullException.ThrowIfNull(configurationSection, nameof(configurationSection));

        services.Configure<Auth0ApiOptions>(authenticationScheme, configurationSection);

        return services
            .AddAuthentication(options => { options.DefaultScheme = authenticationScheme; })
            .AddAuth0ApiAuthentication(authenticationScheme, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 API authentication using a delegate to configure options programmatically.
    /// </summary>
    /// <param name="services">The service collection to add authentication to.</param>
    /// <param name="configureOptions">An action to configure the <see cref="Auth0ApiOptions" />.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this IServiceCollection services,
        Action<Auth0ApiOptions> configureOptions,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

        return services.AddAuth0ApiAuthentication(
            Auth0Constants.AuthenticationScheme.Auth0, configureOptions, configureJwtBearer);
    }

    /// <summary>
    ///     Adds Auth0 API authentication using a delegate to configure options programmatically
    ///     with a custom authentication scheme.
    /// </summary>
    /// <param name="services">The service collection to add authentication to.</param>
    /// <param name="authenticationScheme">The authentication scheme to use.</param>
    /// <param name="configureOptions">An action to configure the <see cref="Auth0ApiOptions" />.</param>
    /// <param name="configureJwtBearer">
    ///     An optional action to further configure the underlying <see cref="JwtBearerOptions" />.
    /// </param>
    /// <returns>An <see cref="Auth0ApiAuthenticationBuilder" /> for further configuration.</returns>
    public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
        this IServiceCollection services,
        string authenticationScheme,
        Action<Auth0ApiOptions> configureOptions,
        Action<JwtBearerOptions>? configureJwtBearer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme, nameof(authenticationScheme));
        ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

        services.Configure<Auth0ApiOptions>(authenticationScheme, configureOptions);

        return services
            .AddAuthentication(options => { options.DefaultScheme = authenticationScheme; })
            .AddAuth0ApiAuthentication(authenticationScheme, configureJwtBearer);
    }
}
