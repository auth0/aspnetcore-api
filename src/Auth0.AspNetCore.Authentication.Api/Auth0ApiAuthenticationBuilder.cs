using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Builder to add functionality on top of Auth0 API authentication.
/// </summary>
public class Auth0ApiAuthenticationBuilder
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="Auth0ApiAuthenticationBuilder" /> class
    ///     using the default Auth0 authentication scheme.
    /// </summary>
    /// <param name="services">
    ///     The <see cref="IServiceCollection" /> instance used to register authentication services.
    /// </param>
    public Auth0ApiAuthenticationBuilder(IServiceCollection services) : this(services,
        Auth0Constants.AuthenticationScheme.Auth0)
    {
    }

    /// <summary>
    ///     Constructs an instance of <see cref="Auth0ApiAuthenticationBuilder" />.
    /// </summary>
    /// <param name="services">
    ///     The <see cref="IServiceCollection" /> instance used to register authentication services.
    /// </param>
    /// <param name="authenticationScheme">
    ///     The authentication scheme to use for the Auth0 authentication handler.
    /// </param>
    public Auth0ApiAuthenticationBuilder(IServiceCollection services, string authenticationScheme)
    {
        Services = services;
        AuthenticationScheme = authenticationScheme;
    }

    /// <summary>
    ///     The authentication scheme name.
    /// </summary>
    public string AuthenticationScheme { get; }

    /// <summary>
    ///     The service collection.
    /// </summary>
    public IServiceCollection Services { get; }
}
