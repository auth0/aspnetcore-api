using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// Post-configures <see cref="JwtBearerOptions"/> to enable Auth0 custom domains support.
/// Injects the singleton <see cref="Auth0CustomDomainsConfigurationManager"/>
/// </summary>
internal sealed class Auth0CustomDomainsPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly Auth0CustomDomainsConfigurationManager _configurationManager;
    private readonly string _authenticationScheme;

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0CustomDomainsPostConfigureOptions"/> class.
    /// </summary>
    /// <param name="configurationManager">
    /// The singleton configuration manager instance registered in DI.
    /// </param>
    /// <param name="authenticationScheme">
    /// The authentication scheme this instance is scoped to. Only <see cref="JwtBearerOptions"/>
    /// registered under this scheme will have their <c>ConfigurationManager</c> replaced.
    /// </param>
    public Auth0CustomDomainsPostConfigureOptions(
        Auth0CustomDomainsConfigurationManager configurationManager,
        string authenticationScheme)
    {
        _configurationManager = configurationManager ?? throw new ArgumentNullException(nameof(configurationManager));
        _authenticationScheme = authenticationScheme ?? throw new ArgumentNullException(nameof(authenticationScheme));
    }

    /// <summary>
    /// Post-configures the JwtBearerOptions by injecting the configuration manager.
    /// Only applies to the authentication scheme this instance was registered for.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The JwtBearerOptions instance to configure.</param>
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, _authenticationScheme, StringComparison.Ordinal))
            return;
        options.ConfigurationManager = _configurationManager;
    }
}
