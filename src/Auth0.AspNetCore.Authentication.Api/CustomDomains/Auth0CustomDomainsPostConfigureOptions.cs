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

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0CustomDomainsPostConfigureOptions"/> class.
    /// </summary>
    /// <param name="configurationManager">
    /// The singleton configuration manager instance registered in DI.
    /// </param>
    public Auth0CustomDomainsPostConfigureOptions(
        Auth0CustomDomainsConfigurationManager configurationManager)
    {
        _configurationManager = configurationManager ?? throw new ArgumentNullException(nameof(configurationManager));
    }

    /// <summary>
    /// Post-configures the JwtBearerOptions by injecting the configuration manager.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The JwtBearerOptions instance to configure.</param>
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.ConfigurationManager = _configurationManager;
    }
}
