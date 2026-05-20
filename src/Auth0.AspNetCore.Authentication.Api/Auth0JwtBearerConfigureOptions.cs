using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Configures <see cref="JwtBearerOptions" /> using values from <see cref="Auth0ApiOptions" />
///     resolved at options resolution time (not at registration time).
/// </summary>
internal class Auth0JwtBearerConfigureOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly string _authenticationScheme;
    private readonly IOptionsMonitor<Auth0ApiOptions> _auth0OptionsMonitor;
    private readonly Action<JwtBearerOptions>? _configureJwtBearer;

    public Auth0JwtBearerConfigureOptions(
        string authenticationScheme,
        IOptionsMonitor<Auth0ApiOptions> auth0OptionsMonitor,
        Action<JwtBearerOptions>? configureJwtBearer)
    {
        _authenticationScheme = authenticationScheme;
        _auth0OptionsMonitor = auth0OptionsMonitor;
        _configureJwtBearer = configureJwtBearer;
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, _authenticationScheme, StringComparison.Ordinal))
        {
            return;
        }

        var auth0Options = _auth0OptionsMonitor.Get(_authenticationScheme);

        // Set Authority and Audience from Auth0 options
        options.Authority = $"https://{auth0Options.Domain}";
        options.Audience = auth0Options.Audience;

        // Apply user's custom JWT Bearer configuration
        _configureJwtBearer?.Invoke(options);

        // Wrap all events (user-configured + defaults) for proper chaining
        options.Events = JwtBearerEventsFactory.Create(options.Events);
    }

    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }
}
