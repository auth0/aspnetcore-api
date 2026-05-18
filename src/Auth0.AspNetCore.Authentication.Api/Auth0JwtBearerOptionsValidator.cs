using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Validates that audience is configured on the final <see cref="JwtBearerOptions" />,
///     after all <see cref="IConfigureOptions{TOptions}" /> (including the user's configureJwtBearer callback)
///     have been applied. This correctly handles both the single-audience case (via
///     <see cref="Auth0ApiOptions.Audience" /> or <see cref="JwtBearerOptions.Audience" />) and
///     the multi-audience case (via <see cref="Microsoft.IdentityModel.Tokens.TokenValidationParameters.ValidAudiences" />).
/// </summary>
internal class Auth0JwtBearerOptionsValidator : IValidateOptions<JwtBearerOptions>
{
    private readonly string _authenticationScheme;

    public Auth0JwtBearerOptionsValidator(string authenticationScheme)
    {
        _authenticationScheme = authenticationScheme;
    }

    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, _authenticationScheme, StringComparison.Ordinal))
        {
            return ValidateOptionsResult.Skip;
        }

        var hasAudience = !string.IsNullOrWhiteSpace(options.Audience);
        var hasValidAudiences = options.TokenValidationParameters?.ValidAudiences?.Any() == true;

        if (!hasAudience && !hasValidAudiences)
        {
            return ValidateOptionsResult.Fail(
                "Audience is required. Either set the 'Audience' property in Auth0ApiOptions (or 'Auth0:Audience' in appsettings.json), " +
                "or configure 'TokenValidationParameters.ValidAudiences' via the configureJwtBearer callback for multiple audiences.");
        }

        return ValidateOptionsResult.Success;
    }
}
