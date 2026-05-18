using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Validates <see cref="Auth0ApiOptions" /> to ensure required configuration is provided.
/// </summary>
internal class Auth0ApiOptionsValidator : IValidateOptions<Auth0ApiOptions>
{
    public ValidateOptionsResult Validate(string? name, Auth0ApiOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Domain))
        {
            failures.Add(
                "Auth0 Domain is required. Please set the 'Domain' property in Auth0ApiOptions or the 'Auth0:Domain' configuration key.");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
