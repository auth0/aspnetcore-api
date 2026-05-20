using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Validates <see cref="Auth0ApiOptions" /> to ensure required configuration is provided.
///     Validates Domain is set and has a valid hostname format.
///     Audience validation is handled separately by <see cref="Auth0JwtBearerOptionsValidator" />
///     because audience can be provided either via Auth0ApiOptions.Audience or via
///     TokenValidationParameters.ValidAudiences in the configureJwtBearer callback.
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
        else
        {
            var domain = options.Domain.Trim();

            if (domain.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                domain.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(
                    $"Auth0 Domain should be a hostname only (e.g., 'tenant.auth0.com'), not a full URL. " +
                    $"Received: '{options.Domain}'. The 'https://' prefix is added automatically.");
            }
            else if (domain.TrimEnd('/').Contains('/'))
            {
                failures.Add(
                    $"Auth0 Domain should be a hostname only (e.g., 'tenant.auth0.com') without a path. " +
                    $"Received: '{options.Domain}'.");
            }
            else if (domain.Contains(':'))
            {
                failures.Add(
                    $"Auth0 Domain should not contain a port number. " +
                    $"Received: '{options.Domain}'. Use the hostname only (e.g., 'tenant.auth0.com').");
            }
            else if (domain.Contains('?') || domain.Contains('#'))
            {
                failures.Add(
                    $"Auth0 Domain should be a hostname only without query strings or fragments. " +
                    $"Received: '{options.Domain}'.");
            }
            else if (!Uri.TryCreate($"https://{domain}", UriKind.Absolute, out var uri) ||
                     !string.Equals(uri.Host, domain.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(
                    $"Auth0 Domain is not a valid hostname. Expected format: 'tenant.auth0.com'. " +
                    $"Received: '{options.Domain}'.");
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
