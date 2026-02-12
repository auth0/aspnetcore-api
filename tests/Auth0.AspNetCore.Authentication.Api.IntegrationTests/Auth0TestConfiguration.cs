using Microsoft.Extensions.Configuration;

namespace Auth0.AspNetCore.Authentication.Api.IntegrationTests;

/// <summary>
/// Provides centralized configuration for integration tests.
/// Reads configuration from client-secrets.json (for local development) and environment variables (for CI/CD).
/// Environment variables take precedence over JSON file settings.
/// </summary>
public abstract class Auth0TestConfiguration
{
    /// <summary>
    /// Shared configuration root for all integration tests.
    /// Reads from client-secrets.json (optional) and environment variables.
    /// </summary>
    public static readonly IConfigurationRoot Config = new ConfigurationBuilder()
        .AddJsonFile("client-secrets.json", optional: true)
        .AddEnvironmentVariables()
        .Build();

    /// <summary>
    /// Gets the configuration for the scenario without DPoP.
    /// </summary>
    public static Auth0Scenario WithoutDPoP => new Auth0Scenario("BASIC");

    /// <summary>
    /// Gets the configuration for the scenario with DPoP in allowed mode.
    /// </summary>
    public static Auth0Scenario WithDPoPAllowed => new Auth0Scenario("DPOP_ALLOWED");

    /// <summary>
    /// Gets the configuration for the scenario with DPoP in required mode.
    /// </summary>
    public static Auth0Scenario WithDPoPRequired => new Auth0Scenario("DPOP_REQUIRED");

    /// <summary>
    /// Gets the configuration for custom domain 1.
    /// </summary>
    public static Auth0Scenario CustomDomain1 => new Auth0Scenario("CUSTOM_DOMAIN_1");

    /// <summary>
    /// Gets the configuration for custom domain 2.
    /// </summary>
    public static Auth0Scenario CustomDomain2 => new Auth0Scenario("CUSTOM_DOMAIN_2");
}

/// <summary>
/// Represents a test scenario with Auth0 configuration.
/// </summary>
public class Auth0Scenario
{
    private readonly string _prefix;

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0Scenario"/> class.
    /// </summary>
    /// <param name="prefix">The prefix for environment variable names (e.g., BASIC, DPOP_ALLOWED, DPOP_REQUIRED).</param>
    public Auth0Scenario(string prefix)
    {
        _prefix = prefix;
    }

    /// <summary>
    /// Gets the Auth0 domain for this scenario.
    /// </summary>
    public string Domain => GetRequiredConfigValue("DOMAIN");

    /// <summary>
    /// Gets the Auth0 audience for this scenario.
    /// </summary>
    public string Audience => GetRequiredConfigValue("AUDIENCE");

    /// <summary>
    /// Gets the Auth0 client ID for this scenario.
    /// </summary>
    public string ClientId => GetRequiredConfigValue("CLIENT_ID");

    /// <summary>
    /// Gets the Auth0 client secret for this scenario.
    /// </summary>
    public string ClientSecret => GetRequiredConfigValue("CLIENT_SECRET");

    /// <summary>
    /// Gets the DPoP mode for this scenario (None, Allowed, Required).
    /// </summary>
    public string DPoPMode => GetConfigValue("DPOP_MODE") ?? "None";

    /// <summary>
    /// Gets whether DPoP is enabled for this scenario.
    /// </summary>
    public bool IsDPoPEnabled => DPoPMode != "None";

    /// <summary>
    /// Gets whether DPoP is required for this scenario.
    /// </summary>
    public bool IsDPoPRequired => DPoPMode == "Required";

    /// <summary>
    /// Gets a required configuration value or throws an exception if it's not set.
    /// </summary>
    /// <param name="suffix">The configuration key suffix (e.g., DOMAIN, AUDIENCE).</param>
    /// <returns>The configuration value.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the configuration value is not set or is empty.</exception>
    private string GetRequiredConfigValue(string suffix)
    {
        var key = $"{_prefix}_{suffix}";
        var value = Auth0TestConfiguration.Config[key];

        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException(
                $"{key} configuration value is required for integration tests. ");
        }

        return value;
    }

    /// <summary>
    /// Gets an optional configuration value.
    /// </summary>
    /// <param name="suffix">The configuration key suffix (e.g., DPOP_MODE).</param>
    /// <returns>The configuration value or null if not set.</returns>
    private string? GetConfigValue(string suffix)
    {
        var key = $"{_prefix}_{suffix}";
        return Auth0TestConfiguration.Config[key];
    }
}
