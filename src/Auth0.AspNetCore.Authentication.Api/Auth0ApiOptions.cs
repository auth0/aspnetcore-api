namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Configuration options for Auth0 API authentication.
///     This class is designed to be bound from configuration sources such as appsettings.json.
/// </summary>
public class Auth0ApiOptions
{
    /// <summary>
    ///     Auth0 domain name, e.g. tenant.auth0.com.
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    ///     The API identifier (audience) registered in Auth0.
    /// </summary>
    public string Audience { get; set; } = string.Empty;
}
