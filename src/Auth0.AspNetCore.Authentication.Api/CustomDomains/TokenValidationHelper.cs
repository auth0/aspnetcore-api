using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// Provides helper methods for JWT token extraction and validation in custom domains scenarios.
/// </summary>
internal static class TokenValidationHelper
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    /// <summary>
    /// Extracts the access token from the Authorization header.
    /// </summary>
    /// <param name="request">The HTTP request containing the Authorization header.</param>
    /// <returns>
    /// The extracted token if found and valid; otherwise, <c>null</c>.
    /// Supports both "Bearer" and "DPoP" authentication schemes.
    /// </returns>
    internal static string? ExtractToken(HttpRequest request)
    {
        var authorization = request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authorization))
        {
            return null;
        }

        if (authorization.StartsWith(Auth0Constants.AuthenticationScheme.Bearer, StringComparison.OrdinalIgnoreCase))
        {
            return authorization[Auth0Constants.AuthenticationScheme.Bearer.Length..].Trim();
        }

        if (authorization.StartsWith(Auth0Constants.DPoP.AuthenticationScheme, StringComparison.OrdinalIgnoreCase))
        {
            return authorization[Auth0Constants.DPoP.AuthenticationScheme.Length..].Trim();
        }

        return null;
    }

    /// <summary>
    /// Extracts the access token from the Authorization header using HttpContext.
    /// </summary>
    /// <param name="httpContext">The HTTP context containing the request.</param>
    /// <returns>
    /// The extracted token if found and valid; otherwise, <c>null</c>.
    /// Supports both "Bearer" and "DPoP" authentication schemes.
    /// </returns>
    internal static string? ExtractToken(HttpContext httpContext)
    {
        return ExtractToken(httpContext.Request);
    }

    /// <summary>
    /// Attempts to decode a JWT token without verifying its signature.
    /// </summary>
    /// <param name="token">The JWT token string to decode.</param>
    /// <param name="issuer">When successful, contains the issuer claim from the token; otherwise, <c>null</c>.</param>
    /// <param name="algorithm">When successful, contains the signing algorithm from the token header; otherwise, <c>null</c>.</param>
    /// <returns>
    /// <c>true</c> if the token was successfully decoded; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method only decodes the token structure without validating the signature.
    /// Any exceptions during decoding are caught and result in a <c>false</c> return value.
    /// Uses the modern <see cref="JsonWebTokenHandler"/> for optimal performance.
    /// </remarks>
    internal static bool TryDecodeToken(string token, out string? issuer, out string? algorithm)
    {
        issuer = null;
        algorithm = null;
        try
        {
            JsonWebToken? jwt = TokenHandler.ReadJsonWebToken(token);
            issuer = jwt.Issuer;
            algorithm = jwt.Alg;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether the specified algorithm is a symmetric signing algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier from the JWT header.</param>
    /// <returns>
    /// <c>true</c> if the algorithm is symmetric (e.g., HS256, HS384, HS512); otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// Symmetric algorithms (HMAC-based) are not supported for custom domains validation
    /// as they require a shared secret and cannot be validated using public JWKS.
    /// </remarks>
    internal static bool IsSymmetricAlgorithm(string? algorithm)
    {
        return !string.IsNullOrEmpty(algorithm) &&
               algorithm.StartsWith("HS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates that the token's issuer matches one of the allowed domains.
    /// </summary>
    /// <param name="issuer">The issuer claim from the JWT token.</param>
    /// <param name="allowedDomains">The list of allowed Auth0 domains.</param>
    /// <returns>
    /// The normalized issuer URL if validation succeeds; otherwise, <c>null</c>.
    /// </returns>
    /// <remarks>
    /// The validation performs case-insensitive comparison and handles trailing slashes.
    /// Domains in the allowed list can be specified with or without the "https://" prefix.
    /// </remarks>
    internal static string? ValidateIssuer(string? issuer, IReadOnlyList<string> allowedDomains)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        var normalizedIssuer = issuer.TrimEnd('/');

        foreach (var domain in allowedDomains)
        {
            var expectedIssuer = BuildIssuerUrl(domain);
            if (string.Equals(normalizedIssuer, expectedIssuer, StringComparison.OrdinalIgnoreCase))
            {
                return expectedIssuer;
            }
        }

        return null;
    }

    /// <summary>
    /// Builds a normalized issuer URL from a domain string.
    /// </summary>
    /// <param name="domain">
    /// The domain string, which may or may not include the "https://" prefix.
    /// </param>
    /// <returns>
    /// A normalized HTTPS URL with no trailing slash.
    /// </returns>
    /// <remarks>
    /// If the domain already starts with "https://", it is returned with trailing slashes removed.
    /// Otherwise, "https://" is prepended to the domain.
    /// </remarks>
    internal static string BuildIssuerUrl(string domain)
    {
        if (domain.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return domain.TrimEnd('/');
        }
        return $"https://{domain.TrimEnd('/')}";
    }
}
