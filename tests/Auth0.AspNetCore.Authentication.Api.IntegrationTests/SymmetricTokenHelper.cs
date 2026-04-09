using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.Api.IntegrationTests;

/// <summary>
/// Helper class to create malformed JWT tokens for negative testing.
/// </summary>
public static class SymmetricTokenHelper
{
    /// <summary>
    /// Creates a JWT token signed with HS256 (symmetric algorithm).
    /// This should be rejected by the custom domains implementation.
    /// </summary>
    public static string CreateHS256Token(string issuer, string audience)
    {
        var securityKey = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new Claim("sub", "test-user") },
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates a malformed JWT token (not a valid 3-part structure).
    /// </summary>
    public static string CreateMalformedToken()
    {
        return "this.is.not.a.valid.jwt.token.structure";
    }

    /// <summary>
    /// Creates an expired JWT token.
    /// </summary>
    public static string CreateExpiredToken(string issuer, string audience)
    {
        var securityKey = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new Claim("sub", "test-user") },
            expires: DateTime.UtcNow.AddHours(-1), // Expired 1 hour ago
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates a JWT token with a custom issuer (for testing issuer validation).
    /// </summary>
    public static string CreateTokenWithCustomIssuer(string issuer, string audience, string algorithm = "HS256")
    {
        var securityKey = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(securityKey,
            algorithm == "HS256" ? SecurityAlgorithms.HmacSha256 : SecurityAlgorithms.HmacSha384);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new Claim("sub", "test-user") },
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        // Override the algorithm in the header if needed
        token.Header["alg"] = algorithm;

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
