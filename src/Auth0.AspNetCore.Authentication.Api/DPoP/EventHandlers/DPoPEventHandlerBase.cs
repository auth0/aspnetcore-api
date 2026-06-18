using System.Net;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

/// <summary>
///     Base class for DPoP event handlers.
///     Provides core methods for extracting and validating DPoP-bound access tokens and headers.
/// </summary>
internal abstract class DPoPEventHandlerBase
{
    /// <summary>
    ///     Extracts the token portion from a DPoP Authorization header by removing the scheme prefix.
    /// </summary>
    /// <param name="authorizationHeader">The complete Authorization header value including the DPoP scheme.</param>
    /// <returns>The token portion of the Authorization header with leading/trailing whitespace removed.</returns>
    /// <exception cref="ArgumentException">Thrown when authorizationHeader is null or empty.</exception>
    internal virtual string ExtractTokenFromAuthorizationHeader(string? authorizationHeader)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizationHeader);
        return authorizationHeader[Auth0Constants.DPoP.AuthenticationScheme.Length..].Trim();
    }

    /// <summary>
    ///     Determines if the <see cref="HttpRequest" /> uses the DPoP authentication scheme.
    ///     Checks if the Authorization header starts with the DPoP scheme as defined in
    ///     <see cref="Auth0Constants.DPoP.AuthenticationScheme" />.
    /// </summary>
    /// <param name="httpRequest">The HTTP request to inspect.</param>
    /// <returns><c>true</c> if the Authorization header uses the DPoP scheme; otherwise, <c>false</c>.</returns>
    internal virtual bool IsDPoPScheme(HttpRequest httpRequest)
    {
        var authorizationHeader = GetAuthorizationHeader(httpRequest);
        return authorizationHeader != null &&
               authorizationHeader.StartsWith(Auth0Constants.DPoP.AuthenticationScheme,
                   StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    ///     Retrieves the value of the Authorization header from the specified <see cref="HttpRequest" />.
    ///     Returns the first value if multiple Authorization headers are present.
    /// </summary>
    /// <param name="httpRequest">The HTTP request to inspect.</param>
    /// <returns>The value of the Authorization header, or <c>null</c> if not present.</returns>
    internal virtual string? GetAuthorizationHeader(HttpRequest httpRequest)
    {
        return httpRequest.Headers.Authorization.FirstOrDefault();
    }

    /// <summary>
    ///     Validates that exactly one Authorization header is present in the request.
    ///     Multiple or missing Authorization headers are considered invalid for DPoP authentication.
    /// </summary>
    /// <param name="httpRequest">The HttpRequest.</param>
    /// <returns><c>true</c> if exactly one Authorization header is present; otherwise, <c>false</c>.</returns>
    internal virtual bool IsValidAuthorizationHeaderCount(HttpRequest httpRequest)
    {
        return httpRequest.Headers.Authorization.Count == 1;
    }

    /// <summary>
    ///     Validates that exactly one DPoP proof header exists in the request with a non-empty value.
    ///     The DPoP proof header is required for DPoP authentication and must contain the proof token.
    /// </summary>
    /// <param name="httpRequest">The HttpRequest</param>
    /// <returns><c>true</c> if exactly one valid DPoP proof header is present; otherwise, <c>false</c>.</returns>
    internal virtual bool IsDPoPProofHeaderExists(HttpRequest httpRequest)
    {
        var dPoPProofHeaders = httpRequest.Headers
            .Where(h => string.Equals(
                h.Key, Auth0Constants.DPoP.ProofHeader, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return dPoPProofHeaders.Count == 1 &&
               dPoPProofHeaders[0].Value.Count == 1 &&
               !string.IsNullOrWhiteSpace(dPoPProofHeaders[0].Value.ToString());
    }

    /// <summary>
    ///     Extracts and validates the DPoP-bound access token from the Authorization header.
    ///     This method performs the core token extraction logic for DPoP authentication,
    ///     ensuring both the access token and DPoP proof header are properly formatted.
    /// </summary>
    /// <param name="httpRequest">
    ///     The Http Request.
    /// </param>
    /// <remarks>
    ///     If any validation fails, the method returns early without setting the token,
    ///     which will cause authentication to fail downstream.
    /// </remarks>
    internal virtual string? ExtractDPoPBoundAccessToken(HttpRequest httpRequest)
    {
        var authorizationHeader = GetAuthorizationHeader(httpRequest);
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return null;
        }

        // Extract the token from the Authorization header
        var extractedToken = ExtractTokenFromAuthorizationHeader(authorizationHeader);

        return string.IsNullOrEmpty(extractedToken) ? null : extractedToken;
    }


    /// <summary>
    ///     Checks if an authorization token exists in the request's Authorization header.
    ///     Supports both DPoP and Bearer schemes by verifying that the token portion is non-empty.
    /// </summary>
    /// <param name="httpRequest">The HTTP request to inspect.</param>
    /// <returns>
    ///     <c>true</c> if a non-empty token exists after the scheme prefix in the Authorization header; otherwise, <c>false</c>.
    /// </returns>
    internal bool IsAuthorizationTokenExists(HttpRequest httpRequest)
    {
        var authorizationHeader = GetAuthorizationHeader(httpRequest);
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return false;
        }

        if (authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authorizationHeader["Bearer ".Length..].Trim().Length > 0;
        }
        else if (authorizationHeader.StartsWith(Auth0Constants.DPoP.AuthenticationScheme,
                     StringComparison.OrdinalIgnoreCase))
        {
            return authorizationHeader[Auth0Constants.DPoP.AuthenticationScheme.Length..].Trim().Length > 0;
        }

        return false;
    }


    /// <summary>
    /// Handles invalid requests in Allowed DPoP mode.
    /// Sets error code and status and fails the authentication context.
    /// </summary>
    /// <param name="context">
    /// The JWT Bearer message received context containing the HTTP request.
    /// </param>
    internal void HandleInvalidRequestInAllowedMode(ResultContext<JwtBearerOptions> context)
    {
        context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorCode] =
            Auth0Constants.DPoP.Error.Code.InvalidRequest;
        context.HttpContext.Items[Auth0Constants.DPoP.BearerStatusCode] = HttpStatusCode.BadRequest;
        context.Fail(Auth0Constants.DPoP.Error.Code.InvalidRequest);
    }

    /// <summary>
    /// Handles invalid requests in Required DPoP mode.
    /// Sets error code and status and fails the authentication context.
    /// </summary>
    /// <param name="context">
    /// The JWT Bearer message received context containing the HTTP request.
    /// </param>
    internal void HandleInvalidRequestInRequiredMode(ResultContext<JwtBearerOptions> context)
    {
        context.HttpContext.Items[Auth0Constants.DPoP.DPoPErrorCode] =
            Auth0Constants.DPoP.Error.Code.InvalidRequest;
        context.HttpContext.Items[Auth0Constants.DPoP.DPoPStatusCode] = HttpStatusCode.BadRequest;
        context.Fail(Auth0Constants.DPoP.Error.Code.InvalidRequest);
    }
}
