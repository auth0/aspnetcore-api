using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains.EventHandlers;

/// <summary>
/// Handles <c>OnMessageReceived</c> event for custom domains validation.
/// Performs pre-network validation to reject invalid tokens before making JWKS calls.
/// </summary>
internal class MessageReceivedHandler(
    Auth0CustomDomainsOptions options,
    ILogger<MessageReceivedHandler> logger)
    : ICustomDomainsEventHandler<MessageReceivedContext>
{
    private readonly Auth0CustomDomainsOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly ILogger<MessageReceivedHandler> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public async Task Handle(MessageReceivedContext context)
    {
        try
        {
            var token = TokenValidationHelper.ExtractToken(context.Request);
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogError("Missing JWT token in Authorization header");
                context.Fail(Auth0Constants.CustomDomains.Error.Description.InvalidToken);
                return;
            }

            if (!TokenValidationHelper.TryDecodeToken(token, out var issuer, out var algorithm))
            {
                _logger.LogError("Failed to decode JWT token");
                context.Fail(Auth0Constants.CustomDomains.Error.Description.InvalidToken);
                return;
            }

            if (TokenValidationHelper.IsSymmetricAlgorithm(algorithm))
            {
                _logger.LogError("Rejected token with symmetric algorithm: {Algorithm}", algorithm);
                context.Fail(Auth0Constants.CustomDomains.Error.Description.SymmetricAlgorithm);
                return;
            }

            if (string.IsNullOrEmpty(issuer))
            {
                _logger.LogError("Token has no issuer claim");
                context.Fail(Auth0Constants.CustomDomains.Error.Description.InvalidIssuer);
                return;
            }

            IReadOnlyList<string>? allowedDomains = await ResolveAllowedDomainsAsync(context.HttpContext);
            if (allowedDomains == null || allowedDomains.Count == 0)
            {
                _logger.LogError("No allowed domains configured for custom domains validation");
                context.Fail(Auth0Constants.CustomDomains.Error.Description.ConfigurationFailed);
                return;
            }

            var validatedIssuer = TokenValidationHelper.ValidateIssuer(issuer, allowedDomains);
            if (validatedIssuer == null)
            {
                _logger.LogError("Token issuer {Issuer} not in allowed domains list", issuer);
                context.Fail(Auth0Constants.CustomDomains.Error.Description.IssuerNotAllowed);
                return;
            }

            _logger.LogDebug("Pre-network validation passed for issuer: {Issuer}", validatedIssuer);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during custom domains validation");
            context.Fail(Auth0Constants.CustomDomains.Error.Description.ConfigurationFailed);
        }
    }

    internal async Task<IReadOnlyList<string>?> ResolveAllowedDomainsAsync(HttpContext httpContext)
    {
        if (_options.DomainsResolver == null)
        {
            return _options.Domains;
        }

        try
        {
            return await _options.DomainsResolver(httpContext, httpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resolving domains from DomainsResolver");
            return null;
        }
    }
}
