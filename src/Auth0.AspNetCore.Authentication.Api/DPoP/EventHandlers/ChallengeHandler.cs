using System.Net;
using System.Text;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

/// <summary>
/// Handles JWT Bearer challenge events for DPoP authentication scenarios.
/// Generates appropriate WWW-Authenticate headers based on DPoP mode and error conditions.
/// </summary>
internal class ChallengeHandler : DPoPEventHandlerBase, IDPoPEventHandler<JwtBearerChallengeContext>
{
    private static readonly string DefaultDPoPHeader = $"DPoP {Auth0Constants.DPoP.Error.DefaultDPoPAlgs}";
    private readonly ILogger<ChallengeHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChallengeHandler"/> class.
    /// </summary>
    /// <param name="logger">The logger instance for logging operations.</param>
    public ChallengeHandler(ILogger<ChallengeHandler> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ChallengeHandler"/> class without a logger.
    /// This constructor is maintained for backward compatibility.
    /// </summary>
    internal ChallengeHandler() : this(Microsoft.Extensions.Logging.Abstractions.NullLogger<ChallengeHandler>.Instance)
    {
    }

    /// <summary>
    /// Handles the JWT Bearer challenge by routing to the appropriate mode-specific handler.
    /// </summary>
    /// <param name="context">The JWT Bearer challenge context containing request and response information.</param>
    /// <returns>A completed task.</returns>
    public Task Handle(JwtBearerChallengeContext? context)
    {
        ArgumentNullException.ThrowIfNull(context);

        DPoPOptions dPoPOptions = context.HttpContext.RequestServices.GetRequiredService<DPoPOptions>();
        return dPoPOptions.Mode switch
        {
            DPoPModes.Disabled => HandleDisabledMode(context),
            DPoPModes.Allowed => HandleAllowedMode(context),
            DPoPModes.Required => HandleRequiredMode(context),
            _ => Task.CompletedTask
        };
    }

    internal virtual Task HandleDisabledMode(JwtBearerChallengeContext context)
    {
        return Task.CompletedTask;
    }

    internal virtual Task HandleRequiredMode(JwtBearerChallengeContext context)
    {
        if (context.HttpContext.Items.ContainsKey(Auth0Constants.DPoP.DPoPErrorCode))
        {
            BuildDPoPAuthenticateHeader(context);
        }

        return Task.CompletedTask;
    }

    internal virtual Task HandleAllowedMode(JwtBearerChallengeContext context)
    {
        // Always include the DPoP algs in the response
        context.Response.Headers.Append(Auth0Constants.DPoP.WWWAuthenticateHeader, DefaultDPoPHeader);

        if (context.HttpContext.Items.ContainsKey(Auth0Constants.DPoP.BearerErrorCode))
        {
            BuildBearerAuthenticateHeader(context);
        }
        if (context.HttpContext.Items.ContainsKey(Auth0Constants.DPoP.DPoPErrorCode))
        {
            BuildDPoPAuthenticateHeader(context);
        }

        return Task.CompletedTask;
    }

    internal void BuildBearerAuthenticateHeader(JwtBearerChallengeContext context)
    {
        var headerConfig = new AuthenticateHeaderConfig(
            Auth0Constants.DPoP.Error.BearerScheme,
            Auth0Constants.DPoP.BearerErrorCode,
            Auth0Constants.DPoP.BearerErrorDescription,
            Auth0Constants.DPoP.BearerStatusCode,
            includeRealm: true
        );

        BuildAuthenticateHeader(context, headerConfig);
    }

    internal void BuildDPoPAuthenticateHeader(JwtBearerChallengeContext context)
    {
        var headerConfig = new AuthenticateHeaderConfig(
            Auth0Constants.DPoP.Error.DPoPScheme,
            Auth0Constants.DPoP.DPoPErrorCode,
            Auth0Constants.DPoP.DPoPErrorDescription,
            Auth0Constants.DPoP.DPoPStatusCode,
            includeRealm: false
        );

        BuildAuthenticateHeader(context, headerConfig);
    }

    /// <summary>
    /// Builds and appends the WWW-Authenticate header for the HTTP response.
    /// </summary>
    /// <param name="context">The JWT Bearer challenge context.</param>
    /// <param name="config">Configuration specifying header format and content.</param>
    internal virtual void BuildAuthenticateHeader(JwtBearerChallengeContext context, AuthenticateHeaderConfig config)
    {
        TryGetItem(context, config.ErrorCodeKey, out var errorCode);
        TryGetItem(context, config.ErrorDescriptionKey, out var errorDescription);
        TryGetItem(context, config.StatusCodeKey, out var statusCode);

        // Ensure status code is valid HTTP status code
        HttpStatusCode httpStatusCode = statusCode as HttpStatusCode? ?? HttpStatusCode.BadRequest;
        context.Response.StatusCode = (int)httpStatusCode;

        var sb = new StringBuilder(config.Scheme);
        PopulateWwwAuthenticateHeader(sb, errorCode, errorDescription);

        if (config.IncludeRealm &&
            string.IsNullOrWhiteSpace(errorCode?.ToString()) &&
            string.IsNullOrWhiteSpace(errorDescription?.ToString()))
        {
            // adding realm only if no error or description is provided.
            sb.Append(' ').Append(Auth0Constants.DPoP.Error.DefaultRealm);
        }

        context.Response.Headers.Append(Auth0Constants.DPoP.WWWAuthenticateHeader, sb.ToString());
        context.HandleResponse();
    }

    /// <summary>
    /// Populates the WWW-Authenticate header with error code and description.
    /// Sanitizes input to prevent header injection attacks.
    /// </summary>
    /// <param name="builder">The StringBuilder to append to.</param>
    /// <param name="errorCode">The error code to include.</param>
    /// <param name="errorDescription">The error description to include.</param>
    internal void PopulateWwwAuthenticateHeader(StringBuilder builder, object? errorCode, object? errorDescription)
    {
        var code = SanitizeHeaderValue(errorCode?.ToString());
        var description = SanitizeHeaderValue(errorDescription?.ToString());

        if (!string.IsNullOrWhiteSpace(code))
        {
            builder.Append(" error=\"")
                .Append(code)
                .Append('\"');
        }

        if (!string.IsNullOrWhiteSpace(description))
        {
            if (!string.IsNullOrWhiteSpace(code))
            {
                // Append a comma only if error code was already added
                builder.Append(',');
            }

            builder.Append(" error_description=\"")
                .Append(description)
                .Append('\"');
        }
    }

    /// <summary>
    /// Sanitizes header values to prevent header injection attacks.
    /// </summary>
    /// <param name="value">The value to sanitize.</param>
    private static string? SanitizeHeaderValue(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        // Remove characters that could be used for header injection
        return value.Replace('\r', ' ')
                   .Replace('\n', ' ')
                   .Replace('\t', ' ')
                   .Replace('"', '\'');
    }

    /// <summary>
    /// Retrieves an item from the HTTP context items dictionary.
    /// </summary>
    /// <param name="context">The JWT Bearer challenge context.</param>
    /// <param name="key">The key to look up in the items dictionary.</param>
    /// <param name="output">The retrieved value, or null if not found.</param>
    private static void TryGetItem(JwtBearerChallengeContext context, string key, out object? output)
    {
        context.HttpContext.Items.TryGetValue(key, out output);
    }

    /// <summary>
    /// Configuration for building WWW-Authenticate headers.
    /// Encapsulates the scheme, error keys, and formatting options.
    /// </summary>
    /// <param name="scheme">The authentication scheme (Bearer or DPoP).</param>
    /// <param name="errorCodeKey">The key for retrieving error code from context items.</param>
    /// <param name="errorDescriptionKey">The key for retrieving error description from context items.</param>
    /// <param name="statusCodeKey">The key for retrieving HTTP status code from context items.</param>
    /// <param name="includeRealm">Whether to include a realm directive when no errors are present.</param>
    internal readonly struct AuthenticateHeaderConfig(
        string scheme,
        string errorCodeKey,
        string errorDescriptionKey,
        string statusCodeKey,
        bool includeRealm)
    {
        public string Scheme { get; } = scheme;
        public string ErrorCodeKey { get; } = errorCodeKey;
        public string ErrorDescriptionKey { get; } = errorDescriptionKey;
        public string StatusCodeKey { get; } = statusCodeKey;
        public bool IncludeRealm { get; } = includeRealm;
    }
}
