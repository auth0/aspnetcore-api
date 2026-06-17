using System.Net;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

internal class MessageReceivedHandler : DPoPEventHandlerBase, IDPoPEventHandler<MessageReceivedContext>
{
    private readonly ILogger<MessageReceivedHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="MessageReceivedHandler"/> class.
    /// </summary>
    /// <param name="logger">The logger instance for logging operations.</param>
    public MessageReceivedHandler(ILogger<MessageReceivedHandler> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MessageReceivedHandler"/> class without a logger.
    /// </summary>
    internal MessageReceivedHandler() : this(Microsoft.Extensions.Logging.Abstractions.NullLogger<MessageReceivedHandler>.Instance)
    {
    }

    public Task Handle(MessageReceivedContext context)
    {
        try
        {
            DPoPOptions dPoPOptions = context.HttpContext.RequestServices.GetRequiredService<DPoPOptions>();
            return dPoPOptions.Mode switch
            {
                DPoPModes.Disabled => HandleDisabledMode(context),
                DPoPModes.Allowed => HandleAllowedMode(context),
                DPoPModes.Required => HandleRequiredMode(context),
                _ => Task.CompletedTask
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle message received for DPoP mode");
            return Task.CompletedTask;
        }
    }

    /// <summary>
    ///     Handles the scenario when DPoP authentication is disabled.
    ///     Skips all DPoP validation and processing, allowing requests to proceed without DPoP checks.
    /// </summary>
    internal virtual Task HandleDisabledMode(MessageReceivedContext context)
    {
        // When DPoP is disabled, skip all DPoP validation and processing
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Handles the DPoP authentication scenario when the mode is set to Allowed.
    ///     In Allowed mode, the method processes the request to extract the DPoP token if present.
    ///     If any validation fails, authentication is not performed and the request proceeds without DPoP checks.
    /// </summary>
    /// <param name="context">
    ///     The JWT Bearer message received context containing the HTTP request.
    /// </param>
    /// <returns>
    ///     A completed <see cref="Task" /> after processing the Allowed DPoP authentication logic.
    /// </returns>
    internal virtual Task HandleAllowedMode(MessageReceivedContext context)
    {
        if (!IsAuthorizationTokenExists(context.Request))
        {
            _logger.LogError("Invalid authorization header in allowed mode - missing token");
            HandleInvalidRequestInAllowedMode(context);
            return Task.CompletedTask;
        }

        // In Allowed mode, process the request to extract DPoP token if present
        if (!IsValidAuthorizationHeaderCount(context.Request))
        {
            _logger.LogError("Invalid authorization header count in allowed mode");
            HandleInvalidRequestInAllowedMode(context);
            return Task.CompletedTask;
        }

        // If not using DPoP scheme, check for conflicting DPoP proof headers
        if (!IsDPoPScheme(context.Request))
        {
            if (IsDPoPProofHeaderExists(context.Request))
            {
                _logger.LogError("Bearer scheme used with DPoP proof header in allowed mode");
                context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorCode] =
                    Auth0Constants.DPoP.Error.Code.InvalidToken;
                context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorDescription] =
                    Auth0Constants.DPoP.Error.Description.BearerSchemeWithDPoPProof;
                context.HttpContext.Items[Auth0Constants.DPoP.BearerStatusCode] = HttpStatusCode.Unauthorized;
                context.Fail(Auth0Constants.DPoP.Error.Description.BearerSchemeWithDPoPProof);
                return Task.CompletedTask;
            }

            return Task.CompletedTask;
        }

        if (!IsDPoPProofHeaderExists(context.Request))
        {
            _logger.LogError("DPoP scheme used without DPoP proof header in allowed mode");
            HandleInvalidRequestInAllowedMode(context);
            return Task.CompletedTask;
        }

        // If a valid DPoP scheme is used and DPoP header exists, extract the token
        var accessToken = ExtractDPoPBoundAccessToken(context.Request);

        if (accessToken is null)
        {
            _logger.LogError("Failed to extract DPoP-bound access token in allowed mode");
            HandleInvalidRequestInAllowedMode(context);
            return Task.CompletedTask;
        }

        context.Token = accessToken;
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Handles the scenario when DPoP authentication is required.
    ///     Validates that the request contains exactly one Authorization header using the DPoP scheme,
    ///     and exactly one valid DPoP proof header. If any validation fails, authentication is not performed.
    ///     If all checks pass, extracts the DPoP-bound access token for downstream authentication.
    /// </summary>
    /// <param name="context">
    ///     The JWT Bearer message received context containing the HTTP request.
    /// </param>
    /// <returns>
    ///     A completed <see cref="Task" /> after processing the required DPoP authentication logic.
    /// </returns>
    internal virtual Task HandleRequiredMode(MessageReceivedContext context)
    {
        if (!IsValidAuthorizationHeaderCount(context.Request))
        {
            _logger.LogError("Invalid authorization header count in required mode");
            HandleInvalidRequestInRequiredMode(context);
            return Task.CompletedTask;
        }

        if (!IsDPoPScheme(context.Request))
        {
            _logger.LogError("Non-DPoP authentication scheme used in required mode");
            HandleInvalidRequestInRequiredMode(context);
            return Task.CompletedTask;
        }

        if (!IsDPoPProofHeaderExists(context.Request))
        {
            _logger.LogError("Missing DPoP proof header in required mode");
            HandleInvalidRequestInRequiredMode(context);
            return Task.CompletedTask;
        }

        if (!IsAuthorizationTokenExists(context.Request))
        {
            _logger.LogError("Missing authorization token in required mode");
            HandleInvalidRequestInRequiredMode(context);
            return Task.CompletedTask;
        }

        var accessToken = ExtractDPoPBoundAccessToken(context.Request);

        if (accessToken is null)
        {
            _logger.LogError("Failed to extract DPoP-bound access token in required mode");
            HandleInvalidRequestInRequiredMode(context);
            return Task.CompletedTask;
        }

        context.Token = accessToken;

        return Task.CompletedTask;
    }
}
