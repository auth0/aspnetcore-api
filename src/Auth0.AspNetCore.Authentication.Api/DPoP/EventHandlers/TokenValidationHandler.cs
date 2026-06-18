using System.Net;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

internal class TokenValidationHandler : DPoPEventHandlerBase, IDPoPEventHandler<TokenValidatedContext>
{
    private readonly IDPoPProofValidationService _validationService;
    private readonly ILogger<TokenValidationHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenValidationHandler"/> class.
    /// </summary>
    /// <param name="validationService">The DPoP proof validation service.</param>
    /// <param name="logger">The logger instance for logging operations.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationService"/> or <paramref name="logger"/> is null.</exception>
    public TokenValidationHandler(IDPoPProofValidationService validationService, ILogger<TokenValidationHandler> logger)
    {
        _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenValidationHandler"/> class without a logger.
    /// </summary>
    /// <param name="validationService">The DPoP proof validation service.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationService"/> is null.</exception>
    internal TokenValidationHandler(IDPoPProofValidationService validationService)
        : this(validationService, Microsoft.Extensions.Logging.Abstractions.NullLogger<TokenValidationHandler>.Instance)
    {
    }

    public Task Handle(TokenValidatedContext? context)
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

    /// <summary>
    /// Handles the Required DPoP mode for token validation.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal virtual async Task HandleRequiredMode(TokenValidatedContext context)
    {
        if (!IsDPoPScheme(context.Request) || !IsDPoPProofHeaderExists(context.Request))
        {
            _logger.LogError("Invalid DPoP request in required mode - missing DPoP scheme or proof header");
            HandleInvalidRequestInRequiredMode(context);
            return;
        }

        DPoPProofValidationResult? validationResult = await ValidateAsyncInternal(context);

        CaptureErrorsInRequiredMode(context, validationResult);
    }

    /// <summary>
    /// Handles the Allowed DPoP mode for token validation.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal virtual async Task HandleAllowedMode(TokenValidatedContext context)
    {
        // If not using DPoP scheme, check for conflicting DPoP proof headers
        if (!IsDPoPScheme(context.Request))
        {
            if (IsDPoPProofHeaderExists(context.Request) || IsTokenDPoPBound(context))
            {
                _logger.LogError("Bearer scheme used with DPoP proof or DPoP-bound token in allowed mode");
                context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorCode] =
                    Auth0Constants.DPoP.Error.Code.InvalidToken;
                context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorDescription] =
                    Auth0Constants.DPoP.Error.Description.BearerSchemeWithDPoPProof;
                context.HttpContext.Items[Auth0Constants.DPoP.BearerStatusCode] = HttpStatusCode.Unauthorized;
                context.Fail(Auth0Constants.DPoP.Error.Description.BearerSchemeWithDPoPProof);
                return;
            }

            return;
        }

        if (!IsDPoPProofHeaderExists(context.Request))
        {
            _logger.LogError("DPoP scheme used without DPoP proof header in allowed mode");
            HandleInvalidRequestInAllowedMode(context);
            return;
        }

        DPoPProofValidationResult? validationResult = await ValidateAsyncInternal(context);
        CaptureErrorsInAllowedMode(context, validationResult);
    }

    /// <summary>
    /// Handles the Disabled DPoP mode for token validation.
    /// In this mode, DPoP validation is bypassed and no additional processing occurs.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal virtual Task HandleDisabledMode(TokenValidatedContext context)
    {
        return Task.CompletedTask;
    }

    /// <summary>
    /// Validates the DPoP proof for the current request using the provided <see cref="TokenValidatedContext"/>.
    /// Extracts the DPoP-bound access token and DPoP proof header, constructs validation parameters,
    /// and invokes the DPoP proof validation service.
    /// If validation fails, handles the error accordingly.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal async Task<DPoPProofValidationResult?> ValidateAsyncInternal(TokenValidatedContext context)
    {
        DPoPProofValidationParameters validationParameters = CreateDPoPProofValidationParameters(context);

        DPoPProofValidationResult? validationResult = await _validationService.ValidateAsync(validationParameters);

        return validationResult;
    }

    /// <summary>
    /// Creates a <see cref="DPoPProofValidationParameters"/> instance from the provided <see cref="TokenValidatedContext"/>.
    /// This method extracts the DPoP proof token, access token, HTTP method, URI, claims, and DPoP options
    /// required for DPoP proof validation.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <returns>
    /// A <see cref="DPoPProofValidationParameters"/> populated with values from the current request and context.
    /// </returns>
    internal DPoPProofValidationParameters CreateDPoPProofValidationParameters(TokenValidatedContext context)
    {
        DPoPOptions? dPoPOptions = context.HttpContext.RequestServices.GetService<DPoPOptions>();

        if (dPoPOptions is null)
        {
            throw new InvalidOperationException("Auth0 DPoP options not configured.");
        }

        var validationParameters = new DPoPProofValidationParameters
        {
            ProofToken = GetDPoPProofToken(context),
            AccessToken = ExtractDPoPBoundAccessToken(context.Request),
            Htm = context.Request.Method,
            Htu = BuildHtu(context.Request),
            AccessTokenClaims = context.Principal?.Claims,
            Options = dPoPOptions
        };
        return validationParameters;
    }

    /// <summary>
    /// Retrieves the DPoP proof token from the request headers.
    /// </summary>
    /// <param name="context">The token validated context containing the HTTP request.</param>
    /// <returns>The DPoP proof token as a string, or an empty string if not present.</returns>
    internal string GetDPoPProofToken(TokenValidatedContext context)
    {
        KeyValuePair<string, StringValues> header = context.Request.Headers
            .FirstOrDefault(h =>
                string.Equals(h.Key, Auth0Constants.DPoP.ProofHeader, StringComparison.OrdinalIgnoreCase));

        return header.Key == null ? string.Empty : header.Value.ToString();
    }

    /// <summary>
    /// Captures and handles errors resulting from DPoP proof validation in Allowed mode.
    /// Delegates error handling to <see cref="DPoPEventHandlerBase.HandleInvalidRequestInAllowedMode"/> for InvalidRequest errors.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <param name="validationResult">The result of DPoP proof validation.</param>
    internal virtual void CaptureErrorsInAllowedMode(TokenValidatedContext context,
        DPoPProofValidationResult? validationResult)
    {
        CaptureErrors(context, validationResult, HandleInvalidRequestInAllowedMode);
    }

    /// <summary>
    /// Captures and handles errors resulting from DPoP proof validation in Required mode.
    /// Delegates error handling to <see cref="DPoPEventHandlerBase.HandleInvalidRequestInRequiredMode"/> for InvalidRequest errors.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <param name="validationResult">The result of DPoP proof validation.</param>
    internal void CaptureErrorsInRequiredMode(TokenValidatedContext context,
        DPoPProofValidationResult? validationResult)
    {
        CaptureErrors(context, validationResult, HandleInvalidRequestInRequiredMode);
    }

    /// <summary>
    /// Captures and handles errors resulting from DPoP proof validation.
    /// Depending on the error type, sets the error context or invokes the provided invalid request handler.
    /// </summary>
    /// <param name="context">The token validated context containing request and principal information.</param>
    /// <param name="validationResult">The result of DPoP proof validation.</param>
    /// <param name="handleInvalidRequest">
    /// Delegate to handle invalid requests, typically used for InvalidRequest errors.
    /// </param>
    internal void CaptureErrors(
        TokenValidatedContext context,
        DPoPProofValidationResult? validationResult,
        Action<TokenValidatedContext> handleInvalidRequest)
    {
        if (validationResult is { HasError: not true })
        {
            return;
        }

        switch (validationResult?.Error)
        {
            case Auth0Constants.DPoP.Error.Code.InvalidToken:
                SetErrorContext(context, validationResult, HttpStatusCode.Unauthorized);
                break;

            case Auth0Constants.DPoP.Error.Code.InvalidRequest:
                handleInvalidRequest(context);
                break;

            case Auth0Constants.DPoP.Error.Code.InvalidDPoPProof:
                SetErrorContext(context, validationResult, HttpStatusCode.BadRequest);
                break;
        }
    }

    internal static void SetErrorContext(
        TokenValidatedContext? context,
        DPoPProofValidationResult? validationResult,
        HttpStatusCode statusCode)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(validationResult);

        context.HttpContext.Items[Auth0Constants.DPoP.DPoPErrorCode] = validationResult.Error;
        context.HttpContext.Items[Auth0Constants.DPoP.DPoPStatusCode] = statusCode;
        context.HttpContext.Items[Auth0Constants.DPoP.DPoPErrorDescription] = validationResult.ErrorDescription;
        context.Fail((validationResult.ErrorDescription ?? validationResult.Error) ??
                     Auth0Constants.DPoP.Error.Description.UnknownError);
    }

    private bool IsTokenDPoPBound(TokenValidatedContext context)
    {
        return context.Principal?.HasClaim(c => c.Type == Auth0Constants.DPoP.Cnf) ?? false;
    }

    /// <summary>
    /// Builds a valid HTU (HTTP URI) string from the provided <see cref="HttpRequest"/>.
    /// The resulting URI includes the scheme, host, and path, and omits the port if it is the default for the scheme.
    /// Throws <see cref="InvalidOperationException"/> if the URI components are invalid.
    /// </summary>
    /// <param name="request">The HTTP request to extract URI components from.</param>
    /// <returns>A string representing the DPoP-compliant HTU.</returns>
    /// <exception cref="InvalidOperationException">Thrown when URI components are invalid.</exception>
    internal static string BuildHtu(HttpRequest request)
    {
        try
        {
            var uriBuilder = new UriBuilder(request.Scheme, request.Host.Host);

            if (request.Host.Port.HasValue)
            {
                var port = request.Host.Port.Value;
                var isDefaultPort = (request.Scheme == "https" && port == 443) ||
                                    (request.Scheme == "http" && port == 80);

                // Only include port if it's not a default port
                uriBuilder.Port = isDefaultPort ? -1 : port;
            }
            else
            {
                uriBuilder.Port = -1;
            }

            uriBuilder.Path = request.PathBase + request.Path;
            return uriBuilder.Uri.ToString();
        }
        catch (UriFormatException ex)
        {
            throw new InvalidOperationException($"Invalid URI components: {ex.Message}", ex);
        }
    }
}
