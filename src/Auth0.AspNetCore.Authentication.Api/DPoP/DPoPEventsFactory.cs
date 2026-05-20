using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Auth0.AspNetCore.Authentication.Api.DPoP;

/// <summary>
///     Provides a factory for creating configured JwtBearerEvents instances with DPoP support.
/// </summary>
internal abstract class DPoPEventsFactory
{
    /// <summary>
    ///     Creates a new instance of <see cref="JwtBearerEvents" /> that wraps existing event handlers
    ///     with DPoP-specific logic, preserving the original event chain.
    /// </summary>
    /// <param name="existingEvents">The existing event handlers (user-configured or from prior layers), or null.</param>
    /// <returns>A configured <see cref="JwtBearerEvents" /> instance with integrated DPoP event handlers.</returns>
    internal static JwtBearerEvents Create(JwtBearerEvents? existingEvents)
    {
        var dPoPEventHandlers = new DPoPEventHandlers();
        return new JwtBearerEvents
        {
            OnMessageReceived =
                ProxyEvent(existingEvents?.OnMessageReceived,
                    dPoPEventHandlers.HandleOnMessageReceived()),
            OnTokenValidated = ProxyEvent(existingEvents?.OnTokenValidated,
                dPoPEventHandlers.HandleOnTokenValidated()),
            OnAuthenticationFailed = ProxyEvent(existingEvents?.OnAuthenticationFailed),
            OnChallenge = ProxyEvent(existingEvents?.OnChallenge,
                dPoPEventHandlers.HandleOnChallenge()),
            OnForbidden = ProxyEvent(existingEvents?.OnForbidden)
        };
    }

    /// <summary>
    ///     Creates a composite event handler that executes an additional handler first,
    ///     followed by the original handler, if they are provided.
    /// </summary>
    /// <typeparam name="T">The type of the event context.</typeparam>
    /// <param name="originalHandler">The original event handler provided by the user.</param>
    /// <param name="additionalHandler">An additional event handler to execute before the original handler.</param>
    /// <returns>A composite event handler that executes both handlers in sequence.</returns>
    private static Func<T, Task> ProxyEvent<T>(Func<T, Task>? originalHandler, Func<T, Task>? additionalHandler = null)
    {
        return async context =>
        {
            if (additionalHandler != null)
            {
                await additionalHandler(context);
            }

            if (originalHandler != null)
            {
                await originalHandler(context);
            }
        };
    }
}
