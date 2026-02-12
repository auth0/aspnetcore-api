using Auth0.AspNetCore.Authentication.Api.CustomDomains.EventHandlers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication.Api.CustomDomains;

/// <summary>
/// Provides a factory for creating configured JwtBearerEvents instances with custom domains validation.
/// </summary>
internal static class CustomDomainsEventsFactory
{
    /// <summary>
    /// Creates a new instance of <see cref="JwtBearerEvents"/> with custom domains validation
    /// chained before any existing event handlers.
    /// </summary>
    /// <param name="existingEvents">The existing JWT Bearer events (may be <c>null</c> or contain user-configured handlers).</param>
    /// <returns>A configured <see cref="JwtBearerEvents"/> instance with chained event handlers.</returns>
    internal static JwtBearerEvents Create(JwtBearerEvents? existingEvents)
    {
        return new JwtBearerEvents
        {
            OnMessageReceived = ProxyEvent(
                existingEvents?.OnMessageReceived,
                HandleOnMessageReceived()),

            // Preserve all other existing event handlers
            OnTokenValidated = existingEvents?.OnTokenValidated!,
            OnAuthenticationFailed = existingEvents?.OnAuthenticationFailed!,
            OnChallenge = existingEvents?.OnChallenge!,
            OnForbidden = existingEvents?.OnForbidden!
        };
    }

    /// <summary>
    /// Creates the OnMessageReceived handler that resolves the MessageReceivedHandler from DI.
    /// This follows the same pattern as DPoP event handlers.
    /// </summary>
    private static Func<MessageReceivedContext, Task> HandleOnMessageReceived()
    {
        return context =>
        {
            MessageReceivedHandler handler = context.HttpContext.RequestServices.GetRequiredService<MessageReceivedHandler>();
            return handler.Handle(context);
        };
    }

    /// <summary>
    /// Creates a composite event handler that executes a custom domains handler first,
    /// followed by the original handler if validation passes.
    /// </summary>
    /// <typeparam name="T">The type of the event context.</typeparam>
    /// <param name="originalHandler">The original event handler provided by the user or DPoP.</param>
    /// <param name="customDomainsHandler">The custom domains validation handler to execute first.</param>
    /// <returns>A composite event handler that executes both handlers in sequence.</returns>
    private static Func<T, Task> ProxyEvent<T>(
        Func<T, Task>? originalHandler,
        Func<T, Task> customDomainsHandler)
    {
        return async context =>
        {
            await customDomainsHandler(context);

            // Return early if validation fails
            if (context is MessageReceivedContext msgContext &&
                msgContext.Result != null &&
                msgContext.Result.Failure != null)
            {
                return;
            }

            if (originalHandler != null)
            {
                await originalHandler(context);
            }
        };
    }
}
