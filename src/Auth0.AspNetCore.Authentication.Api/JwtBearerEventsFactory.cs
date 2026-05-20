using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Provides a factory for creating configured JwtBearerEvents instances
/// </summary>
internal abstract class JwtBearerEventsFactory
{
    /// <summary>
    ///     Creates a new instance of <see cref="JwtBearerEvents" /> that wraps the existing user-configured events,
    ///     ensuring they are preserved and called in sequence.
    /// </summary>
    /// <param name="existingEvents">The existing event handlers configured by the user, or null.</param>
    /// <returns>A configured <see cref="JwtBearerEvents" /> instance.</returns>
    internal static JwtBearerEvents Create(JwtBearerEvents? existingEvents)
    {
        return new JwtBearerEvents
        {
            OnTokenValidated = ProxyEvent(existingEvents?.OnTokenValidated),
            OnAuthenticationFailed = ProxyEvent(existingEvents?.OnAuthenticationFailed),
            OnMessageReceived = ProxyEvent(existingEvents?.OnMessageReceived),
            OnChallenge = ProxyEvent(existingEvents?.OnChallenge),
            OnForbidden = ProxyEvent(existingEvents?.OnForbidden)
        };
    }

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
