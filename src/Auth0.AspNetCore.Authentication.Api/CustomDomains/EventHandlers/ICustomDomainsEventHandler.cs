namespace Auth0.AspNetCore.Authentication.Api.CustomDomains.EventHandlers;

/// <summary>
/// Defines a contract for custom domains event handlers.
/// </summary>
/// <typeparam name="T">The type of context to handle.</typeparam>
internal interface ICustomDomainsEventHandler<in T>
{
    /// <summary>
    /// Handles the custom domains validation logic for the specified context.
    /// </summary>
    /// <param name="context">The context containing request information.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task Handle(T context);
}
