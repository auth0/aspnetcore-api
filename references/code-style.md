# Code Style

Style is enforced via `.editorconfig` at the repo root. Highlights:

- 4-space indentation, LF line endings, UTF-8, final newline, trimmed trailing whitespace.
- 120-column guideline (`max_line_length = 120`).
- `var` for built-in types and when the type is apparent; **explicit type elsewhere** (`csharp_style_var_elsewhere = false`).
- Braces always required (`csharp_prefer_braces = true`).
- `System.*` usings sorted first, import directive groups separated.
- No `this.` qualification for fields/properties/methods/events.
- Expression-bodied members are **not** preferred for methods/properties/ctors.

## Naming

- PascalCase for public types, methods, properties; camelCase for locals/parameters; `_camelCase` is not used for private fields in this codebase (fields are unqualified).
- Public API types and members carry XML `<summary>` doc comments (the package generates a documentation file and is `CLSCompliant`).

## ✅ Good

```csharp
public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(
    this IServiceCollection services,
    Action<Auth0ApiOptions> configureOptions,
    Action<JwtBearerOptions>? configureJwtBearer = null)
{
    ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

    return services.AddAuth0ApiAuthentication(
        Auth0Constants.AuthenticationScheme.Auth0, configureOptions, configureJwtBearer);
}
```

## ❌ Bad

```csharp
// Missing null guard, no XML doc, expression-bodied public method, implicit var for non-apparent type
public static Auth0ApiAuthenticationBuilder AddAuth0ApiAuthentication(this IServiceCollection services, Action<Auth0ApiOptions> configureOptions)
    => services.AddAuth0ApiAuthentication(Auth0Constants.AuthenticationScheme.Auth0, configureOptions, null);
```

## Dominant patterns

- **Fluent builder** — setup methods return `Auth0ApiAuthenticationBuilder`, chained with `.WithDPoP()`.
- **Options pattern** — `Auth0ApiOptions` wraps `JwtBearerOptions` + `Domain`; `DPoPOptions` configures DPoP; validated via `IPostConfigureOptions` (`Auth0JwtBearerPostConfigureOptions`).
- **Event-handler wrapping** — DPoP event handlers wrap user-supplied `JwtBearerEvents`, running the DPoP logic first then delegating to the user's handler (see `DPoPEventsFactory.Create()` / `JwtBearerEventsFactory`). Always preserve existing user events when modifying this.
- **Typed error codes** — DPoP failures use `Auth0Constants.DPoP.Error.Code.*` set on `DPoPProofValidationResult`, surfaced via `context.Fail()`.
- **Argument guards** — public methods start with `ArgumentNullException.ThrowIfNull` / `ArgumentException.ThrowIfNullOrWhiteSpace`.
