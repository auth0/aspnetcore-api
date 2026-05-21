# Change Log

## [1.0.0-beta.6](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.6) (2026-05-21)

> **⚠️ This release contains breaking changes.** Please read the notes below before upgrading.

### Breaking Changes

#### 1. `Auth0ApiOptions.JwtBearerOptions` removed — use `Audience` instead

`Auth0ApiOptions` no longer exposes a `JwtBearerOptions` property. The `Audience` value is now a
first-class property on `Auth0ApiOptions`.

```csharp
// Before
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = "tenant.auth0.com";
    options.JwtBearerOptions = new JwtBearerOptions { Audience = "https://your-api" };
});

// After
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = "tenant.auth0.com";
    options.Audience = "https://your-api";
});
```

#### 2. `AddAuth0ApiAuthentication(...)` signature changed — JWT customization moved to a separate callback

Any additional `JwtBearerOptions` customization that previously lived inside `Auth0ApiOptions`
must now be passed as an optional second argument (`configureJwtBearer`).

```csharp
// Before
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = "tenant.auth0.com";
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = "https://your-api",
        TokenValidationParameters = new TokenValidationParameters { ... }
    };
});

// After
builder.Services.AddAuth0ApiAuthentication(
    options =>
    {
        options.Domain = "tenant.auth0.com";
        options.Audience = "https://your-api";
    },
    configureJwtBearer: jwtOptions =>
    {
        jwtOptions.TokenValidationParameters = new TokenValidationParameters { ... };
    });
```

The recommended registration now also supports direct `IConfigurationSection` binding:

```csharp
// Recommended — binds Domain and Audience from appsettings.json
builder.Services.AddAuth0ApiAuthentication(builder.Configuration.GetSection("Auth0"));
```

#### 3. `WithDPoP(...)` no longer accepts an authentication scheme parameter

DPoP is now automatically scoped to the scheme of the `Auth0ApiAuthenticationBuilder` it is
chained from. Remove any scheme argument passed to `WithDPoP`.

```csharp
// Before
builder.Services.AddAuth0ApiAuthentication(...).WithDPoP("Bearer");

// After
builder.Services.AddAuth0ApiAuthentication(...).WithDPoP();
```

#### 4. Stricter startup validation — app will fail to start for invalid configuration

The SDK now validates configuration at startup and throws if any of the following are detected:

| Condition | Error |
|---|---|
| `Domain` is missing or empty | `OptionsValidationException` |
| No audience configured (neither `Audience` nor `JwtBearerOptions.ValidAudiences`) | `OptionsValidationException` |
| `Domain` contains a scheme, path, port, or query string (e.g. `https://tenant.auth0.com`) | `OptionsValidationException` |
| `JwtBearerOptions.EventsType` is set | `OptionsValidationException` — use `Events` instead |

### Added

- Support for binding `Auth0ApiOptions` directly from `IConfigurationSection` (e.g. `appsettings.json`, environment variables) [\#59](https://github.com/auth0/aspnetcore-api/pull/59)
- New `AddAuth0ApiAuthentication(IConfigurationSection, ...)` overloads on both `IServiceCollection` and `AuthenticationBuilder`
- Startup validation with fast-fail error messages for misconfigured domains, missing audience, and unsupported `EventsType` usage

### Security

Dependency upgrades [\#65](https://github.com/auth0/aspnetcore-api/pull/65), [\#58](https://github.com/auth0/aspnetcore-api/pull/58):

| Package | From | To |
|---|---|---|
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 8.0.25 | 8.0.27 |
| `Microsoft.Extensions.Logging.Abstractions` | 10.0.5 | 10.0.8 |

<details>
<summary>Dev / CI-only dependency updates</summary>

| Package | From | To |
|---|---|---|
| `Microsoft.NET.Test.Sdk` | 18.3.0 | 18.5.1 |
| `Microsoft.SourceLink.GitHub` | 10.0.201 | 10.0.300 |
| `coverlet.collector` | 8.0.1 | 10.0.1 |
| `codecov/codecov-action` | 6.0.0 | 6.0.1 |
| `actions/upload-pages-artifact` | 4 | 5 |

</details>

## [1.0.0-beta.5](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.5) (2026-04-09)

**Added**
- Adds support for Multiple Custom Domains [\#30](https://github.com/auth0/aspnetcore-api/pull/30) ([kailash-b](https://github.com/kailash-b))

**Security**
- chore: Dependency updates [\#47](https://github.com/auth0/aspnetcore-api/pull/47) ([kailash-b](https://github.com/kailash-b))

## [1.0.0-beta.4](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.4) (2026-02-26)

**Security**
- chore: Upgrade dependencies [\#34](https://github.com/auth0/aspnetcore-api/pull/34) ([kailash-b](https://github.com/kailash-b))

## [1.0.0-beta.3](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.3) (2026-01-19)

**Added**
- Adds compile-time support for .NET 10 [\#25](https://github.com/auth0/aspnetcore-api/pull/25) ([kailash-b](https://github.com/kailash-b))

## [1.0.0-beta.2](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.2) (2025-12-02)

**Fixed**
- Update docfx configurations and broken links [\#15](https://github.com/auth0/aspnetcore-api/pull/15) ([kailash-b](https://github.com/kailash-b))

**Security**
- Update dependencies [\#16](https://github.com/auth0/aspnetcore-api/pull/16) ([kailash-b](https://github.com/kailash-b))

## [1.0.0-beta.1](https://github.com/auth0/aspnetcore-api/tree/1.0.0-beta.1) (2025-11-20)

### Installation
```bash
dotnet add package Auth0.AspNetCore.Authentication.Api
```

### Usage
```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});
```

### Added
- JWT Bearer authentication with Auth0-specific configuration
- Built-in DPoP (RFC 9449) support with three enforcement modes: `Allowed`, `Required`, `Disabled`
- Fluent configuration API via `AddAuth0ApiAuthentication()` and `WithDPoP()`
- Comprehensive documentation with examples and migration guide
- Playground application with Postman collection

### Dependencies
- `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.21
- `Microsoft.Extensions.Logging.Abstractions` 8.0.0
- Target framework: .NET 8.0+


