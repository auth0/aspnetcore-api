# Configuration Guide

This guide covers all configuration options available in the Auth0 ASP.NET Core API Authentication library.

## Basic Configuration

The most basic configuration requires only two settings — `Domain` and `Audience` — which can be bound directly from your configuration:

```csharp
builder.Services.AddAuth0ApiAuthentication(
    builder.Configuration.GetSection("Auth0"));
```

Or configure programmatically using a delegate:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = "your-tenant.auth0.com";
    options.Audience = "https://your-api-identifier";
});
```

Both approaches also accept an optional `configureJwtBearer` parameter for advanced JWT Bearer customization:

```csharp
builder.Services.AddAuth0ApiAuthentication(
    options =>
    {
        options.Domain = "your-tenant.auth0.com";
        options.Audience = "https://your-api-identifier";
    },
    configureJwtBearer: jwt =>
    {
        jwt.SaveToken = true;
    });
```

## Configuration Options

### Auth0ApiOptions

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `Domain` | string | Yes | Your Auth0 tenant domain (e.g., "your-tenant.auth0.com") |
| `Audience` | string | Yes | The API identifier registered in Auth0 |

### Customizing JwtBearerOptions

For advanced JWT Bearer configuration, use the `configureJwtBearer` parameter:

```csharp
builder.Services.AddAuth0ApiAuthentication(
    builder.Configuration.GetSection("Auth0"),
    configureJwtBearer: jwt =>
    {
        jwt.RequireHttpsMetadata = true;
        jwt.SaveToken = true;
        jwt.TokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    });
```

The library exposes all standard `JwtBearerOptions` properties from ASP.NET Core. For a complete list of available options and their descriptions, refer to the [Microsoft JwtBearerOptions API documentation](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.jwtbearer.jwtbeareroptions).

## Environment-Specific Configuration

### Using Configuration Files

**appsettings.json** (shared settings — both Domain and Audience required at runtime):
```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

You can override values per environment. For example, if the API identifier stays the same across environments but the tenant differs:

**appsettings.Development.json**:
```json
{
  "Auth0": {
    "Domain": "dev-tenant.auth0.com"
  }
}
```

**appsettings.Production.json**:
```json
{
  "Auth0": {
    "Domain": "prod-tenant.auth0.com"
  }
}
```

> **Note:** The .NET configuration system merges files in order, so environment-specific files override values from the base `appsettings.json`. Both `Domain` and `Audience` must resolve to non-empty values at startup or the application will fail with a validation error.

### Using Environment Variables

Environment variables are automatically bound via the .NET configuration system:

```bash
export Auth0__Domain="your-tenant.auth0.com"
export Auth0__Audience="https://your-api-identifier"
```

No code changes needed — the `GetSection("Auth0")` call picks up values from all configured providers (appsettings.json, environment variables, user secrets, etc.).

## Using AuthenticationBuilder Directly

If you're composing multiple authentication schemes and need to work with `AuthenticationBuilder` directly, the same configuration patterns are available:

```csharp
var authBuilder = builder.Services.AddAuthentication();

// From configuration section
authBuilder.AddAuth0ApiAuthentication("Auth0", builder.Configuration.GetSection("Auth0"));

// Or programmatically
authBuilder.AddAuth0ApiAuthentication("Auth0", options =>
{
    options.Domain = "your-tenant.auth0.com";
    options.Audience = "https://your-api-identifier";
});

// Add other schemes as needed
authBuilder.AddScheme<ApiKeyAuthOptions, ApiKeyAuthHandler>("ApiKey", options => { });
```

## Next Steps

- [DPoP Overview](dpop-overview.md) - Understanding DPoP and its security benefits
- [Getting Started with DPoP](dpop-getting-started.md) - Enable DPoP in your API
- [API Reference](../api/Auth0.AspNetCore.Authentication.Api.yml) - Complete API documentation
