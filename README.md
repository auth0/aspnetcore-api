![Auth0 API SDK for securing your .NET API Server using tokens from Auth0](https://cdn.auth0.com/website/sdks/banners/auth0-dotnet-api-banner.png)

[![Build and Test](https://github.com/auth0/aspnetcore-api/actions/workflows/build.yml/badge.svg)](https://github.com/auth0/aspnetcore-api/actions/workflows/build.yml)
[![License](https://img.shields.io/:license-Apache%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![NuGet Version](https://img.shields.io/nuget/v/Auth0.AspNetCore.Authentication.Api?style=flat&logo=nuget)](https://www.nuget.org/packages/Auth0.AspNetCore.Authentication.Api)
![Downloads](https://img.shields.io/nuget/dt/Auth0.AspNetCore.Authentication.Api)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/aspnetcore-api)

A library that provides **everything the standard JWT Bearer authentication offers**, with the added power of **built-in DPoP (Demonstration of Proof-of-Possession)** support for enhanced token security. Simplify your Auth0 JWT authentication integration for ASP.NET Core APIs with Auth0-specific configuration and validation.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Migration from JWT Bearer](#migration-from-jwt-bearer)
- [Getting Started](#getting-started)
  - [Basic Configuration](#basic-configuration)
  - [Configuration Options](#configuration-options)
- [DPoP: Enhanced Token Security](#dpop-enhanced-token-security)
  - [Enabling DPoP](#enabling-dpop)
  - [DPoP Configuration Options](#dpop-configuration-options)
  - [DPoP Modes](#dpop-modes)
- [Advanced Features](#advanced-features)
  - [Using Full JWT Bearer Options](#using-full-jwt-bearer-options)
- [Examples](#examples)
- [Development](#development)
  - [Building the Project](#building-the-project)
  - [Running Tests](#running-tests)
  - [Playground Application](#playground-application)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

## Features

This library builds on top of the standard `Microsoft.AspNetCore.Authentication.JwtBearer` package, providing:

- **Complete JWT Bearer Functionality** - All features from `Microsoft.AspNetCore.Authentication.JwtBearer` are available
- **Built-in DPoP Support** - Industry-leading proof-of-possession token security per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- **Auth0 Optimized** - Pre-configured for Auth0's authentication patterns
- **Zero Lock-in** - Use standard JWT Bearer features alongside DPoP enhancements
- **Single Package** - Everything you need in one dependency
- **Flexible Configuration** - Options pattern with full access to underlying JWT Bearer configuration

## Requirements

- This library currently supports .NET 8.0 and above.

## Installation

Install the package via NuGet Package Manager:

```bash
dotnet add package Auth0.AspNetCore.Authentication.Api
```

Or via the Package Manager Console:

```powershell
Install-Package Auth0.AspNetCore.Authentication.Api
```

## Migration from JWT Bearer

**Already using `Microsoft.AspNetCore.Authentication.JwtBearer`?** Great news! This library is a **drop-in replacement** with zero behavior changes.

### Quick Migration

Migrating from JWT Bearer is simple:

**Before:**
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
    });
```

**After:**
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

### What You Get

**Zero Breaking Changes** - All JWT Bearer functionality works identically
**5-15 Lines** - Typically only 5-15 lines of code change  
**Full Compatibility** - Custom events, validation, and policies work as-is  
**New Capabilities** - Optional DPoP support with zero refactoring

### Complete Migration Guide

For detailed migration instructions including:
- 8 migration scenarios (basic to complex)
- Custom events and validation
- Multiple audiences
- Testing strategies
- Rollback procedures
- Troubleshooting (10+ common issues)

**See the [Complete Migration Guide](./MIGRATION.md)**

## Getting Started

### Basic Configuration

Add Auth0 authentication to your ASP.NET Core API in `Program.cs`:

```csharp
using Auth0.AspNetCore.Authentication.Api;

using Microsoft.AspNetCore.Authentication.JwtBearer;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Adds Auth0 JWT validation to the API
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

builder.Services.AddAuthorization();

WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/open-endpoint", () =>
    {
        var responseMessage = "This endpoint is available to all users.";
        return responseMessage;
    })
    .WithName("AccessOpenEndpoint")
    .WithOpenApi();

app.MapGet("/restricted-endpoint", () =>
    {
        var responseMessage = "This endpoint is available only to authenticated users.";
        return responseMessage;
    })
    .WithName("AccessRestrictedEndpoint")
    .WithOpenApi().RequireAuthorization();

app.Run();

```

> **Want more examples?** Check out [EXAMPLES.md](./EXAMPLES.md) for comprehensive code examples including authorization policies, scopes, permissions, custom handlers, and more!

### Configuration Options

Add the following settings to your `appsettings.json`:

```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

**Required Settings:**

- **Domain**: Your Auth0 domain (e.g., `my-app.auth0.com`) - **without** the `https://` prefix
- **Audience**: The API identifier configured in your Auth0 Dashboard

The library automatically constructs the authority URL as `https://{Domain}`.

## DPoP: Enhanced Token Security

**DPoP (Demonstration of Proof-of-Possession)** is a security mechanism that binds access tokens to a cryptographic key, making them resistant to token theft and replay attacks. This library provides seamless DPoP integration for your Auth0-protected APIs.

**Learn more about DPoP:** [Auth0 DPoP Documentation](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)

### Enabling DPoP

Enable DPoP with a single method call:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(); // Enable DPoP support
```

That's it! Your API now supports DPoP tokens while maintaining backward compatibility with Bearer tokens.

### DPoP Configuration Options

For fine-grained control, configure DPoP behavior:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(dpopOptions =>
{
    // Enforcement mode
    dpopOptions.Mode = DPoPModes.Required;
    
    // Time validation settings
    dpopOptions.IatOffset = 300; // Allow 300 seconds offset for 'iat' claim (default)
    dpopOptions.Leeway = 30;     // 30 seconds leeway for time-based validation (default)
});
```

### DPoP Modes

Choose the right enforcement mode for your security requirements:

| Mode | Description |
|------|-------------|
| `DPoPModes.Allowed` *(default)* | Accept both DPoP and Bearer tokens |
| `DPoPModes.Required` | Only accept DPoP tokens, reject Bearer tokens |
| `DPoPModes.Disabled` | Standard JWT Bearer validation only |

> **Learn more:** See detailed DPoP examples and use cases in [EXAMPLES.md](./EXAMPLES.md#dpop-demonstration-of-proof-of-possession)

## Advanced Features

### Using Full JWT Bearer Options

Since this library provides **complete access to JWT Bearer configuration**, you can use any standard JWT Bearer option:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        
        // All standard JWT Bearer options are available
        RequireHttpsMetadata = true,
        SaveToken = true,
        IncludeErrorDetails = true,
        
        // Custom token validation parameters
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            NameClaimType = ClaimTypes.NameIdentifier
        },
        
        // Event handlers for custom logic
        Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                return Task.CompletedTask;
            }
        }
    };
});
```

> **Looking for more advanced scenarios?** Visit [EXAMPLES.md](./EXAMPLES.md) for examples on:
> - Scope and permission-based authorization
> - Custom authorization handlers
> - Role-based access control
> - Custom JWT Bearer events
> - SignalR integration
> - Error handling and logging
> - And much more!

## Examples

For comprehensive, copy-pastable code examples covering various scenarios, see **[EXAMPLES.md](./EXAMPLES.md)**:

- **Getting Started** - Basic authentication and endpoint protection
- **Configuration** - Custom token validation and settings
- **DPoP** - All DPoP modes with practical examples
- **Authorization** - Scopes, permissions, roles, and custom handlers
- **Advanced Scenarios** - Claims, events, custom error responses
- **Integration** - SignalR and other integrations

## Development

### Building the Project

Clone the repository and build the solution:

```bash
git clone https://github.com/auth0/aspnetcore-api.git
cd aspnetcore-api
dotnet restore Auth0.AspNetCore.Authentication.Api.sln
dotnet build Auth0.AspNetCore.Authentication.Api.sln --configuration Release
```

### Running Tests

Run the unit test suite:

```bash
dotnet test tests/Auth0.AspNetCore.Authentication.Api.UnitTests/
```

### Playground Application

The repository includes a playground application for testing both standard JWT Bearer and **DPoP authentication**:

#### Setup

1. **Configure Auth0 settings** in `Auth0.AspNetCore.Authentication.Api.Playground/appsettings.json`:
   ```json
   {
     "Auth0": {
       "Domain": "your-tenant.auth0.com",
       "Audience": "https://your-api-identifier"
     }
   }
   ```

2. **Run the playground**:
   ```bash
   cd Auth0.AspNetCore.Authentication.Api.Playground
   dotnet run
   ```

3. **Access the application**:
   - Swagger UI: `https://localhost:7190/swagger`
   - Open endpoint: GET `/open-endpoint` (no authentication required)
   - Protected endpoint: GET `/restricted-endpoint` (requires authentication)

#### Testing with Postman

The playground includes a pre-configured Postman collection (`Auth0.AspNetCore.Authentication.Api.Playground.postman_collection.json`) with ready-to-use requests:

1. Import the collection into Postman
2. Obtain a JWT token from Auth0
3. Set the `{{token}}` variable in your Postman environment
4. Test both endpoints with pre-configured headers

See the [Playground README](./Auth0.AspNetCore.Authentication.Api.Playground/README.md) for detailed testing instructions and examples.

## Contributing

We appreciate your contributions! Please review our [contribution guidelines](./.github/PULL_REQUEST_TEMPLATE.md) before submitting pull requests.

### Contribution Checklist

- ✅ Read the [Auth0 General Contribution Guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- ✅ Read the [Auth0 Code of Conduct](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- ✅ Ensure all tests pass
- ✅ Add tests for new functionality
- ✅ Update documentation as needed
- ✅ Sign all commits

## Support

If you have questions or need help:

- 📖 Check the [Auth0 Documentation](https://auth0.com/docs)
- � See [EXAMPLES.md](./EXAMPLES.md) for code examples
- 💬 Visit the [Auth0 Community](https://community.auth0.com/)
- 🐛 Report issues on [GitHub Issues](https://github.com/auth0/aspnetcore-api/issues)

## License
Copyright 2025 Okta, Inc.

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Authors
Okta Inc.
---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy-to-implement, adaptable authentication and authorization platform. To learn more check out <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">This project is licensed under the Apache License 2.0. See the <a href="./LICENSE">LICENSE</a> file for more info.</p>