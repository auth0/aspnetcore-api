# Auth0 ASP.NET Core API Authentication

Welcome to the official documentation for the Auth0 ASP.NET Core API Authentication library.

This library simplifies the integration of Auth0 JWT authentication into your ASP.NET Core APIs by wrapping the standard JWT Bearer authentication with Auth0-specific configuration and validation.

## Features

- 🔐 **Easy Auth0 Integration** - Simple configuration with Auth0 Domain and Audience
- 🛡️ **DPoP Support** - Full Demonstration of Proof-of-Possession (DPoP) implementation for enhanced token security
- 🎯 **JWT Bearer Authentication** - Built on top of Microsoft's JWT Bearer authentication
- ⚙️ **Flexible Configuration** - Full access to JWT Bearer options while maintaining Auth0 defaults
- � **Multiple Security Modes** - Support for Bearer, DPoP-allowed, and DPoP-required modes
- 📦 **.NET 8** - Built for modern .NET applications

## Quick Start

```csharp
using Auth0.AspNetCore.Authentication.Api;

var builder = WebApplication.CreateBuilder(args);

// Add Auth0 API Authentication
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions()
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/protected", () => "Hello from protected endpoint!")
    .RequireAuthorization();

app.Run();
```

## Configuration

Add the following to your `appsettings.json`:

```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

## Documentation Sections

### Getting Started
- [Getting Started](articles/getting-started.md) - Installation and basic setup
- [Configuration Guide](articles/configuration.md) - Detailed configuration options

### DPoP (Proof-of-Possession)
- [DPoP Overview](articles/dpop-overview.md) - Understanding DPoP and its security benefits
- [Getting Started with DPoP](articles/dpop-getting-started.md) - Enable DPoP in your API
- [DPoP Configuration Reference](articles/dpop-configuration.md) - Advanced DPoP settings

### Reference
- [API Reference](api/Auth0.AspNetCore.Authentication.Api.yml) - Complete API documentation

## Resources

- [GitHub Repository](https://github.com/auth0/aspnetcore-api)
- [Auth0 Documentation](https://auth0.com/docs)
- [ASP.NET Core Documentation](https://docs.microsoft.com/aspnet/core)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
