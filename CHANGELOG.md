# Change Log

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


