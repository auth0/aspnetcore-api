# Getting Started

This guide will help you get started with the Auth0 ASP.NET Core API Authentication library.

## Prerequisites

- .NET 8.0 or later
- An Auth0 account ([sign up for free](https://auth0.com/signup))
- An Auth0 API configured in your Auth0 dashboard ([learn how to set up APIs](https://auth0.com/docs/get-started/auth0-overview/set-up-apis))

## Installation

Install the NuGet package:

```bash
dotnet add package Auth0.AspNetCore.Authentication.Api
```

## Setting Up Auth0

### Configure Your Application

Add your Auth0 settings to `appsettings.json`:

```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

⚠️ **Important**: Replace `your-tenant.auth0.com` with your actual Auth0 domain and `https://your-api-identifier` with your API identifier from the Auth0 dashboard.

## Basic Implementation

### 1. Register Authentication in Program.cs

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

// Add other services
builder.Services.AddControllers();

var app = builder.Build();

// Use authentication & authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
```

### 2. Protect Your Endpoints

#### Using Minimal APIs

```csharp
app.MapGet("/api/public", () => "This is a public endpoint");

app.MapGet("/api/protected", () => "This is a protected endpoint")
    .RequireAuthorization();
```

#### Using Controllers

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ValuesController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public()
    {
        return Ok("This is a public endpoint");
    }

    [Authorize]
    [HttpGet("protected")]
    public IActionResult Protected()
    {
        return Ok("This is a protected endpoint");
    }
}
```

## Testing Your API

### 1. Get an Access Token

Use the Auth0 Dashboard or your client application to obtain an access token for your API.

For testing purposes, you can use cURL:

```bash
curl --request POST \
  --url https://your-tenant.auth0.com/oauth/token \
  --header 'content-type: application/json' \
  --data '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://your-api-identifier",
    "grant_type": "client_credentials"
  }'
```

### 2. Call Your Protected Endpoint

```bash
curl --request GET \
  --url http://localhost:5000/api/protected \
  --header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

## Next Steps

- [Configuration Guide](configuration.md) - Learn about advanced configuration options
- [DPoP Overview](dpop-overview.md) - Understanding DPoP and its security benefits
- [Getting Started with DPoP](dpop-getting-started.md) - Enable DPoP in your API
- [API Reference](../api/Auth0.AspNetCore.Authentication.Api.yml) - Complete API documentation

## Troubleshooting

### Some Common Issues you might run into

**401 Unauthorized Response**
- Verify your Auth0 Domain and Audience are correct
- Ensure the access token is valid and not expired
- Check that the token's audience matches your API's audience

**Unable to obtain OIDC configuration**
- Verify your Auth0 Domain is correct (without https://)
- Check your network connection and firewall settings

**No authentication handler is registered**
- Ensure `app.UseAuthentication()` is called before `app.UseAuthorization()`
- Verify the authentication service is registered in `Program.cs`

### Need Help?

If you're experiencing issues not covered here, please [open an issue on GitHub](https://github.com/auth0/aspnetcore-api/issues) and we'll be happy to help!
