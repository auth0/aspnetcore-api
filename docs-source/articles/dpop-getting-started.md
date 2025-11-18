# Getting Started with DPoP

This guide walks you through enabling DPoP (Demonstration of Proof-of-Possession) support in your Auth0-protected ASP.NET Core API.

## Prerequisites

Before enabling DPoP, ensure you have:

- ✅ An Auth0 account with DPoP enabled (contact Auth0 support if needed)
- ✅ An API configured in Auth0 with DPoP support
- ✅ The Auth0 ASP.NET Core API Authentication library installed
- ✅ Basic Auth0 authentication already configured (see [Getting Started](getting-started.md))

## Quick Start

### Step 1: Enable DPoP with Default Settings

Add `.WithDPoP()` to your authentication configuration:

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions()
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(); // ✨ Enable DPoP with default settings

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

That's it! Your API now supports DPoP validation with sensible defaults.

### Step 2: Configure Auth0

Ensure your Auth0 API is configured to issue DPoP-bound tokens. Follow the [Auth0 DPoP configuration guide](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop) to set up DPoP for your API and clients.

> **Note**: DPoP requires Auth0 tenant configuration. Contact Auth0 support if you don't see DPoP options.

### Step 3: Test Your API

#### With DPoP (will succeed)

```bash
curl -X GET https://localhost:5001/api/protected \
  -H "Authorization: DPoP <dpop-bound-access-token>" \
  -H "DPoP: <dpop-proof-token>"
```

#### Without DPoP (will also succeed with default Allowed mode)

```bash
curl -X GET https://localhost:5001/api/protected \
  -H "Authorization: Bearer <regular-access-token>"
```

## DPoP Modes Explained

### Allowed Mode (Default)

```csharp
.WithDPoP(options =>
{
    options.Mode = DPoPModes.Allowed;
});
```

**Behavior:**
- ✅ Accepts DPoP-bound tokens with valid proofs
- ✅ Also accepts standard Bearer tokens
- 🔍 Validates DPoP when the `DPoP` header is present

### Required Mode

```csharp
.WithDPoP(options =>
{
    options.Mode = DPoPModes.Required;
});
```

**Behavior:**
- ✅ Only accepts DPoP-bound tokens with valid proofs
- ❌ Rejects standard Bearer tokens
- ❌ Rejects requests without the `DPoP` header

### Disabled Mode

```csharp
.WithDPoP(options =>
{
    options.Mode = DPoPModes.Disabled;
});
```

**Behavior:**
- ✅ Only standard JWT Bearer authentication
- ❌ No DPoP validation performed
- 🚫 DPoP headers are ignored

## Common Configuration Examples

### Example 1: Allowed Mode

Start with Allowed mode to test DPoP without breaking existing clients:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions()
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(options =>
{
    options.Mode = DPoPModes.Allowed;
    options.Leeway = 30; // 30 seconds tolerance
    options.IatOffset = 300; // 5 minutes max age
});
```

### Example 2: Required Mode

Enforce DPoP for all requests:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions()
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(options =>
{
    options.Mode = DPoPModes.Required;
    options.Leeway = 10; // Tighter timing
    options.IatOffset = 120; // 2 minutes max age
});
```

### Example 3: Custom Authentication Scheme

Use a custom scheme name:

```csharp
builder.Services
    .AddAuthentication("MyCustomScheme")
    .AddAuth0ApiAuthentication("MyCustomScheme", options =>
    {
        options.Domain = builder.Configuration["Auth0:Domain"];
        options.JwtBearerOptions = new JwtBearerOptions()
        {
            Audience = builder.Configuration["Auth0:Audience"]
        };
    })
    .WithDPoP("MyCustomScheme", options =>
    {
        options.Mode = DPoPModes.Allowed;
    });
```

## Protecting Endpoints

Once DPoP is enabled, protect your endpoints as usual:

### Using Minimal APIs

```csharp
app.MapGet("/api/public", () => 
    Results.Ok("Public endpoint - no authentication required"));

app.MapGet("/api/protected", () => 
    Results.Ok("Protected endpoint - authentication required"))
    .RequireAuthorization();
```

### Using Controllers

```csharp
[ApiController]
[Route("api/[controller]")]
public class DataController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public()
    {
        return Ok("Public endpoint");
    }

    [Authorize]
    [HttpGet("protected")]
    public IActionResult Protected()
    {
        return Ok("Protected endpoint");
    }
}
```

## Accessing Claims

DPoP validation is transparent - access claims normally:

```csharp
[Authorize]
[HttpGet("user-info")]
public IActionResult GetUserInfo()
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = User.FindFirst(ClaimTypes.Email)?.Value;
    
    return Ok(new { userId, email });
}
```

## Troubleshooting

### DPoP Validation Fails

**Problem**: Requests with DPoP header are rejected

**Solutions:**
1. Check that Auth0 issued a DPoP-bound token (look for `cnf` claim)
2. Verify the `DPoP` proof is properly formed
3. Ensure `htm` (HTTP method) and `htu` (HTTP URI) match exactly
4. Check time synchronization - `iat` must be recent

### Bearer Tokens Rejected in Required Mode

**Problem**: Standard bearer tokens return 401

**Solution**: This is expected behavior in Required mode. Either:
- Switch to `DPoPModes.Allowed` to support both
- Update clients to send DPoP proofs

### Time Validation Errors

**Problem**: Valid-looking DPoP proofs are rejected due to timing

**Solutions:**
1. Increase `IatOffset` to allow older proofs
2. Increase `Leeway` for clock skew tolerance
3. Ensure client and server clocks are synchronized

```csharp
.WithDPoP(options =>
{
    options.IatOffset = 600; // 10 minutes
    options.Leeway = 60; // 1 minute leeway
});
```

## Error Responses

### Invalid DPoP Proof

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="invalid_dpop_proof", 
                  error_description="DPoP proof validation failed"
```

### Missing DPoP Proof (Required Mode)

```http
HTTP/1.1 401 Unauthorized  
WWW-Authenticate: DPoP error="invalid_request",
                  error_description="DPoP proof is missing"
```

### Invalid Token

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="invalid_token",
                  error_description="The cnf (confirmation) claim is missing or invalid"
```

## Next Steps

- [DPoP Configuration](dpop-configuration.md) - Detailed configuration options
- [DPoP Overview](dpop-overview.md) - Understanding DPoP concepts
- [Configuration Guide](configuration.md) - General Auth0 configuration

## Additional Resources

- [RFC 9449: OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [Auth0 DPoP Documentation](https://auth0.com/docs/secure/tokens/token-best-practices/proof-of-possession)
- [Sample Application](https://github.com/auth0/aspnetcore-api/tree/main/Auth0.AspNetCore.Authentication.Api.Playground)
