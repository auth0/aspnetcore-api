# Migration Guide: From JWT Bearer to Auth0.AspNetCore.Authentication.Api

[![Compatibility](https://img.shields.io/badge/.NET-8.0+-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Migration Time](https://img.shields.io/badge/Migration%20Time-5--15%20minutes-brightgreen)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Easy-success)]()

Welcome! This guide will help you migrate from the standard `Microsoft.AspNetCore.Authentication.JwtBearer` package to `Auth0.AspNetCore.Authentication.Api`. This migration is designed to be **seamless** with **zero behavior changes** to your existing authentication flow, while unlocking powerful new features like **DPoP (Demonstration of Proof-of-Possession)** for enhanced security.

## How to Use This Guide

**Choose your path based on your experience level:**

- **🚀 Quick Migration (5 minutes):** If you have a basic JWT Bearer setup, jump directly to [Basic JWT Bearer Authentication](#1-basic-jwt-bearer-authentication) and follow the before/after example.

- **📚 First-Time Migrators:** Start with [Pre-Migration Checklist](#pre-migration-checklist), review [Breaking Changes](#breaking-changes) (spoiler: there are none!), then follow [Step-by-Step Migration Instructions](#step-by-step-migration-instructions).

- **🔍 Complex Setup:** If you have custom events, multiple audiences, or custom validation, browse the [Migration Scenarios](#migration-scenarios) to find your specific use case.

- **🆘 Troubleshooting:** Having issues? Go directly to [Common Issues and Solutions](#common-issues-and-solutions) for quick fixes.

- **✅ Post-Migration:** After migrating, use the [Complete Migration Checklist](#complete-migration-checklist) to verify everything works correctly.

Most migrations are completed in **5-15 minutes** with changes to just **5-15 lines of code** in a single file.

## Table of Contents

- [Version Compatibility](#version-compatibility)
- [Breaking Changes](#breaking-changes)
- [Migration Effort & Complexity](#migration-effort--complexity)
- [Pre-Migration Checklist](#pre-migration-checklist)
- [Migration Overview](#migration-overview)
- [Migration Scenarios](#migration-scenarios)
  - [1. Basic JWT Bearer Authentication](#1-basic-jwt-bearer-authentication)
  - [2. Custom Authentication Scheme](#2-custom-authentication-scheme)
  - [3. Custom Token Validation Parameters](#3-custom-token-validation-parameters)
  - [4. Custom JWT Bearer Events](#4-custom-jwt-bearer-events)
  - [5. Multiple Audiences](#5-multiple-audiences)
  - [6. Custom Token Retrieval](#6-custom-token-retrieval)
  - [7. Using AuthenticationBuilder](#7-using-authenticationbuilder)
  - [8. Controllers with [Authorize] Attribute](#8-controllers-with-authorize-attribute)
- [Step-by-Step Migration Instructions](#step-by-step-migration-instructions)
- [Enabling DPoP (Optional)](#enabling-dpop-optional)
- [Verification Steps](#verification-steps)
- [Testing Your Migration](#testing-your-migration)
- [Rollback Strategy](#rollback-strategy)
- [Common Issues and Solutions](#common-issues-and-solutions)
- [Getting Help](#getting-help)

---

## Version Compatibility

### Supported Versions

| Component | Minimum Version | Recommended Version |
|-----------|----------------|---------------------|
| .NET | 8.0 | 8.0 (latest patch) |
| Auth0.AspNetCore.Authentication.Api | 1.0.0 | Latest |
| Microsoft.AspNetCore.Authentication.JwtBearer | 8.0.0 | Included as dependency |
| Auth0 Tenant | Any | N/A |

### Package Dependencies

The `Auth0.AspNetCore.Authentication.Api` package includes:
- ✅ `Microsoft.AspNetCore.Authentication.JwtBearer` (as dependency)
- ✅ `Microsoft.IdentityModel.Tokens` (as dependency)

**You do not need** to explicitly reference `Microsoft.AspNetCore.Authentication.JwtBearer` after migration (though it's harmless if you do).

### Migration Compatibility

This migration guide applies to:
- ✅ ASP.NET Core 8.0+ applications
- ✅ Applications using `Microsoft.AspNetCore.Authentication.JwtBearer` 6.0+
- ✅ Both Minimal APIs and Controller-based applications
- ✅ Applications with single or multiple authentication schemes

---

## Breaking Changes

### None! 🎉

**There are NO breaking changes in this migration.** The library is designed as a drop-in replacement for JWT Bearer authentication.

### API Surface Changes

The only API change is the configuration method:

```csharp
// Before: JwtBearer API surface
AddJwtBearer(options => { /* ... */ })

// After: Auth0 API surface
AddAuth0ApiAuthentication(options => 
{
    options.Domain = "...";
    options.JwtBearerOptions = new JwtBearerOptions { /* ... */ };
})
```

### Behavioral Guarantees

The following remain **100% identical**:
- ✅ Token validation logic
- ✅ Claims extraction and transformation
- ✅ Authorization policy enforcement
- ✅ JWT Bearer event handling
- ✅ Error responses and status codes
- ✅ Performance characteristics
- ✅ Memory footprint

### What's New (Additive Only)

New optional features available after migration:
- ✨ **DPoP support** - Opt-in proof-of-possession tokens
- ✨ **Simplified Auth0 configuration** - Domain-based setup
- ✨ **Auth0-optimized defaults** - Best practices built-in

---

## Migration Effort & Complexity

### Estimated Time

| Scenario | Estimated Time | Complexity |
|----------|----------------|------------|
| Basic setup (single audience) | 5 minutes | 🟢 Easy |
| Custom token validation | 10 minutes | 🟢 Easy |
| Custom events/handlers | 10-15 minutes | 🟡 Medium |
| Multiple auth schemes | 15-20 minutes | 🟡 Medium |
| Complex multi-tenant setup | 20-30 minutes | 🟠 Advanced |

### Code Changes Summary

For a typical application:
- **Files modified:** 1-2 files (usually just `Program.cs`)
- **Lines changed:** 5-15 lines
- **New dependencies:** 1 package added
- **Configuration changes:** 0-1 (appsettings.json structure can stay the same)

### Risk Assessment

| Risk Level | Description |
|------------|-------------|
| **Migration Risk** | 🟢 **Low** - Drop-in replacement, no behavior changes |
| **Rollback Risk** | 🟢 **Low** - Simple package swap to revert |
| **Testing Effort** | 🟢 **Low** - Existing tests should pass unchanged |
| **Production Impact** | 🟢 **None** - Zero downtime migration possible |

---

## Pre-Migration Checklist

Before starting the migration, ensure you have:

### Required

- [ ] **Backup your code** - Commit current state to version control
- [ ] **.NET 8.0 or higher** - Check with `dotnet --version`
- [ ] **Auth0 credentials** - Have Domain and Audience values ready
- [ ] **Existing tests pass** - Run tests before migration for baseline
- [ ] **Local environment working** - Verify current auth works locally

### Recommended

- [ ] **Review current configuration** - Document current JWT Bearer setup
- [ ] **Identify custom events** - List any custom JWT Bearer events in use
- [ ] **Check authorization policies** - Note custom policies that depend on auth
- [ ] **Test tokens available** - Have valid and invalid tokens for testing
- [ ] **Staging environment** - Have non-prod environment to test first
- [ ] **Rollback plan** - Know how to revert if needed (see [Rollback Strategy](#rollback-strategy))

### Optional (for DPoP)

- [ ] **DPoP learning** - Understand [DPoP concepts](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)
- [ ] **Client capability** - Check if clients can send DPoP proofs
- [ ] **Auth0 DPoP enabled** - Verify Auth0 tenant supports DPoP

---

## Migration Overview

### Package Changes
- **Remove:** `Microsoft.AspNetCore.Authentication.JwtBearer` (it's included as a dependency)
- **Add:** `Auth0.AspNetCore.Authentication.Api`

### Configuration Changes
- **Before:** Configure `Authority` and `Audience` in `JwtBearerOptions`
- **After:** Configure `Domain` in `Auth0ApiOptions` and `Audience` in `JwtBearerOptions`
- **Why:** Simpler Auth0-specific configuration pattern

### No Behavioral Changes
- Token validation remains **identical**
- Authorization policies work **unchanged**
- Custom events continue to work **as-is**
- Middleware pipeline stays **the same**

---

## Migration Scenarios

### 1. Basic JWT Bearer Authentication

This is the most common scenario - straightforward JWT authentication with Auth0.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/public", () => "Public endpoint");
app.MapGet("/api/private", () => "Private endpoint").RequireAuthorization();

app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/public", () => "Public endpoint");
app.MapGet("/api/private", () => "Private endpoint").RequireAuthorization();

app.Run();
```

#### Key Changes
1. Import `Auth0.AspNetCore.Authentication.Api` namespace
2. Replace `AddAuthentication().AddJwtBearer()` with `AddAuth0ApiAuthentication()`
3. Set `options.Domain` instead of constructing `Authority`
4. Move `Audience` into `options.JwtBearerOptions`

---

### 2. Custom Authentication Scheme

If you're using a custom authentication scheme name instead of the default.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("MyCustomScheme")
    .AddJwtBearer("MyCustomScheme", options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
    });

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder("MyCustomScheme")
        .RequireAuthenticatedUser()
        .Build();
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication("MyCustomScheme", options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder("MyCustomScheme")
        .RequireAuthenticatedUser()
        .Build();
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.Run();
```

#### Key Changes
1. Pass scheme name as first parameter to `AddAuth0ApiAuthentication()`
2. Authorization policies reference the same scheme name (unchanged)

---

### 3. Custom Token Validation Parameters

When you need fine-grained control over token validation.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
            NameClaimType = "name",
            RoleClaimType = "https://myapp.com/roles"
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
            NameClaimType = "name",
            RoleClaimType = "https://myapp.com/roles"
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### Key Changes
1. Move `TokenValidationParameters` into `options.JwtBearerOptions`
2. All validation settings remain exactly the same

---

### 4. Custom JWT Bearer Events

If you're handling custom JWT Bearer events like token validation, authentication failure, etc.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
        
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token received: {HasToken}", 
                    !string.IsNullOrEmpty(context.Token));
                return Task.CompletedTask;
            },
            
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                var userId = context.Principal?.FindFirst("sub")?.Value;
                logger.LogInformation("Token validated for user: {UserId}", userId);
                return Task.CompletedTask;
            },
            
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            },
            
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogWarning("Authentication challenge issued");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        
        Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token received: {HasToken}", 
                    !string.IsNullOrEmpty(context.Token));
                return Task.CompletedTask;
            },
            
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                var userId = context.Principal?.FindFirst("sub")?.Value;
                logger.LogInformation("Token validated for user: {UserId}", userId);
                return Task.CompletedTask;
            },
            
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            },
            
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogWarning("Authentication challenge issued");
                return Task.CompletedTask;
            }
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### Key Changes
1. Move entire `Events` object into `options.JwtBearerOptions`
2. All event handlers remain **completely unchanged**

---

### 5. Multiple Audiences

Supporting multiple API identifiers/audiences.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudiences = new[]
            {
                builder.Configuration["Auth0:Audience:Api"],
                builder.Configuration["Auth0:Audience:Legacy"]
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudiences = new[]
            {
                builder.Configuration["Auth0:Audience:Api"],
                builder.Configuration["Auth0:Audience:Legacy"]
            }
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### Key Changes
1. Move `ValidAudiences` into `options.JwtBearerOptions.TokenValidationParameters`
2. When using multiple audiences, you don't set single `Audience` property

---

### 6. Custom Token Retrieval

Extracting tokens from query strings, cookies, or custom headers.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
        
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Try query string first (for SignalR, etc.)
                var token = context.Request.Query["access_token"].FirstOrDefault();
                
                // Fallback to custom header
                if (string.IsNullOrEmpty(token))
                {
                    token = context.Request.Headers["X-API-Token"].FirstOrDefault();
                }
                
                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                }
                
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        
        Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Try query string first (for SignalR, etc.)
                var token = context.Request.Query["access_token"].FirstOrDefault();
                
                // Fallback to custom header
                if (string.IsNullOrEmpty(token))
                {
                    token = context.Request.Headers["X-API-Token"].FirstOrDefault();
                }
                
                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                }
                
                return Task.CompletedTask;
            }
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### Key Changes
1. Move custom `OnMessageReceived` event into `options.JwtBearerOptions.Events`
2. Token retrieval logic remains **identical**

---

### 7. Using AuthenticationBuilder

If you're explicitly working with `AuthenticationBuilder` for multiple authentication schemes.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

var authBuilder = builder.Services.AddAuthentication();

// Add Auth0 JWT Bearer
authBuilder.AddJwtBearer("Auth0", options =>
{
    options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
    options.Audience = builder.Configuration["Auth0:Audience"];
});

// Add another authentication scheme (e.g., API Key)
authBuilder.AddScheme<ApiKeyAuthOptions, ApiKeyAuthHandler>("ApiKey", options => { });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

var authBuilder = builder.Services.AddAuthentication();

// Add Auth0 authentication
authBuilder.AddAuth0ApiAuthentication("Auth0", options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

// Add another authentication scheme (e.g., API Key)
authBuilder.AddScheme<ApiKeyAuthOptions, ApiKeyAuthHandler>("ApiKey", options => { });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

#### Key Changes
1. Replace `.AddJwtBearer()` with `.AddAuth0ApiAuthentication()` on the `AuthenticationBuilder`
2. Other authentication schemes remain unchanged

---

### 8. Controllers with [Authorize] Attribute

Using controllers with attribute-based authorization.

#### Before (JWT Bearer)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new[] { "Product1", "Product2" });
    }

    [HttpGet("{id}")]
    [Authorize]
    public IActionResult Get(int id)
    {
        var userId = User.FindFirst("sub")?.Value;
        return Ok(new { id, userId });
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public IActionResult Create([FromBody] ProductModel product)
    {
        return CreatedAtAction(nameof(Get), new { id = product.Id }, product);
    }
}

public record ProductModel(int Id, string Name);
```

#### After (Auth0.AspNetCore.Authentication.Api)

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new[] { "Product1", "Product2" });
    }

    [HttpGet("{id}")]
    [Authorize]
    public IActionResult Get(int id)
    {
        var userId = User.FindFirst("sub")?.Value;
        return Ok(new { id, userId });
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public IActionResult Create([FromBody] ProductModel product)
    {
        return CreatedAtAction(nameof(Get), new { id = product.Id }, product);
    }
}

public record ProductModel(int Id, string Name);
```

#### Key Changes
1. Controllers and `[Authorize]` attributes remain **completely unchanged**
2. User claims access (`User.FindFirst()`) works **exactly the same**
3. Role-based and policy-based authorization continues to work **as-is**

---

## Step-by-Step Migration Instructions

Follow these steps to migrate your application:

### Step 1: Install the Package

```bash
dotnet add package Auth0.AspNetCore.Authentication.Api
```

**Note:** You can optionally remove the explicit `Microsoft.AspNetCore.Authentication.JwtBearer` package reference since it's included as a dependency, but this is not required.

### Step 2: Update Using Statements

Add the Auth0 namespace to your `Program.cs` or `Startup.cs`:

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer; // Still needed for JwtBearerOptions
```

### Step 3: Update Configuration Code

**Find this pattern:**
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
        options.Audience = builder.Configuration["Auth0:Audience"];
        // ... other options
    });
```

**Replace with:**
```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
        // ... move other JwtBearerOptions properties here
    };
});
```

### Step 4: Move JWT Bearer Options

Take all properties you previously configured on `JwtBearerOptions` and nest them inside `options.JwtBearerOptions`:

- `Audience` → `options.JwtBearerOptions.Audience`
- `TokenValidationParameters` → `options.JwtBearerOptions.TokenValidationParameters`
- `Events` → `options.JwtBearerOptions.Events`
- `MetadataAddress` → `options.JwtBearerOptions.MetadataAddress`
- `RequireHttpsMetadata` → `options.JwtBearerOptions.RequireHttpsMetadata`
- And any other `JwtBearerOptions` properties

### Step 5: Update appsettings.json (if needed)

Ensure your `appsettings.json` has the Auth0 configuration:

```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

**Important:** The `Domain` should be just the domain name (e.g., `my-app.auth0.com`), **not** the full URL with `https://`.

### Step 6: Build and Test

```bash
dotnet build
```

If the build succeeds, run your application:

```bash
dotnet run
```

### Step 7: Verify Authentication

Test your protected endpoints:

1. **Without token** - Should return `401 Unauthorized`
2. **With valid token** - Should return `200 OK` with expected data
3. **With expired token** - Should return `401 Unauthorized`
4. **With invalid token** - Should return `401 Unauthorized`

---

## Enabling DPoP (Optional)

Once you've successfully migrated, you can optionally enable DPoP for enhanced security. This is completely optional and doesn't affect existing Bearer token authentication.

### What is DPoP?

DPoP (Demonstration of Proof-of-Possession) binds access tokens to cryptographic keys, making stolen tokens useless to attackers. Learn more: [Auth0 DPoP Documentation](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)

### Enable DPoP with Default Settings

Simply add `.WithDPoP()` after `AddAuth0ApiAuthentication()`:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(); // ⭐ Enable DPoP support
```

**Default behavior:** Accepts both DPoP tokens and regular Bearer tokens (gradual adoption mode).

### DPoP Modes

Configure DPoP enforcement level:

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
    // Choose one:
    dpopOptions.Mode = DPoPModes.Allowed;   // Accept both DPoP and Bearer (default)
    dpopOptions.Mode = DPoPModes.Required;  // Only accept DPoP tokens
    dpopOptions.Mode = DPoPModes.Disabled;  // Standard JWT Bearer only
});
```

### Gradual DPoP Adoption Strategy

1. **Phase 1:** Enable `DPoPModes.Allowed` (accepts both token types)
2. **Phase 2:** Update clients to use DPoP tokens
3. **Phase 3:** Switch to `DPoPModes.Required` once all clients are upgraded

---

## Security Considerations

### What Improves After Migration

#### Token Security Enhancements
- ✅ **DPoP Support Available** - Optional proof-of-possession prevents token replay attacks
- ✅ **Auth0-Optimized Validation** - Best practices for Auth0 token validation built-in
- ✅ **Future-Proof** - Ready for Auth0's latest security features

#### No Security Regressions
- ✅ **Identical Token Validation** - Same JWKS endpoint, signing key validation
- ✅ **Same Issuer/Audience Checks** - No weakening of validation rules
- ✅ **Claim Handling Unchanged** - Claims extracted identically
- ✅ **HTTPS Requirements** - Same HTTPS enforcement

### Security Testing Recommendations

After migration, verify security posture:

```bash
# 1. Test expired token rejection
curl -H "Authorization: Bearer <expired-token>" https://localhost:5001/api/protected
# Expected: 401 Unauthorized

# 2. Test tampered token rejection  
curl -H "Authorization: Bearer <modified-token>" https://localhost:5001/api/protected
# Expected: 401 Unauthorized

# 3. Test wrong audience rejection
curl -H "Authorization: Bearer <wrong-audience-token>" https://localhost:5001/api/protected
# Expected: 401 Unauthorized

# 4. Test wrong issuer rejection
curl -H "Authorization: Bearer <wrong-issuer-token>" https://localhost:5001/api/protected
# Expected: 401 Unauthorized
```

### Logging and Monitoring

Ensure security events are logged:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        
        Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // Log authentication failures for security monitoring
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                    
                logger.LogWarning(
                    "Authentication failed: {Exception}. Request: {Method} {Path}",
                    context.Exception.Message,
                    context.Request.Method,
                    context.Request.Path);
                    
                return Task.CompletedTask;
            }
        }
    };
});
```

### Security Checklist

After migration:
- [ ] Token expiration is enforced
- [ ] Invalid signatures are rejected
- [ ] Wrong audience tokens are rejected
- [ ] Wrong issuer tokens are rejected
- [ ] HTTPS is enforced in production
- [ ] Sensitive claims are not logged
- [ ] Failed auth attempts are logged
- [ ] No bearer tokens in logs/errors
- [ ] Rate limiting still works (if implemented)
- [ ] CORS policies unchanged

---

## Verification Steps

After migration, verify these key areas:

### 1. Build Verification
```bash
# Clean build to ensure no compilation errors
dotnet clean
dotnet build --configuration Release
```

**Expected:** Build succeeds with no errors or warnings.

### 2. Authentication Works
```bash
# Test with your existing access token
curl -H "Authorization: Bearer YOUR_TOKEN" https://localhost:5001/api/protected
```

**Expected:** `200 OK` with protected data.

### 3. Unauthorized Access Rejected
```bash
# Test without token
curl https://localhost:5001/api/protected
```

**Expected:** `401 Unauthorized`.

### 4. Invalid Token Rejected
```bash
# Test with malformed token
curl -H "Authorization: Bearer invalid.token.here" https://localhost:5001/api/protected
```

**Expected:** `401 Unauthorized`.

### 5. Authorization Policies Work
If you have custom policies, verify they still work:
```csharp
app.MapGet("/api/admin", () => "Admin only")
    .RequireAuthorization("AdminPolicy");
```

**Expected:** Policy enforcement unchanged.

### 6. Claims Are Accessible
Verify user claims are still accessible:
```csharp
app.MapGet("/api/user", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    var email = context.User.FindFirst("email")?.Value;
    return Results.Ok(new { userId, email });
}).RequireAuthorization();
```

**Expected:** Claims extracted correctly.

### 7. Custom Events Fire
If you have custom JWT Bearer events, add logging to verify they're still called:
```csharp
OnTokenValidated = context =>
{
    Console.WriteLine("Token validated - event fired successfully!");
    return Task.CompletedTask;
}
```

**Expected:** Log messages appear during authentication.

### 8. Multiple Audiences Validate
If using multiple audiences, test tokens for each audience.

**Expected:** All valid audiences accepted.

### 9. Performance Baseline
```bash
# Compare response times before and after
ab -n 1000 -c 10 -H "Authorization: Bearer YOUR_TOKEN" https://localhost:5001/api/protected
```

**Expected:** Similar or identical performance.

### 10. Integration Tests Pass
```bash
# Run existing integration tests
dotnet test --filter Category=Integration
```

**Expected:** All tests pass without modification.

---

## Testing Your Migration

### Recommended Testing Strategy

#### Phase 1: Local Development (30 minutes)
1. **Unit tests** - Run existing unit test suite
   ```bash
   dotnet test --filter Category=Unit
   ```
2. **Manual testing** - Test protected endpoints with Postman/curl
3. **Event verification** - Confirm custom events still fire
4. **Claims inspection** - Verify all expected claims are present

#### Phase 2: Integration Environment (1-2 hours)
1. **Deploy to test/dev** - Deploy migrated code to non-production
2. **Smoke tests** - Run automated smoke test suite
3. **Load testing** - Verify performance under load
   ```bash
   dotnet run --configuration Release
   k6 run load-test.js  # or your load testing tool
   ```
4. **Monitor logs** - Check for authentication errors

#### Phase 3: Staging/Pre-Production (1-2 days)
1. **Soak testing** - Run for 24-48 hours
2. **Monitor metrics** - Track error rates, response times
3. **Client testing** - Have client applications test against staging
4. **DPoP testing** (if enabled) - Test DPoP token flows

#### Phase 4: Production Deployment
1. **Gradual rollout** - Use blue/green or canary deployment if possible
2. **Monitor closely** - Watch authentication metrics
3. **Rollback ready** - Have rollback plan prepared (see below)

### Automated Test Examples

Add these integration tests to verify migration success:

```csharp
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Headers;
using Xunit;

public class MigrationVerificationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public MigrationVerificationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ProtectedEndpoint_WithValidToken_ReturnsSuccess()
    {
        // Arrange
        var validToken = "your-valid-test-token";
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", validToken);

        // Act
        var response = await _client.GetAsync("/api/protected");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutToken_ReturnsUnauthorized()
    {
        // Act
        var response = await _client.GetAsync("/api/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithInvalidToken_ReturnsUnauthorized()
    {
        // Arrange
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", "invalid.token");

        // Act
        var response = await _client.GetAsync("/api/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithValidToken_ReturnsExpectedClaims()
    {
        // Arrange
        var validToken = "your-valid-test-token";
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", validToken);

        // Act
        var response = await _client.GetAsync("/api/user-info");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Contains("sub", content);
        Assert.Contains("expected-user-id", content);
    }
}
```

### Manual Testing Checklist

Print and check off each item:

- [ ] Public endpoints still accessible without auth
- [ ] Protected endpoints require valid token
- [ ] Invalid tokens are rejected (401)
- [ ] Expired tokens are rejected (401)
- [ ] All expected claims are present in User.Claims
- [ ] Custom authorization policies work
- [ ] Role-based authorization works
- [ ] Scope-based authorization works
- [ ] Custom JWT events are invoked
- [ ] Error responses match previous behavior
- [ ] Performance is equivalent or better
- [ ] Logs show expected auth flow

---

## Rollback Strategy

### When to Rollback

Consider rolling back if:
- ❌ Authentication fails in production
- ❌ Unexpected 401 errors spike
- ❌ Performance degrades significantly
- ❌ Claims are missing or incorrect
- ❌ Custom events stop firing

### Rollback Procedure

#### Option 1: Package Rollback (Fastest - 2 minutes)

```bash
# 1. Remove Auth0 package
dotnet remove package Auth0.AspNetCore.Authentication.Api

# 2. Re-add JWT Bearer (if removed)
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.0

# 3. Revert code changes
git checkout HEAD -- Program.cs  # or your auth configuration file

# 4. Rebuild and deploy
dotnet build
dotnet publish
```

#### Option 2: Git Revert (5 minutes)

```bash
# 1. Find the migration commit
git log --oneline

# 2. Revert the migration commit
git revert <commit-hash>

# 3. Rebuild and deploy
dotnet build
dotnet publish
```

#### Option 3: Deployment Rollback (Instant)

If using deployment slots or containers:

```bash
# Azure App Service
az webapp deployment slot swap --name myapp --resource-group mygroup --slot staging --target-slot production

# Kubernetes
kubectl rollout undo deployment/myapi

# Docker
docker-compose up -d --force-recreate  # with previous image
```

### Post-Rollback Verification

After rollback:

1. **Verify authentication works** - Test with valid token
2. **Check error rates** - Monitor application insights/logs
3. **Client verification** - Confirm clients can authenticate
4. **Document issue** - Create GitHub issue with details for future retry

### Safe Migration Strategy

To minimize rollback risk:

1. **Use feature flags** - Toggle between old and new auth
   ```csharp
   if (builder.Configuration.GetValue<bool>("UseAuth0SDK"))
   {
       builder.Services.AddAuth0ApiAuthentication(/* ... */);
   }
   else
   {
       builder.Services.AddJwtBearer(/* ... */);
   }
   ```

2. **Blue/Green deployment** - Run both versions simultaneously
3. **Canary deployment** - Roll out to 10%, 50%, 100% gradually
4. **Database flag** - Control via runtime configuration

---

## Common Issues and Solutions

### 1. "InvalidOperationException: IDX10205: Issuer validation failed"

**Symptom:** Authentication fails with issuer validation error.

**Cause:** Domain is configured incorrectly (likely includes `https://` prefix).

**Solution:** 
```csharp
// ❌ WRONG - Don't include https://
options.Domain = "https://my-tenant.auth0.com";

// ✅ CORRECT - Domain only
options.Domain = "my-tenant.auth0.com";
```

---

### 2. "InvalidOperationException: The Audience must not be null or empty"

**Symptom:** Application fails to start with audience validation error.

**Cause:** Audience not configured in `JwtBearerOptions`.

**Solution:**
```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"] // ✅ Must be set
    };
});
```

---

### 3. "ArgumentNullException: Value cannot be null. (Parameter 'configureOptions')"

**Symptom:** Application fails to start with null parameter error.

**Cause:** Missing configuration action.

**Solution:**
```csharp
// ❌ WRONG - Missing configuration
builder.Services.AddAuth0ApiAuthentication();

// ✅ CORRECT - Provide configuration action
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
});
```

---

### 4. Custom Events Not Firing

**Symptom:** JWT Bearer events you configured aren't being called.

**Cause:** Events not moved into `JwtBearerOptions`.

**Solution:**
```csharp
// ❌ WRONG - Events at wrong level
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.Events = new JwtBearerEvents { /* ... */ }; // This doesn't exist!
});

// ✅ CORRECT - Events inside JwtBearerOptions
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        Events = new JwtBearerEvents { /* ... */ } // ✅ Correct location
    };
});
```

---

### 5. "Multiple audiences but validation fails"

**Symptom:** Token with secondary audience is rejected.

**Cause:** Using single `Audience` property instead of `ValidAudiences`.

**Solution:**
```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudiences = new[] // ✅ Use ValidAudiences for multiple
            {
                "https://api1.example.com",
                "https://api2.example.com"
            }
        }
    };
});
```

---

### 6. Authorization Policies Not Working

**Symptom:** `[Authorize]` attribute or `.RequireAuthorization()` not enforcing authentication.

**Cause:** Missing `app.UseAuthentication()` or `app.UseAuthorization()` in middleware pipeline.

**Solution:**
```csharp
var app = builder.Build();

app.UseAuthentication(); // ✅ Must be called before UseAuthorization
app.UseAuthorization();  // ✅ Must be called before endpoint mapping

app.MapControllers();
app.Run();
```

**Order matters!** Authentication must come before authorization.

---

### 7. "No authenticationScheme was specified"

**Symptom:** Authentication challenges fail with scheme error.

**Cause:** Multiple authentication schemes without a default.

**Solution:**
```csharp
// Option 1: Set default scheme explicitly
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Auth0";
    options.DefaultChallengeScheme = "Auth0";
}).AddAuth0ApiAuthentication("Auth0", options =>
{
    // ... configuration
});

// Option 2: Specify scheme in authorization
app.MapGet("/api/protected", () => "Protected")
    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Auth0" });
```

---

### 8. DPoP Tokens Rejected After Enabling

**Symptom:** DPoP tokens return `401 Unauthorized` after enabling DPoP.

**Cause:** Client not sending proper DPoP proof or configuration mismatch.

**Solution:**

1. **Verify client is sending DPoP header:**
```
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IlJTMjU2IiwiandrIjp7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwia2lkIjoiZGlkOndlYjpleGFtcGxlLmNvbSIsIm4iOiJ4T...
```

2. **Check DPoP mode:**
```csharp
.WithDPoP(dpopOptions =>
{
    dpopOptions.Mode = DPoPModes.Allowed; // Start with Allowed mode
});
```

3. **Verify token is DPoP-bound:** The access token must have `cnf` claim.

4. **Check logs for specific DPoP validation errors.**

---

### 9. Build Errors After Migration

**Symptom:** Compilation errors referencing `JwtBearerDefaults` or `JwtBearerOptions`.

**Cause:** Missing using statement.

**Solution:**
```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer; // ✅ Still needed!
```

Even though you're using `Auth0.AspNetCore.Authentication.Api`, you still need the JWT Bearer namespace for `JwtBearerOptions` and `JwtBearerEvents`.

---

### 10. Configuration Values Are Null

**Symptom:** `Auth0:Domain` or `Auth0:Audience` configuration returns null.

**Cause:** Missing or incorrect `appsettings.json` configuration.

**Solution:**

1. **Verify `appsettings.json`:**
```json
{
  "Auth0": {
    "Domain": "your-tenant.auth0.com",
    "Audience": "https://your-api-identifier"
  }
}
```

2. **Check configuration is loaded:**
```csharp
var domain = builder.Configuration["Auth0:Domain"];
if (string.IsNullOrEmpty(domain))
{
    throw new InvalidOperationException(
        "Auth0:Domain configuration is missing. Check appsettings.json");
}
```

3. **Verify appsettings file is copied to output:**
Check `.csproj` file has:
```xml
<ItemGroup>
  <Content Include="appsettings.json">
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </Content>
</ItemGroup>
```

---

## Getting Help

If you encounter issues not covered in this guide:

### 📖 Documentation
- **README:** [Complete feature documentation](./README.md)
- **Examples:** [Comprehensive code examples](./EXAMPLES.md)
- **Auth0 Docs:** [Auth0 DPoP Documentation](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)

### 🐛 GitHub Issues
We're here to help! If you run into any problems during migration:

1. **Check existing issues:** [Search for similar problems](https://github.com/auth0/aspnetcore-api/issues)
2. **Create a new issue:** [Report your issue](https://github.com/auth0/aspnetcore-api/issues/new)

When reporting an issue, please include:
- Your current JWT Bearer configuration (sanitized)
- Error messages or stack traces
- .NET version and package versions
- What you've already tried

---

## Complete Migration Checklist

### Pre-Migration
- [ ] Code committed to version control
- [ ] .NET 8.0+ installed and verified
- [ ] Auth0 Domain and Audience values documented
- [ ] Current authentication working and tested
- [ ] Existing test suite passing
- [ ] Non-production environment available for testing

### Migration Steps
- [ ] Package installed: `dotnet add package Auth0.AspNetCore.Authentication.Api`
- [ ] Using statement added: `using Auth0.AspNetCore.Authentication.Api;`
- [ ] Code updated: `AddJwtBearer()` → `AddAuth0ApiAuthentication()`
- [ ] Domain configured: `options.Domain = "..."`
- [ ] JWT options nested: `options.JwtBearerOptions = new JwtBearerOptions { ... }`
- [ ] Custom events moved (if any): `options.JwtBearerOptions.Events = ...`
- [ ] Custom validation moved (if any): `options.JwtBearerOptions.TokenValidationParameters = ...`
- [ ] Configuration file updated (if needed): `appsettings.json`

### Build & Local Testing
- [ ] Clean build successful: `dotnet clean && dotnet build`
- [ ] Application starts without errors
- [ ] Protected endpoint with valid token: ✅ 200 OK
- [ ] Protected endpoint without token: ✅ 401 Unauthorized
- [ ] Protected endpoint with invalid token: ✅ 401 Unauthorized
- [ ] Public endpoints still accessible
- [ ] User claims accessible in endpoints
- [ ] Authorization policies enforced correctly
- [ ] Custom events firing (if applicable)
- [ ] Unit tests passing
- [ ] Integration tests passing

### Non-Production Testing
- [ ] Deployed to dev/test environment
- [ ] Smoke tests passing
- [ ] Load tests showing equivalent performance
- [ ] Monitoring logs for errors
- [ ] Client applications tested successfully
- [ ] 24-hour soak test completed (staging)

### Production Deployment
- [ ] Deployment plan reviewed
- [ ] Rollback procedure documented and ready
- [ ] Monitoring dashboards prepared
- [ ] Alerts configured for auth failures
- [ ] Deployed to production
- [ ] Authentication success rate monitored
- [ ] Error rates normal
- [ ] Performance metrics acceptable
- [ ] No client complaints within 1 hour
- [ ] Logs reviewed for unexpected errors

### Post-Migration
- [ ] Old package references removed (optional)
- [ ] Documentation updated
- [ ] Team notified of changes
- [ ] Monitoring continued for 48 hours
- [ ] Migration marked as successful

### Optional: DPoP Enablement
- [ ] DPoP requirements understood
- [ ] `.WithDPoP()` added to configuration
- [ ] DPoP mode configured (`Allowed` or `Required`)
- [ ] Client applications updated to send DPoP proofs
- [ ] DPoP tokens validated successfully
- [ ] Gradual rollout completed

---

*Happy migrating! 🚀*
