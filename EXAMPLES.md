# Auth0 ASP.NET Core API - Code Examples

This document provides practical, copy-pastable code examples for common scenarios when using the Auth0 ASP.NET Core API Authentication SDK.

## Table of Contents

1. **Getting Started**
   - 1.1 [Basic JWT Authentication](#11-basic-jwt-authentication)
   - 1.2 [Protecting Minimal API Endpoints](#12-protecting-minimal-api-endpoints)
   - 1.3 [Protecting Controller Endpoints](#13-protecting-controller-endpoints)
2. **Configuration**
   - 2.1 [Custom Token Validation Parameters](#21-custom-token-validation-parameters)
3. **DPoP (Demonstration of Proof-of-Possession)**
   - 3.1 [Enabling DPoP with Default Settings](#31-enabling-dpop-with-default-settings)
   - 3.2 [DPoP in Allowed Mode (Gradual Adoption)](#32-dpop-in-allowed-mode-gradual-adoption)
   - 3.3 [DPoP in Required Mode (Strict Security)](#33-dpop-in-required-mode-strict-security)
4. **Multiple Custom Domains**
   - 4.1 [Basic Custom Domains Configuration](#41-basic-custom-domains-configuration)
   - 4.2 [Dynamic Domain Resolution](#42-dynamic-domain-resolution)
   - 4.3 [Custom Cache Configuration](#43-custom-cache-configuration)
5. **Authorization**
   - 5.1 [Scope-Based Authorization with Policies](#51-scope-based-authorization-with-policies)
   - 5.2 [Permission-Based Authorization](#52-permission-based-authorization)
   - 5.3 [Custom Authorization Handler](#53-custom-authorization-handler)
   - 5.4 [Role-Based Authorization](#54-role-based-authorization)
6. **Advanced Scenarios**
   - 6.1 [Accessing User Claims](#61-accessing-user-claims)
   - 6.2 [Custom JWT Bearer Events](#62-custom-jwt-bearer-events)
   - 6.3 [Token Extraction from Query String](#63-token-extraction-from-query-string)
   - 6.4 [Custom Error Responses](#64-custom-error-responses)
7. **Integration Examples**
   - 7.1 [SignalR Integration](#71-signalr-integration)

---

## Getting Started

### 1.1 Basic JWT Authentication

Basic setup for Auth0 JWT authentication in a minimal API.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Add Auth0 JWT authentication
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

app.MapGet("/", () => "Hello, World!");

app.Run();
```

---

### 1.2 Protecting Minimal API Endpoints

Protect endpoints using `RequireAuthorization()` in minimal APIs.

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

// Public endpoint - no authentication required
app.MapGet("/api/public", () => Results.Ok(new { message = "This is a public endpoint" }));

// Protected endpoint - requires authentication
app.MapGet("/api/protected", () => Results.Ok(new { message = "You are authenticated!" }))
    .RequireAuthorization();

// Protected endpoint with user information
app.MapGet("/api/user", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    var email = context.User.FindFirst("email")?.Value;
    
    return Results.Ok(new { userId, email });
})
.RequireAuthorization();

app.Run();
```

---

### 1.3 Protecting Controller Endpoints

Protect endpoints using `[Authorize]` attribute in controllers.

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
public class DataController : ControllerBase
{
    // Public endpoint
    [HttpGet("public")]
    public IActionResult GetPublic()
    {
        return Ok(new { message = "This is a public endpoint" });
    }

    // Protected endpoint
    [Authorize]
    [HttpGet("protected")]
    public IActionResult GetProtected()
    {
        var userId = User.FindFirst("sub")?.Value;
        return Ok(new { message = "You are authenticated!", userId });
    }

    // Protected POST endpoint
    [Authorize]
    [HttpPost]
    public IActionResult CreateData([FromBody] DataModel data)
    {
        return CreatedAtAction(nameof(GetProtected), new { id = data.Id }, data);
    }
}

public record DataModel(int Id, string Name);
```

---

## Configuration

### 2.1 Custom Token Validation Parameters

Customize JWT token validation with specific parameters.

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
        RequireHttpsMetadata = true,
        SaveToken = true,
        
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            NameClaimType = "name",
            RoleClaimType = "https://schemas.auth0.com/roles"
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/protected", () => Results.Ok(new { message = "Token validated with custom parameters" }))
    .RequireAuthorization();

app.Run();
```

---

## DPoP (Demonstration of Proof-of-Possession)

DPoP is a security mechanism that binds access tokens to cryptographic keys, preventing token theft and replay attacks. This SDK provides seamless DPoP integration with flexible enforcement modes.

### 3.1 Enabling DPoP with Default Settings

Enable DPoP with a single method call - accepts both DPoP and Bearer tokens.

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
}).WithDPoP(); // ✨ Enable DPoP with default settings (Allowed mode)

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// This endpoint works with both:
// 1. DPoP tokens (Authorization: DPoP <token> + DPoP: <proof>)
// 2. Bearer tokens (Authorization: Bearer <token>)
app.MapGet("/api/data", () => Results.Ok(new { message = "Supports both DPoP and Bearer tokens" }))
    .RequireAuthorization();

app.Run();
```

**What this does:**
- Enables DPoP validation in **Allowed mode** (default)
- Accepts DPoP-bound tokens with proof validation
- Still accepts regular Bearer tokens for backward compatibility
- Uses default time validation settings (300s iat offset, 30s leeway)

---

### 3.2 DPoP in Allowed Mode (Gradual Adoption)

Use Allowed mode to gradually adopt DPoP without breaking existing clients using Bearer tokens.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Auth0.AspNetCore.Authentication.Api.DPoP;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(dpopOptions =>
{
    // Explicitly set to Allowed mode (this is the default)
    dpopOptions.Mode = DPoPModes.Allowed;
    
    // Customize time validation
    dpopOptions.IatOffset = 300; // Allow DPoP proof tokens up to 5 minutes old
    dpopOptions.Leeway = 30;     // 30 seconds clock skew tolerance
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/legacy", () => 
    Results.Ok(new { message = "Works with Bearer tokens from legacy clients" }))
    .RequireAuthorization();

app.MapGet("/api/modern", () => 
    Results.Ok(new { message = "Works with DPoP tokens from modern clients" }))
    .RequireAuthorization();

app.Run();
```

**Use this when:**
- You're migrating from Bearer tokens to DPoP
- You have mixed clients (some support DPoP, some don't)
- You want to test DPoP without forcing all clients to upgrade
- You need a gradual rollout strategy

**Security note:** Allowed mode provides backward compatibility but doesn't enforce the full security benefits of DPoP for Bearer tokens.

---

### 3.3 DPoP in Required Mode (Strict Security)

Use Required mode when you want maximum security - only DPoP tokens are accepted.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Auth0.AspNetCore.Authentication.Api.DPoP;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP(dpopOptions =>
{
    // Only accept DPoP tokens, reject Bearer tokens
    dpopOptions.Mode = DPoPModes.Required;
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// This endpoint ONLY accepts DPoP tokens
// Bearer tokens will be rejected with 401 Unauthorized
app.MapGet("/api/high-security", () => 
    Results.Ok(new { message = "DPoP token verified successfully" }))
    .RequireAuthorization();

app.Run();
```

---

## Multiple Custom Domains

Multiple Custom Domains enables the same code to accept tokens from multiple custom domains.

### 4.1 Basic Custom Domains Configuration

Configure a static list of allowed Auth0 domains for multi-tenant scenarios.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
})
.WithCustomDomains(customDomainsOptions =>
{
    // Static list of allowed Auth0 domains
    customDomainsOptions.Domains = new[]
    {
        "tenant1.auth0.com",
        "tenant2.auth0.com",
        "tenant3.eu.auth0.com"
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// This endpoint accepts tokens from any of the configured domains
app.MapGet("/api/data", () => 
    Results.Ok(new { message = "Authenticated from any allowed domain" }))
    .RequireAuthorization();

app.Run();
```

**What this does:**
- Accepts JWT tokens issued by any domain in the `Domains` list
- Automatically validates token issuer against the allowed list
- Rejects tokens from unauthorized domains with 401 Unauthorized
- Uses in-memory cache for OIDC configurations (100 entries, 10-minute sliding expiration)

**Use this when:**
- You have a fixed set of Auth0 tenants (e.g., different regions or customer tiers)
- Domain list is known at application startup
- You need simple, straightforward multi-tenant configuration

---

### 4.2 Dynamic Domain Resolution

Resolve allowed domains dynamically at runtime based on request context, database lookups, or external APIs.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Example: Register a tenant service for domain resolution
builder.Services.AddSingleton<ITenantService, TenantService>();

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
})
.WithCustomDomains(customDomainsOptions =>
{
    // Dynamic domain resolution using request context
    customDomainsOptions.DomainsResolver = async (httpContext, cancellationToken) =>
    {
        // Example 1: Resolve from header
        var tenantId = httpContext.Request.Headers["X-Tenant-Id"].FirstOrDefault();
        
        // Example 2: Resolve from database
        var tenantService = httpContext.RequestServices.GetRequiredService<ITenantService>();
        var domains = await tenantService.GetAllowedDomainsAsync(tenantId, cancellationToken);
        
        return domains;
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/tenant-data", () => 
    Results.Ok(new { message = "Domain resolved dynamically" }))
    .RequireAuthorization();

app.Run();

```

**What this does:**
- Resolves allowed domains dynamically for each request
- Provides full `HttpContext` access for custom resolution logic
- Supports database queries, external API calls, or complex business logic
- Enables true multi-tenant SaaS architectures

**Use this when:**
- Domains are not known at startup (e.g., customer onboarding creates new tenants)
- You need request-specific domain resolution (headers, query params, claims)
- Tenant configuration is stored in a database or external service
- Building a white-label SaaS with customer-specific Auth0 tenants

**Important:** `DomainsResolver` and `Domains` are mutually exclusive - configure only one.

---

### 4.3 Custom Cache Configuration

Customize the OIDC configuration cache behavior for performance optimization.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
})
.WithCustomDomains(customDomainsOptions =>
{
    customDomainsOptions.Domains = new[]
    {
        "tenant1.auth0.com",
        "tenant2.auth0.com"
    };
    
    // Customize cache settings
    customDomainsOptions.ConfigurationManagerCache = new MemoryConfigurationManagerCache(
        maxSize: 50,  // Maximum number of cached configurations
        slidingExpiration: TimeSpan.FromMinutes(15)  // Cache entry expiration
    );
    
    // Customize OIDC refresh intervals
    customDomainsOptions.AutomaticRefreshInterval = TimeSpan.FromHours(24);
    customDomainsOptions.RefreshInterval = TimeSpan.FromMinutes(10);
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/cached", () => 
    Results.Ok(new { message = "Using custom cache configuration" }))
    .RequireAuthorization();

app.Run();
```

**Alternative - Disable Caching:**
```csharp
.WithCustomDomains(customDomainsOptions =>
{
    customDomainsOptions.Domains = new[] { "tenant1.auth0.com" };
    
    // Disable caching entirely (fetch OIDC config on every request)
    customDomainsOptions.ConfigurationManagerCache = new NullConfigurationManagerCache();
});
```
---

## Authorization

### 5.1 Scope-Based Authorization with Policies

Validate scopes from Auth0 access tokens using authorization policies.

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

// Define scope-based authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("read:data", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c =>
                c.Type == "scope" &&
                c.Value.Split(' ').Contains("read:data"))));
    
    options.AddPolicy("write:data", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c =>
                c.Type == "scope" &&
                c.Value.Split(' ').Contains("write:data"))));
    
    options.AddPolicy("delete:data", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c =>
                c.Type == "scope" &&
                c.Value.Split(' ').Contains("delete:data"))));
});

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
    // Requires 'read:data' scope
    [Authorize(Policy = "read:data")]
    [HttpGet]
    public IActionResult GetProducts()
    {
        var products = new[] { "Product 1", "Product 2", "Product 3" };
        return Ok(products);
    }

    // Requires 'write:data' scope
    [Authorize(Policy = "write:data")]
    [HttpPost]
    public IActionResult CreateProduct([FromBody] ProductModel product)
    {
        return CreatedAtAction(nameof(GetProducts), new { id = product.Id }, product);
    }

    // Requires 'delete:data' scope
    [Authorize(Policy = "delete:data")]
    [HttpDelete("{id}")]
    public IActionResult DeleteProduct(int id)
    {
        return NoContent();
    }
}

public record ProductModel(int Id, string Name);
```

---

### 5.2 Permission-Based Authorization

Validate Auth0 permissions using custom authorization policies.

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

// Define permission-based authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanReadUsers", policy =>
        policy.RequireClaim("permissions", "read:users"));
    
    options.AddPolicy("CanCreateUsers", policy =>
        policy.RequireClaim("permissions", "create:users"));
    
    options.AddPolicy("CanDeleteUsers", policy =>
        policy.RequireClaim("permissions", "delete:users"));
});

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [Authorize(Policy = "CanReadUsers")]
    [HttpGet]
    public IActionResult GetUsers()
    {
        var users = new[] { "User 1", "User 2", "User 3" };
        return Ok(users);
    }

    [Authorize(Policy = "CanCreateUsers")]
    [HttpPost]
    public IActionResult CreateUser([FromBody] UserModel user)
    {
        return CreatedAtAction(nameof(GetUsers), new { id = user.Id }, user);
    }

    [Authorize(Policy = "CanDeleteUsers")]
    [HttpDelete("{id}")]
    public IActionResult DeleteUser(string id)
    {
        return NoContent();
    }
}

public record UserModel(string Id, string Name, string Email);
```

---

### 5.3 Custom Authorization Handler

Create a reusable authorization handler for scope validation.

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

// Register custom authorization handler
builder.Services.AddSingleton<IAuthorizationHandler, HasScopeHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("read:products", policy =>
        policy.Requirements.Add(new HasScopeRequirement("read:products")));
    
    options.AddPolicy("write:products", policy =>
        policy.Requirements.Add(new HasScopeRequirement("write:products")));
});

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Custom authorization requirement
public class HasScopeRequirement : IAuthorizationRequirement
{
    public string Scope { get; }

    public HasScopeRequirement(string scope)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
}

// Custom authorization handler
public class HasScopeHandler : AuthorizationHandler<HasScopeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        HasScopeRequirement requirement)
    {
        var scopeClaim = context.User.FindFirst(c => c.Type == "scope");

        if (scopeClaim != null)
        {
            var scopes = scopeClaim.Value.Split(' ');
            if (scopes.Contains(requirement.Scope))
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}

[ApiController]
[Route("api/[controller]")]
public class InventoryController : ControllerBase
{
    [Authorize(Policy = "read:products")]
    [HttpGet]
    public IActionResult GetInventory()
    {
        return Ok(new[] { "Item 1", "Item 2" });
    }

    [Authorize(Policy = "write:products")]
    [HttpPost]
    public IActionResult AddInventory([FromBody] InventoryItem item)
    {
        return Created($"/api/inventory/{item.Id}", item);
    }
}

public record InventoryItem(int Id, string Name, int Quantity);
```

---

### 5.4 Role-Based Authorization

Validate Auth0 roles using authorization policies.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
            RoleClaimType = "https://schemas.auth0.com/roles"
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("ManagerOrAdmin", policy => policy.RequireRole("Manager", "Admin"));
});

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    [Authorize(Policy = "AdminOnly")]
    [HttpGet("settings")]
    public IActionResult GetSettings()
    {
        return Ok(new { setting = "Admin settings" });
    }

    [Authorize(Policy = "ManagerOrAdmin")]
    [HttpGet("reports")]
    public IActionResult GetReports()
    {
        var userRoles = User.FindAll("https://schemas.auth0.com/roles")
            .Select(c => c.Value);
        
        return Ok(new { message = "Reports data", roles = userRoles });
    }
}
```

---

## Advanced Scenarios

### 6.1 Accessing User Claims

Access and use user claims from Auth0 tokens.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

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

// Access user claims in minimal API
app.MapGet("/api/profile", (HttpContext context) =>
{
    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
        ?? context.User.FindFirst("sub")?.Value;
    return Results.Ok(new { userId });
})
.RequireAuthorization();

// Access all claims
app.MapGet("/api/claims", (ClaimsPrincipal user) =>
{
    var claims = user.Claims.Select(c => new { c.Type, c.Value });
    return Results.Ok(claims);
})
.RequireAuthorization();

app.Run();
```

---

### 6.2 Custom JWT Bearer Events

Implement custom logic during JWT authentication events.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                
                var userId = context.Principal?.FindFirst("sub")?.Value;
                logger.LogInformation("Token validated for user: {UserId}", userId);
                
                // Add custom claims
                var identity = context.Principal?.Identity as ClaimsIdentity;
                identity?.AddClaim(new Claim("validated_at", DateTime.UtcNow.ToString()));
                
                return Task.CompletedTask;
            },
            
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                
                logger.LogError(context.Exception, "Authentication failed");
                
                if (context.Exception is SecurityTokenExpiredException)
                {
                    context.Response.Headers.Append("Token-Expired", "true");
                }
                
                return Task.CompletedTask;
            },
            
            OnMessageReceived = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                
                var hasToken = !string.IsNullOrEmpty(context.Token);
                logger.LogDebug("Token received: {HasToken}", hasToken);
                
                return Task.CompletedTask;
            },
            
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                
                logger.LogWarning("Authentication challenge issued: {Error}", context.Error);
                
                return Task.CompletedTask;
            }
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/protected", (ClaimsPrincipal user) =>
{
    var validatedAt = user.FindFirst("validated_at")?.Value;
    return Results.Ok(new { message = "Authenticated", validatedAt });
})
.RequireAuthorization();

app.Run();
```

---

### 6.3 Token Extraction from Query String

Extract JWT tokens from query string for scenarios like SignalR.

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
                // Check for token in query string
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                
                // Allow token from query string for specific paths (e.g., SignalR hubs)
                if (!string.IsNullOrEmpty(accessToken) && 
                    (path.StartsWithSegments("/hubs") || path.StartsWithSegments("/api/stream")))
                {
                    context.Token = accessToken;
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

// Standard endpoint - expects token in Authorization header
app.MapGet("/api/data", () => Results.Ok(new { data = "Standard endpoint" }))
    .RequireAuthorization();

// Streaming endpoint - can accept token from query string
app.MapGet("/api/stream", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    return Results.Ok(new { message = "Streaming data", userId });
})
.RequireAuthorization();

app.Run();
```

---

### 6.4 Custom Error Responses

Customize error responses for authentication failures.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions
    {
        Audience = builder.Configuration["Auth0:Audience"],
        Events = new JwtBearerEvents
        {
            OnChallenge = context =>
            {
                // Skip the default behavior
                context.HandleResponse();
                
                // Create custom error response
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                
                var errorResponse = new
                {
                    error = "unauthorized",
                    message = "Authentication is required to access this resource",
                    timestamp = DateTime.UtcNow
                };
                
                return context.Response.WriteAsync(
                    JsonSerializer.Serialize(errorResponse));
            },
            
            OnAuthenticationFailed = context =>
            {
                if (context.Exception != null)
                {
                    var logger = context.HttpContext.RequestServices
                        .GetRequiredService<ILogger<Program>>();
                    
                    logger.LogError(context.Exception, 
                        "Authentication failed: {Message}", context.Exception.Message);
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

app.MapGet("/api/protected", () => Results.Ok(new { data = "Protected resource" }))
    .RequireAuthorization();

app.Run();
```

---

## Integration Examples

### 7.1 SignalR Integration

Integrate Auth0 authentication with SignalR hubs.

```csharp
using Auth0.AspNetCore.Authentication.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

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
                // Extract token from query string for SignalR
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                
                if (!string.IsNullOrEmpty(accessToken) &&
                    path.StartsWithSegments("/hubs"))
                {
                    context.Token = accessToken;
                }
                
                return Task.CompletedTask;
            }
        }
    };
});

builder.Services.AddAuthorization();
builder.Services.AddSignalR();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapHub<ChatHub>("/hubs/chat");

app.Run();

// SignalR Hub with authentication
[Authorize]
public class ChatHub : Hub
{
    private readonly ILogger<ChatHub> _logger;

    public ChatHub(ILogger<ChatHub> logger)
    {
        _logger = logger;
    }

    public override async Task OnConnectedAsync()
    {
        var userId = Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? Context.User?.FindFirst("sub")?.Value;
        var connectionId = Context.ConnectionId;
        
        _logger.LogInformation("User {UserId} connected with ID {ConnectionId}", 
            userId, connectionId);
        
        await Clients.All.SendAsync("UserConnected", userId);
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var userId = Context.User?.FindFirst("sub")?.Value;
        
        _logger.LogInformation("User {UserId} disconnected", userId);
        
        await Clients.All.SendAsync("UserDisconnected", userId);
        await base.OnDisconnectedAsync(exception);
    }

    public async Task SendMessage(string message)
    {
        var userId = Context.User?.FindFirst("sub")?.Value;
        var userName = Context.User?.FindFirst("name")?.Value ?? "Anonymous";
        
        await Clients.All.SendAsync("ReceiveMessage", userName, message);
    }

    // Only users with specific scope can broadcast
    [Authorize(Policy = "write:messages")]
    public async Task BroadcastMessage(string message)
    {
        var userName = Context.User?.FindFirst("name")?.Value ?? "System";
        await Clients.All.SendAsync("ReceiveMessage", userName, message);
    }
}
```

---

## Getting an Auth0 Access Token

To test these examples, you'll need an access token from Auth0. Here's how to get one:

### Using cURL

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

### Making Authenticated Requests

```bash
# Replace YOUR_ACCESS_TOKEN with the token from above
curl --request GET \
  --url https://localhost:5000/api/protected \
  --header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

---

## Additional Resources

- [Auth0 Documentation](https://auth0.com/docs)
- [ASP.NET Core Authentication Documentation](https://docs.microsoft.com/aspnet/core/security/authentication/)
- [JWT Bearer Authentication](https://docs.microsoft.com/aspnet/core/security/authentication/jwt-authn)
- [Auth0 Community](https://community.auth0.com/)

---

## Support

If you have questions or need help with these examples:

- 📖 Check the [main README](README.md) for overview and setup instructions
- 💬 Visit the [Auth0 Community](https://community.auth0.com/)
- 🐛 Report issues on [GitHub Issues](https://github.com/auth0/aspnetcore-api/issues)
