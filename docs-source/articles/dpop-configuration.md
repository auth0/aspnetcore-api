# DPoP Configuration Reference

This guide provides comprehensive documentation for all DPoP configuration options in the Auth0 ASP.NET Core API Authentication library.

## Table of Contents

- [Basic Configuration](#basic-configuration)
- [DPoPOptions Properties](#dpopoptions-properties)
- [DPoP Modes](#dpop-modes)
- [Configuration Reference Table](#configuration-reference-table)
- [Next Steps](#next-steps)
- [Resources](#resources)

## Basic Configuration

### Minimal Configuration

Enable DPoP with default settings:

```csharp
builder.Services.AddAuth0ApiAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.JwtBearerOptions = new JwtBearerOptions()
    {
        Audience = builder.Configuration["Auth0:Audience"]
    };
}).WithDPoP();
```

### Configuration with Options

Customize DPoP behavior:

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
    options.IatOffset = 300;
    options.Leeway = 30;
});
```

## DPoPOptions Properties

### Mode

**Type**: `DPoPModes`  
**Default**: `DPoPModes.Allowed`

Specifies the DPoP enforcement mode.

```csharp
options.Mode = DPoPModes.Allowed;   // Accept both DPoP and Bearer
options.Mode = DPoPModes.Required;  // Only DPoP tokens
options.Mode = DPoPModes.Disabled;  // No DPoP validation
```

**Permitted Values:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `Allowed` | DPoP validated when present; Bearer tokens also accepted | Migration, mixed environments |
| `Required` | Only DPoP tokens accepted; Bearer tokens rejected | Maximum security |
| `Disabled` | No DPoP validation; standard JWT Bearer only | Temporary disable, troubleshooting |

### IatOffset

**Type**: `int` (seconds)  
**Default**: `300` (5 minutes)  
**Minimum**: `0`

Maximum allowed age of the DPoP proof token based on the `iat` (issued at) claim.

```csharp
options.IatOffset = 300; // Allow proofs up to 5 minutes old
```

**Example Scenarios:**

```csharp
// Strict security - short window
options.IatOffset = 60; // 1 minute

// Balanced - recommended for most APIs
options.IatOffset = 300; // 5 minutes

// Lenient - high-latency networks
options.IatOffset = 600; // 10 minutes
```

### Leeway

**Type**: `int` (seconds)  
**Default**: `30`  
**Minimum**: `0`

Clock skew tolerance for time-based validations.

```csharp
options.Leeway = 30; // 30 seconds tolerance
```

**Example Scenarios:**

```csharp
// Tight synchronization
options.Leeway = 10; // 10 seconds

// Standard tolerance
options.Leeway = 30; // 30 seconds

// Distributed systems with known clock drift
options.Leeway = 60; // 1 minute
```

## DPoP Modes

### Allowed Mode (Default)

```csharp
.WithDPoP(options => options.Mode = DPoPModes.Allowed)
```

**Behavior:**
- ✅ Validates DPoP when `DPoP` header present
- ✅ Accepts standard Bearer tokens
- 🔍 Checks `Authorization` header scheme (`DPoP` or `Bearer`)

### Required Mode

```csharp
.WithDPoP(options => options.Mode = DPoPModes.Required)
```

**Behavior:**
- ✅ Only accepts DPoP-bound tokens
- ❌ Rejects Bearer tokens even if valid
- ❌ Rejects requests without `DPoP` header

### Disabled Mode

```csharp
.WithDPoP(options => options.Mode = DPoPModes.Disabled)
```

**Behavior:**
- ✅ Standard JWT Bearer authentication only
- 🚫 Ignores `DPoP` header completely
- 🚫 No DPoP validation performed


## Configuration Reference Table

| Property | Type | Default | Min | Max | Purpose |
|----------|------|---------|-----|-----|---------|
| `Mode` | `DPoPModes` | `Allowed` | - | - | Enforcement mode |
| `IatOffset` | `int` | 300 | 0 | ∞ | Max proof age (seconds) |
| `Leeway` | `int` | 30 | 0 | ∞ | Clock skew tolerance (seconds) |

## Next Steps

- [DPoP Overview](dpop-overview.md) - Understanding DPoP concepts
- [Getting Started with DPoP](dpop-getting-started.md) - Quick start guide
- [API Reference](../api/Auth0.AspNetCore.Authentication.Api.DPoP.DPoPOptions.html) - Full API documentation

## Resources

- [RFC 9449: OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [Auth0 DPoP Documentation](https://auth0.com/docs/secure/tokens/token-best-practices/proof-of-possession)
- [OIDC Discovery Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html)
