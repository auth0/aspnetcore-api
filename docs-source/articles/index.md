![](https://cdn.auth0.com/website/sdks/banners/auth0-net-banner.png)
[![License](https://img.shields.io/:license-Apache%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)


:books: [Documentation](#documentation) - :rocket: [Getting Started](#getting-started) - :computer: [API Reference](https://auth0.github.io/auth0.net/) - :speech_balloon: [Feedback](#feedback)
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

## Documentation Sections

### Getting Started
- [Getting Started](getting-started.md) - Installation and basic setup
- [Configuration Guide](configuration.md) - Detailed configuration options

### DPoP (Proof-of-Possession)
- [DPoP Overview](dpop-overview.md) - Understanding DPoP and its security benefits
- [Getting Started with DPoP](dpop-getting-started.md) - Enable DPoP in your API
- [DPoP Configuration Reference](dpop-configuration.md) - Advanced DPoP settings

### Reference
### Reference
- [API Reference](../api/Auth0.AspNetCore.Authentication.Api.yml) - Complete API documentation

## Resources

- [GitHub Repository](https://github.com/auth0/aspnetcore-api)
- [Auth0 Documentation](https://auth0.com/docs)
- [ASP.NET Core Documentation](https://docs.microsoft.com/aspnet/core)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0.net/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the Apache License 2.0. See the <a href="./LICENSE"> LICENSE</a> file for more info.</p>