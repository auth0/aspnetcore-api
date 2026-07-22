# AI Agent Guidelines for Auth0.AspNetCore.Authentication.Api

This document provides context and guidelines for AI coding assistants working with the Auth0.AspNetCore.Authentication.Api codebase.

## Your Role

You are a C# SDK engineer maintaining the Auth0 ASP.NET Core API authentication library. It wraps `Microsoft.AspNetCore.Authentication.JwtBearer` with Auth0-specific configuration, RFC 9449 DPoP (Demonstration of Proof-of-Possession) validation, and Multiple Custom Domain support; you write small, well-tested code and preserve the fluent-builder public API that consumers depend on.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Overview

**Auth0.AspNetCore.Authentication.Api** is an Auth0 authentication SDK for ASP.NET Core APIs providing JWT Bearer authentication with built-in DPoP and Multiple Custom Domain support.

- **Language:** C# (`<LangVersion>latest</LangVersion>`, nullable + implicit usings enabled)
- **Tech Stack:** ASP.NET Core JWT Bearer authentication; DPoP per RFC 9449
- **Package Manager:** NuGet (.NET SDK)
- **Minimum Platform Version:** .NET 8.0 — library multi-targets `net8.0;net10.0`
- **Dependencies:** `Microsoft.AspNetCore.Authentication.JwtBearer` (8.0.27 / 10.0.3), `Microsoft.Extensions.Logging.Abstractions` · test: xUnit 2.9, Moq 4.20, FluentAssertions 7.2. See the `.csproj` files for the authoritative list.

---

## Project Structure

```
.
├── src/Auth0.AspNetCore.Authentication.Api/   # Main library (the published NuGet package)
│   ├── ServiceCollectionExtensions.cs           # Public API: IServiceCollection.AddAuth0ApiAuthentication()
│   ├── AuthenticationBuilderExtensions.cs        # Public API: .AddAuth0ApiAuthentication(), .WithDPoP()
│   ├── Auth0ApiAuthenticationBuilder.cs          # Fluent builder returned from setup
│   ├── Auth0ApiOptions.cs                         # Domain + JwtBearerOptions wrapper
│   ├── Auth0JwtBearerPostConfigureOptions.cs      # Sets Authority from Domain; adds Auth0-Client header
│   ├── Utils.cs / Version.cs                       # Telemetry agent string + SDK version constant
│   ├── DPoP/                                        # RFC 9449 implementation (validation, modes, event handlers)
│   └── CustomDomains/                              # Multiple Custom Domain configuration + caching
├── tests/
│   ├── Auth0.AspNetCore.Authentication.Api.UnitTests/         # xUnit unit tests (no credentials)
│   └── Auth0.AspNetCore.Authentication.Api.IntegrationTests/  # Live-tenant integration tests
├── Auth0.AspNetCore.Authentication.Api.Playground/            # Runnable sample API + Swagger
├── Auth0.AspNetCore.Authentication.Api.Playground.DPoPClient/ # Sample DPoP client
├── build/common.props                              # Shared package metadata + version
├── docs-source/ + docs/                            # docfx source and generated API docs
└── .version / .shiprc                              # Release version source + ship-cli config
```

### Key Files

| File | Purpose |
|------|---------|
| `src/.../ServiceCollectionExtensions.cs` | Primary public entry — `AddAuth0ApiAuthentication()` overloads |
| `src/.../AuthenticationBuilderExtensions.cs` | DPoP enablement `.WithDPoP()` + internal JWT Bearer setup |
| `src/.../DPoP/DPoPProofValidationService.cs` | Core DPoP proof validation (JWK, signature, `cnf` thumbprint, `htm`/`htu`/`iat`) |
| `src/.../DPoP/DPoPModes.cs` | `Allowed` / `Required` / `Disabled` enforcement modes |
| `src/.../Utils.cs` + `Version.cs` | `Auth0-Client` telemetry header payload + SDK version |
| `.version`, `build/common.props`, `Version.cs` | The three version sources kept in sync via `.shiprc` |

---

## Boundaries

### ✅ Always Do

- Run the unit tests before committing (`dotnet test tests/…UnitTests/`).
- Follow the existing code style and naming conventions (see `.editorconfig` — enforced: 4-space indent, `var` for built-in/apparent types, braces required, 120-col guideline).
- Add xUnit tests for new functionality.
- Set DPoP validation errors via the typed `Auth0Constants.DPoP.Error.Code.*` constants and `DPoPProofValidationResult.SetError(...)` — do not throw ad-hoc exceptions from the validation pipeline.
- Update `README.md` and `EXAMPLES.md` in the same PR when you change the public API, configuration options, or supported integration patterns.
- Keep the three version sources (`.version`, `build/common.props` `<Version>`, `src/.../Version.cs`) in sync — they are listed together in `.shiprc`.
- Telemetry is shared per-request infrastructure — existing request paths already carry it. Only when you add a **new outbound HTTP path to Auth0**, route it through `Utils.CreateAgentString()` and add the `Auth0-Client` header (as `Auth0JwtBearerPostConfigureOptions.cs` and `CustomDomains/Auth0CustomDomainsConfigurationManager.cs` do) rather than hand-rolling a new client.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never change or remove a public API signature, the fluent-builder surface, or default DPoP behavior on your own initiative. Breaking changes also require a migration guide (inferred from the target branch/major at that time).
- Adding new NuGet dependencies or bumping existing package versions.
- Modifying public API signatures (the `AddAuth0ApiAuthentication` / `WithDPoP` / `WithCustomDomains` fluent surface).
- Changes to CI/CD configuration (`.github/workflows/`).
- Modifying security-related code (DPoP proof validation, token/thumbprint handling, custom-domain trust).
- Running the integration/acceptance tests — they hit a live Auth0 tenant, are slow, and require real credentials (see Testing).

### 🚫 Never Do

- Commit secrets, API keys, tokens, or real tenant credentials.
- Hardcode tokens in tests — obtain them via `Auth0TokenHelper.GetClientCredentialsTokenAsync()` with environment variables.
- Modify auto-generated files or the `docs/` generated output by hand.
- Remove or skip failing tests without fixing the underlying issue.
- Modify build/vendor output directories (`bin/`, `obj/`, `TestResults/`).
- Break backward compatibility without asking first and getting explicit approval.

---

## Security Considerations

- **DPoP (RFC 9449):** `DPoPProofValidationService` verifies the proof JWK, the signature, the `cnf.jkt` thumbprint binding (SHA-256 of the public key), and the `htm`/`htu`/`iat` claims. `IatOffset` (default 300s) covers clock skew; `Leeway` (default 30s) covers lifetime checks. Treat this pipeline as security-critical — changes are Ask-First.
- **Token handling:** never log access tokens or DPoP proofs. Log validation *failures* via `ILogger<T>` with the error code/description, not token contents.
- **DPoP modes:** `Allowed` validates DPoP if present (enables migration); `Required` rejects Bearer tokens entirely; `Disabled` is standard JWT Bearer. Don't silently change the default (`Allowed`).
- **Custom domains:** token-issuer trust is validated per configured domain — review `CustomDomains/` trust logic carefully before changing.
- **Secret scanning:** Snyk (`.github/workflows/snyk.yml`) and RL-Secure (`rl-secure.yml`) run in CI. Never commit anything that trips them.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer.

## Commands

Core loop: `dotnet restore … && dotnet build …sln -c Release` then `dotnet test tests/…UnitTests/`. See [references/commands.md](references/commands.md) for the full build/test/coverage/docs command list — read when you need to build, test, or package.

---

## Testing

- **Framework:** xUnit (`[Fact]`/`[Theory]`), Moq for mocking, FluentAssertions for assertions.
- **Location:** `tests/…UnitTests/` (safe, no credentials) and `tests/…IntegrationTests/` (live tenant).
- **Coverage:** Coverlet → Cobertura, uploaded to Codecov in CI.

The default `dotnet test tests/…UnitTests/` suite is unit-only and needs no credentials. The integration suite hits a live Auth0 tenant and requires `BASIC_*`, `DPOP_ALLOWED_*`, `DPOP_REQUIRED_*`, and `CUSTOM_DOMAIN_*_*` environment variables — it is **Ask First** (see Boundaries).

See [references/testing.md](references/testing.md) for conventions, mocking, the integration-test helpers, and the exact live-test command — read when writing or running tests.

---

## Code Style

Enforced via `.editorconfig`: 4-space indent, LF, UTF-8, 120-col guideline; `var` for built-in/apparent types (not elsewhere), braces always required, `System` usings sorted first with separated import groups. Public types/members use PascalCase and carry XML doc comments; the package is `CLSCompliant`.

See [references/code-style.md](references/code-style.md) for naming detail, good/bad examples, and the dominant patterns (fluent builder, options, event-handler wrapping) — read before writing new source.

---

## Git Workflow

Branch from `master`; PRs target `master` and use `.github/PULL_REQUEST_TEMPLATE.md` (Changes / References / Testing / Checklist — all commits must be signed). See [references/git-workflow.md](references/git-workflow.md) for branch naming, commit style, and the CHANGELOG format — read when branching, committing, or opening a PR.

---

## Common Pitfalls

The top gotcha: `Domain` must be `tenant.auth0.com` **without** the `https://` prefix — the SDK prepends it. See [references/pitfalls.md](references/pitfalls.md) for the full list (DPoP mode semantics, event preservation, `InternalsVisibleTo`, multi-targeting) — read when debugging unexpected auth behavior.

---

## Docs Update Rules

> Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

Tracked docs: `README.md` (present) and `EXAMPLES.md` (present) are the always-tracked docs; the `Playground` sample apps demonstrate the public API. See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping — read when your change touches the public API, options, or integration patterns.
