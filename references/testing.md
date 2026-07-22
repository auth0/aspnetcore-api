# Testing

## Frameworks

- **xUnit** — `[Fact]` for single cases, `[Theory]` + `[InlineData]` for parameterized.
- **Moq** — mock collaborators (e.g. `IDPoPProofValidationService` when testing event handlers).
- **FluentAssertions** — `result.Should().Contain(...)`, `act.Should().NotThrow()`.

## Layout

- `tests/Auth0.AspNetCore.Authentication.Api.UnitTests/` — unit tests, no network/credentials. This is the default suite.
- `tests/Auth0.AspNetCore.Authentication.Api.IntegrationTests/` — live-tenant tests (Ask First).

Both test projects use `<InternalsVisibleTo>` (declared in the library `.csproj`) so tests can exercise internal validators directly.

## Unit test conventions

- Descriptive method names with underscores, e.g. `CreateAgentString_ReturnsBase64EncodedJson_With_Correct_Name_And_Version`.
- Test each DPoP validator independently against the internal methods in `DPoPProofValidationService`.
- Mock `IDPoPProofValidationService` when testing the event-handler chain (`MessageReceived`, `TokenValidated`, `Challenge`).

## Integration / acceptance tests (Ask First)

> ⚠️ These hit a live Auth0 tenant, are slow, may cost money, and obtain real tokens. Ask before running (see Boundaries).

Requires these environment variables (provided as CI secrets in `.github/workflows/build.yml`):

- `BASIC_DOMAIN`, `BASIC_AUDIENCE`, `BASIC_CLIENT_ID`, `BASIC_CLIENT_SECRET`
- `DPOP_ALLOWED_*` and `DPOP_REQUIRED_*` (domain, audience, client id/secret, dpop mode)
- `CUSTOM_DOMAIN_1_*` and `CUSTOM_DOMAIN_2_*`

```bash
dotnet test tests/Auth0.AspNetCore.Authentication.Api.IntegrationTests/Auth0.AspNetCore.Authentication.Api.IntegrationTests.csproj
```

Patterns:
- `TestWebApplicationFactory` spins up a `TestServer`; `Auth0TokenHelper` obtains real client-credentials tokens; `DPoPHelper` generates DPoP proofs with real EC keys (`ECDsa.Create(ECCurve.NamedCurves.nistP256)`).
- Use the `Auth0Scenario` configuration to select Basic / DPoPAllowed / DPoPRequired / CustomDomains environments.
- **Never hardcode tokens** — always go through `Auth0TokenHelper`.

## Coverage

Coverlet collects coverage (`--collect:"XPlat Code coverage"`, Cobertura format) and CI uploads it to Codecov. No hard threshold is enforced in CI (`fail_ci_if_error: false`).
