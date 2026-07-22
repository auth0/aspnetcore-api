# Commands

> Copy-paste ready. These match the CI workflow (`.github/workflows/build.yml`).

```bash
# Restore
dotnet restore Auth0.AspNetCore.Authentication.Api.sln

# Build (Release, as in CI)
dotnet build Auth0.AspNetCore.Authentication.Api.sln --configuration Release --no-restore

# Run unit tests (safe — no credentials required)
dotnet test tests/Auth0.AspNetCore.Authentication.Api.UnitTests/Auth0.AspNetCore.Authentication.Api.UnitTests.csproj

# Run unit tests with coverage (as in CI)
dotnet test tests/Auth0.AspNetCore.Authentication.Api.UnitTests/Auth0.AspNetCore.Authentication.Api.UnitTests.csproj \
  --collect:"XPlat Code coverage" --results-directory ./TestResults/ \
  /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura

# Run a single test by name
dotnet test tests/Auth0.AspNetCore.Authentication.Api.UnitTests/ --filter "FullyQualifiedName~UtilsTests"

# Clean
dotnet clean Auth0.AspNetCore.Authentication.Api.sln
```

## Integration tests (Ask First — live tenant)

Requires the environment variables set as CI secrets (`BASIC_*`, `DPOP_ALLOWED_*`, `DPOP_REQUIRED_*`, `CUSTOM_DOMAIN_1_*`, `CUSTOM_DOMAIN_2_*`):

```bash
dotnet test tests/Auth0.AspNetCore.Authentication.Api.IntegrationTests/Auth0.AspNetCore.Authentication.Api.IntegrationTests.csproj
```

## Playground

```bash
cd Auth0.AspNetCore.Authentication.Api.Playground
# Configure Auth0:Domain and Auth0:Audience in appsettings.json first
dotnet run
# then open https://localhost:7190/swagger
```

## Documentation

```bash
./build-docs.sh          # builds the project + runs docfx into docs/
```
