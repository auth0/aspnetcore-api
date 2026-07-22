# Docs Update Rules

This is a **library / SDK** — its public surface is exported types and methods (the `AddAuth0ApiAuthentication` overloads, `.WithDPoP()`, `.WithCustomDomains()`, `Auth0ApiOptions`, `DPoPOptions`, `DPoPModes`, custom-domain options). Keep docs in step with that surface.

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Features, requirements, installation, getting started, DPoP, Multiple Custom Domains, configuration options | present |
| `EXAMPLES.md` | Copy-paste usage scenarios (basic setup, DPoP modes, custom domains, full JWT Bearer options) | present |
| `Playground/` + `Playground.DPoPClient/` | Runnable sample API + DPoP client demonstrating the public API | present |

> `MIGRATION.md` exists but is **not tracked as a fixed doc** — migration guidance is version-specific and inferred from the target branch when a breaking change lands. `CHANGELOG.md` is maintained by the release flow, not during feature PRs.

## When you change code, update these docs

| When this changes | Update these docs |
|-------------------|-------------------|
| Public API surface (`AddAuth0ApiAuthentication`, `.WithDPoP()`, exported options types) | `README.md` (getting started / configuration), `EXAMPLES.md` (all affected samples), Playground apps that use it |
| Configuration options (`Auth0ApiOptions`, `DPoPOptions`, custom-domain options, appsettings keys) | `README.md` (configuration section) |
| Authentication / DPoP validation flow or modes | `README.md` (DPoP section), `EXAMPLES.md` (DPoP examples) |
| Install / package name / target frameworks | `README.md` (installation / requirements) |
| A new public method or exported type added | `EXAMPLES.md` (add a usage sample) |
| A public method or type removed or renamed | `README.md` + `EXAMPLES.md` (remove/update references) |
| New integration pattern supported (e.g. new custom-domain scenario) | `EXAMPLES.md` (add integration example) |

> When you touch code that maps to a doc above, update that doc **in the same PR** — do not defer.
