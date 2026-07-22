# Common Pitfalls

1. **Domain format.** `options.Domain` must be `tenant.auth0.com` — **without** the `https://` scheme. The SDK constructs the Authority as `https://{Domain}` itself; passing a scheme produces a malformed Authority.

2. **DPoP mode semantics.** `Allowed` (default) validates a DPoP proof *only if one is present* and still accepts Bearer tokens — this is the gradual-migration mode. `Required` rejects Bearer tokens entirely and demands a valid DPoP proof. `Disabled` is plain JWT Bearer. Confusing `Allowed` with `Required` is the most common behavioral surprise.

3. **Event preservation.** When editing `AuthenticationBuilderExtensions.cs` or the DPoP event handlers, always preserve the consumer's existing `JwtBearerEvents` — the DPoP handlers *wrap* user events (run DPoP first, then delegate). Overwriting `Events.OnMessageReceived` etc. silently drops the consumer's handlers.

4. **`InternalsVisibleTo`.** Tests reach internal validators via `<InternalsVisibleTo>` declared in the library `.csproj` (`…UnitTests`, `…IntegrationTests`, `DynamicProxyGenAssembly2` for Moq). If you move an internal type to a new assembly, update these.

5. **Multi-targeting.** The library targets `net8.0;net10.0`. Package references are conditioned per TFM (e.g. `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.27 for net8.0, 10.0.3 for net10.0). Add framework-conditioned references when introducing a dependency, and don't assume APIs available only in net10.0.

6. **DPoP timing.** `IatOffset` (default 300s) tolerates clock skew on the proof `iat`; `Leeway` (default 30s) applies to token lifetime checks. Tightening these can cause spurious `invalid_dpop_proof` failures under normal clock drift.
