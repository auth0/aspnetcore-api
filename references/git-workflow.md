# Git Workflow

## Branches

- `master` is the main branch; branch off it and target it in PRs.
- Use descriptive prefixes seen in this repo: `chore/…`, `release/…`, and feature/fix branches.

## Commits

- No commitlint config is enforced. Write clear, imperative messages.
- **All commits must be signed** (per the PR checklist).

## Pull Requests

PRs use `.github/PULL_REQUEST_TEMPLATE.md`, which asks for:

- **Changes** — what changed and why (classes/methods added, removed, deprecated, changed; public-API usage summary).
- **References** — support ticket, community/forum/StackOverflow links.
- **Testing** — how reviewers can test; checkboxes for unit and integration coverage.
- **Checklist** — read the Auth0 general contribution guidelines + Code of Conduct; all tests pass; all commits signed.

CI on every PR (`build.yml`): restore → build (Release) → unit tests → integration tests → Codecov upload. Snyk and RL-Secure also run.

## Changelog & Releases

- `CHANGELOG.md` follows a Keep-a-Changelog-style layout. Changelog entries and version bumps are cut as part of the release flow (`ship`-cli, see `.shiprc`), not hand-edited during a feature PR.
- The version lives in three files kept in sync via `.shiprc`: `.version`, `build/common.props` (`<Version>`), and `src/Auth0.AspNetCore.Authentication.Api/Version.cs` (`Version.Current`). Release CI: `.github/workflows/release.yml` and `nuget-release.yml`.
