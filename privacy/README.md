# OpenMotion Privacy Hardening Toolkit

This directory maintains the automated telemetry-removal scripts, fail-closed privacy audit guard, runtime verification tests, and domain allowlist for maintaining a privacy-hardened fork of [`nexu-io/openmotion`](https://github.com/nexu-io/openmotion).

## What Is Removed / Disabled

1. **PostHog product telemetry & GeoIP** (`shared/tracking-config.json`, `shared/tracking.ts`, `tracking/node.ts`, `tracking/browser.ts`, `tracking/posthog-geoip.hog`, `src/cloud-tracking.ts`, `studio/src/motion/tracking.ts`, `studio/src/motion/studioTracking.ts`, `studio/src/motion/reporting.ts`, `studio/src/webmcp/tracking.ts`):
   - Removes the hardcoded PostHog endpoint (`https://us.i.posthog.com`), project token, and `geoip: true` flag.
   - Permanently locks application, cloud-ingest, and browser telemetry off regardless of `OPENMOTION_POSTHOG_HOST`, `OPENMOTION_POSTHOG_KEY`, `OPENMOTION_TRACKING_ENABLED`, or preference files.
   - Stops writing `tracking/identity.json`, `tracking/preferences.json`, and `tracking/tasks.json` to the user data directory.
2. **Sentry error/performance reporting** (`packages/observability/*`, `src/entrypoints/api.ts` runtime injection, `desktop/src/sentry.ts`, release workflows):
   - Replaces the browser Sentry SDK integration with zero-network no-ops and refuses every DSN.
   - Removes Sentry DSN injection, sourcemap/debug-id build tooling, sourcemap upload steps, and `@sentry/*` dependencies.
   - Disables the Electron main-process Sentry envelope reporter, crash upload, and store-and-forward outbox.
3. **Desktop edge-health telemetry** (`desktop/src/telemetry.ts`, `shared/desktop-telemetry.ts`):
   - Disables local `telemetry/health-metrics.json` collection and persistence and the optional remote flush.
4. **Hardware / OS device fingerprinting** (`tracking/device.ts`, `.github/workflows/device-identity-check.yml`):
   - Removes execution of macOS `/usr/sbin/ioreg` (`IOPlatformUUID`), Windows `reg.exe` (`MachineGuid`), and Linux `/etc/machine-id` / `/var/lib/dbus/machine-id`, plus HMAC hashing.
5. **Install & cross-site attribution** (`shared/install-attribution.ts`, `workers/install-guide/index.ts`, `tracking/host.ts`, `shared/workspace-url.ts`, `studio/src/motion/campaignAttribution.ts`, `studio/src/motion/accountOffer.ts`):
   - Disables `--utm-source` install attribution and event reporting.
   - Stops injecting and propagating `tracking_context` query parameters in preview URLs.
   - Disables the Black Friday promotional banner and strips `od_origin`, `od_entry_source`, `od_entry_id`, `od_entry_at`, and `utm_*` parameters from Pricing and subscription links.
6. **Browser anonymous IDs & external feedback prompts** (`studio/src/telemetry/*`, `studio/src/utils/studioTelemetry.ts`, `studio/src/components/feedback/StudioFeedbackCard.tsx`):
   - Eliminates `localStorage` persistence of `hyperframes-studio:anonymousId` / `hf-studio-anon-id` and `window.__HF_CLI_DISTINCT_ID` adoption.
   - Disables the feedback prompt card and its Google Calendar interview booking link.
7. **Unsolicited background network requests** (`studio/src/motion/githubRepository.ts`, `server.ts`, `hyperframes.ts`, `deploy/*`):
   - Disables automatic background `https://api.github.com/repos/nexu-io/openmotion` Stars fetches.
   - Disables automatic startup `gateway.account.prefetch()` when that API exists (explicit user sign-in still prepares it on demand).
   - Adds `HYPERFRAMES_NO_UPDATE_CHECK=1` and `HYPERFRAMES_NO_AUTO_INSTALL=1` alongside `HYPERFRAMES_NO_TELEMETRY=1` in `hyperframes.ts` and Docker defaults.
8. **Deployment and dependency hardening** (`.env.example`, `docker-compose.yml`, Kubernetes config, `package.json`, `package-lock.json`):
   - Removes Sentry/PostHog environment settings and forces `OPENMOTION_TELEMETRY=0` / `DO_NOT_TRACK=1`.
   - Removes `@sentry/*` packages from manifests and the lockfile; `npm ci` remains reproducible.
9. **Preserved local & user-initiated features**:
   - Local diagnostic ZIP export (`DiagnosticExport` — local only, never uploaded).
   - User-configured BYOK media providers, MCP tools, Studio editing/rendering, and template libraries.

The scripts are **layout-aware**: known telemetry files are hardened whenever present, while files added or removed by upstream restructuring do not break the guard on an older checkout. Forbidden endpoints, unknown domains, and analytics dependencies still fail closed when the same behavior returns under a new filename.

## Usage

```bash
# 1. Strip telemetry from the current checkout (or pass --root /path/to/checkout)
node privacy/strip-telemetry.mjs

# 2. Run the fail-closed privacy audit (forbidden patterns + domain allowlist drift + npm deps)
node privacy/audit-privacy.mjs

# 3. Install locked dependencies once, then run runtime verification tests
#    (intercepts global fetch, verifies zero network & disk writes)
npm ci --ignore-scripts --no-audit --no-fund
node --experimental-strip-types --test privacy/verify-privacy.test.mjs
```

## Automated Upstream Sync

Two workflows govern ongoing sync with `https://github.com/nexu-io/openmotion`:

- [`.github/workflows/sync-upstream-privacy.yml`](../.github/workflows/sync-upstream-privacy.yml): Runs daily (and on manual `workflow_dispatch`). Resets a sync branch to the clean upstream tree, overlays `privacy/` and the privacy workflows, replays `privacy/strip-telemetry.mjs`, runs `privacy/audit-privacy.mjs`, installs dependencies, runs `verify-privacy.test.mjs` plus full typecheck/Studio build, and opens/updates a PR into `main`. If upstream introduces a new telemetry SDK, an unapproved external domain, or refactors a stripped file so an anchor drifts, the workflow **fails closed**, opens/updates a `[Privacy Alert]` GitHub Issue, and refuses to push or open a PR.
- [`.github/workflows/privacy-guard.yml`](../.github/workflows/privacy-guard.yml): Runs on every push and PR to `main` to prevent accidental regressions.

### Required repository configuration

The sync branch contains the upstream tree, which includes changes under `.github/workflows/`. GitHub deliberately blocks the built-in `GITHUB_TOKEN` from creating or updating workflow files, even with `contents: write`; the push fails with:

```text
refusing to allow a GitHub App to create or update workflow `.github/workflows/ci.yml` without `workflows` permission
```

Create a repository secret named **`PRIVACY_SYNC_TOKEN`** with a token that has the **Workflows: Read and write** permission. The workflow uses this secret for the final `git push` and for `gh`/issue updates, while keeping it out of the checkout so upstream build scripts cannot read it.

Recommended: a fine-grained personal access token scoped to this repository only, with:

| Permission | Access |
| --- | --- |
| Contents | Read and write |
| Pull requests | Read and write |
| Issues | Read and write |
| Workflows | Read and write |
| Metadata | Read-only (mandatory) |

Add it under **Settings → Secrets and variables → Actions → New repository secret**. Alternatively, create a GitHub App installed on this repository with the same repository permissions and adapt the workflow to mint a short-lived installation token with `actions/create-github-app-token` (use its output for the push and `gh`/issue steps instead of a long-lived secret).

If you do not want to grant workflow-update access, the alternative is to keep the fork's own `.github/workflows/` files and exclude upstream workflow changes from the sync branch; this requires changing the sync workflow and means upstream CI changes are not mirrored.

### Using a Separate Builder Repository

Both `strip-telemetry.mjs` and `audit-privacy.mjs` accept `--root <dir>`, and `verify-privacy.test.mjs` accepts `OPENMOTION_PRIVACY_TEST_ROOT=<dir>`. You can copy `privacy/` into a standalone orchestrator repository that checks out `nexu-io/openmotion` into `./target`, runs these scripts against `--root ./target`, and pushes the verified tree to your fork.

## Handling Upstream Drift Alerts

1. Inspect the `[Privacy Alert]` issue or run `node privacy/strip-telemetry.mjs` and `node privacy/audit-privacy.mjs` locally against the new upstream commit.
2. If `strip-telemetry.mjs` reports `[DRIFT]`, update the affected file template or regex anchor in `privacy/strip-telemetry.mjs`.
3. If `audit-privacy.mjs` reports `unapproved-external-domain`, inspect the referenced file and line:
   - If it is telemetry, analytics, or unsolicited phone-home traffic: add a stripping step to `privacy/strip-telemetry.mjs` and a forbidden rule to `privacy/audit-privacy.mjs`.
   - If it is a legitimate user-initiated feature or passive documentation link: register it with its narrowest `filePrefixes` scope in `privacy/domain-allowlist.json`.
