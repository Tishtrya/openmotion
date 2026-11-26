# OpenMotion Privacy Hardening Toolkit

This directory maintains the automated telemetry-removal scripts, fail-closed privacy audit guard, runtime verification tests, and domain allowlist for maintaining a privacy-hardened fork of [`nexu-io/openmotion`](https://github.com/nexu-io/openmotion).

## What Is Removed / Disabled

1. **PostHog product telemetry & GeoIP** (`shared/tracking-config.json`, `shared/tracking.ts`, `tracking/node.ts`, `tracking/browser.ts`, `tracking/posthog-geoip.hog`, `studio/src/motion/tracking.ts`, `studio/src/motion/reporting.ts`, `studio/src/webmcp/tracking.ts`):
   - Removes the hardcoded PostHog endpoint (`https://us.i.posthog.com`), project token, and `geoip: true` flag.
   - Permanently locks telemetry off regardless of `OPENMOTION_POSTHOG_HOST`, `OPENMOTION_POSTHOG_KEY`, or preference files.
   - Stops writing `tracking/identity.json`, `tracking/preferences.json`, and `tracking/tasks.json` to the user data directory.
2. **Hardware / OS device fingerprinting** (`tracking/device.ts`, `.github/workflows/device-identity-check.yml`):
   - Removes execution of macOS `/usr/sbin/ioreg` (`IOPlatformUUID`), Windows `reg.exe` (`MachineGuid`), and Linux `/etc/machine-id` / `/var/lib/dbus/machine-id`, plus HMAC hashing.
3. **Install & cross-site attribution** (`shared/install-attribution.ts`, `workers/install-guide/index.ts`, `tracking/host.ts`, `shared/workspace-url.ts`, `studio/src/motion/campaignAttribution.ts`):
   - Disables `--utm-source` install attribution and event reporting.
   - Stops injecting and propagating `tracking_context` query parameters in preview URLs.
   - Disables the Black Friday promotional banner and strips `od_origin`, `od_entry_source`, `od_entry_id`, `od_entry_at`, and `utm_*` parameters from Pricing links.
4. **Browser anonymous IDs & external feedback prompts** (`studio/src/telemetry/*`, `studio/src/utils/studioTelemetry.ts`, `studio/src/components/feedback/StudioFeedbackCard.tsx`):
   - Eliminates `localStorage` persistence of `hyperframes-studio:anonymousId` / `hf-studio-anon-id` and `window.__HF_CLI_DISTINCT_ID` adoption.
   - Disables the feedback prompt card and its Google Calendar interview booking link.
5. **Unsolicited background network requests** (`studio/src/motion/githubRepository.ts`, `server.ts`, `hyperframes.ts`, `deploy/*`):
   - Disables automatic background `https://api.github.com/repos/nexu-io/openmotion` Stars fetches.
   - Disables automatic startup `gateway.account.prefetch()` (which silently installs `@powerformer/vela-cli` from npm on startup; explicit user sign-in still prepares it on demand).
   - Adds `HYPERFRAMES_NO_UPDATE_CHECK=1` and `HYPERFRAMES_NO_AUTO_INSTALL=1` alongside `HYPERFRAMES_NO_TELEMETRY=1` in `hyperframes.ts` and Docker defaults.
6. **Preserved local & user-initiated features**:
   - Local diagnostic ZIP export (`DiagnosticExport` — local only, never uploaded).
   - User-configured BYOK media providers, MCP tools, Studio editing/rendering, and template libraries.

## Usage

```bash
# 1. Strip telemetry from the current checkout (or pass --root /path/to/checkout)
node privacy/strip-telemetry.mjs

# 2. Run the fail-closed privacy audit (forbidden patterns + domain allowlist drift + npm deps)
node privacy/audit-privacy.mjs

# 3. Run runtime verification tests (intercepts global fetch, verifies zero network & disk writes)
node --experimental-strip-types --test privacy/verify-privacy.test.mjs
```

## Automated Upstream Sync

Two workflows govern ongoing sync with `https://github.com/nexu-io/openmotion`:

- [`.github/workflows/sync-upstream-privacy.yml`](../.github/workflows/sync-upstream-privacy.yml): Runs daily (and on manual `workflow_dispatch`). Resets a sync branch to the clean upstream tree, overlays `privacy/` and the privacy workflows, replays `privacy/strip-telemetry.mjs`, runs `privacy/audit-privacy.mjs`, installs dependencies, runs `verify-privacy.test.mjs` plus full typecheck/Studio build, and opens/updates a PR into `main`. If upstream introduces a new telemetry SDK, an unapproved external domain, or refactors a stripped file so an anchor drifts, the workflow **fails closed**, opens/updates a `[Privacy Alert]` GitHub Issue, and refuses to push or open a PR.
- [`.github/workflows/privacy-guard.yml`](../.github/workflows/privacy-guard.yml): Runs on every push and PR to `main` to prevent accidental regressions.

### Using a Separate Builder Repository

Both `strip-telemetry.mjs` and `audit-privacy.mjs` accept `--root <dir>`, and `verify-privacy.test.mjs` accepts `OPENMOTION_PRIVACY_TEST_ROOT=<dir>`. You can copy `privacy/` into a standalone orchestrator repository that checks out `nexu-io/openmotion` into `./target`, runs these scripts against `--root ./target`, and pushes the verified tree to your fork.

## Handling Upstream Drift Alerts

1. Inspect the `[Privacy Alert]` issue or run `node privacy/strip-telemetry.mjs` and `node privacy/audit-privacy.mjs` locally against the new upstream commit.
2. If `strip-telemetry.mjs` reports `[DRIFT]`, update the affected file template or regex anchor in `privacy/strip-telemetry.mjs`.
3. If `audit-privacy.mjs` reports `unapproved-external-domain`, inspect the referenced file and line:
   - If it is telemetry, analytics, or unsolicited phone-home traffic: add a stripping step to `privacy/strip-telemetry.mjs` and a forbidden rule to `privacy/audit-privacy.mjs`.
   - If it is a legitimate user-initiated feature or passive documentation link: register it with its narrowest `filePrefixes` scope in `privacy/domain-allowlist.json`.
