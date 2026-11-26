import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';

import { runAudit } from './audit-privacy.mjs';
import { runStrip } from './strip-telemetry.mjs';

const TARGET_ROOT = path.resolve(process.env.OPENMOTION_PRIVACY_TEST_ROOT || process.cwd());

function modUrl(rel) {
  return pathToFileURL(path.join(TARGET_ROOT, rel)).href;
}

describe('OpenMotion privacy hardening runtime verification', () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = [];
  let tempDir;

  beforeEach(async () => {
    fetchCalls = [];
    globalThis.fetch = async (input, init) => {
      fetchCalls.push({ url: String(input), init });
      throw new Error(`Unexpected network fetch during privacy test: ${String(input)}`);
    };
    tempDir = await mkdtemp(path.join(os.tmpdir(), 'openmotion-privacy-test-'));
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes privacy audit on the hardened checkout', () => {
    const report = runAudit({ root: TARGET_ROOT });
    assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
    assert.equal(report.violationCount, 0);
  });

  it('strip-telemetry.mjs is idempotent (dry-run reports zero changes on hardened checkout)', () => {
    const res = runStrip({ root: TARGET_ROOT, dryRun: true });
    assert.equal(res.ok, true, JSON.stringify(res.errors));
    assert.equal(res.counts.updated, 0, JSON.stringify(res.actions.filter(a => a.status !== 'unchanged' && a.status !== 'already-removed')));
    assert.equal(res.counts.removed, 0);
  });

  it('hardware device fingerprinting is completely disabled', async () => {
    const device = await import(modUrl('tracking/device.ts'));
    assert.deepEqual(device.unknownDevice, { device_id: 'unknown', device_id_source: 'unavailable' });
    assert.deepEqual(device.deviceIdentity('darwin', '11111111-2222-3333-4444-555555555555'), device.unknownDevice);
    assert.deepEqual(await device.loadDeviceIdentity(), device.unknownDevice);
    assert.equal(fetchCalls.length, 0);
  });

  it('shared/tracking.ts stays locked off even when PostHog env vars are explicitly injected', async () => {
    const prevEnv = {
      OPENMOTION_TELEMETRY: process.env.OPENMOTION_TELEMETRY,
      DO_NOT_TRACK: process.env.DO_NOT_TRACK,
      OPENMOTION_POSTHOG_HOST: process.env.OPENMOTION_POSTHOG_HOST,
      OPENMOTION_POSTHOG_KEY: process.env.OPENMOTION_POSTHOG_KEY,
      OPENMOTION_TRACKING_ENV: process.env.OPENMOTION_TRACKING_ENV,
      OPENMOTION_TRACKING_TEST_RUN_ID: process.env.OPENMOTION_TRACKING_TEST_RUN_ID,
    };
    try {
      process.env.OPENMOTION_TELEMETRY = '1';
      process.env.DO_NOT_TRACK = '0';
      process.env.OPENMOTION_POSTHOG_HOST = 'https://us.i.posthog.com';
      process.env.OPENMOTION_POSTHOG_KEY = 'phc_injected_test_token_12345';
      process.env.OPENMOTION_TRACKING_ENV = 'production';
      process.env.OPENMOTION_TRACKING_TEST_RUN_ID = '11111111-1111-4111-8111-111111111111';

      const tracking = await import(modUrl('shared/tracking.ts'));
      assert.equal(tracking.trackingLocked(), true);
      assert.equal(tracking.trackingLockReason(), 'environment');
      assert.equal(tracking.trackingPreference(tempDir), false);

      await tracking.saveTrackingPreference(tempDir, true);
      assert.equal(tracking.trackingPreference(tempDir), false);

      const tracker = await tracking.createAppTracking(tempDir, 'mcp');
      assert.equal(tracker.enabled(), false);
      assert.equal(tracker.track('mcp_tool_started', { tool_name: 'openmotion_list_projects', transport: 'stdio', call_id: '11111111-1111-4111-8111-111111111111' }), 'disabled');
      assert.equal(tracker.pending(), 0);
      assert.equal(await tracker.flush(), 'disabled');
      await tracking.closeTracking(tracker);

      // Must NOT create any tracking/ folder or files on disk
      await assert.rejects(() => stat(path.join(tempDir, 'tracking')), { code: 'ENOENT' });
      assert.equal(fetchCalls.length, 0);
    } finally {
      for (const [k, v] of Object.entries(prevEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('tracking/node.ts never writes identity.json or calls fetch', async () => {
    const nodeTracking = await import(modUrl('tracking/node.ts'));
    const id = await nodeTracking.loadIdentity(tempDir, 'producthunt');
    assert.equal(id.utm_source, null);
    await nodeTracking.saveInstallationSource(tempDir, 'hackernews');
    await assert.rejects(() => stat(path.join(tempDir, 'identity.json')), { code: 'ENOENT' });

    const sender = nodeTracking.createPosthogSender({
      host: 'https://us.i.posthog.com',
      token: 'phc_fake_token',
      identity: id,
      appVersion: '0.0.1',
      env: 'production',
      fetch: globalThis.fetch,
    });
    const receipt = await sender([], new AbortController().signal);
    assert.equal(receipt, 'drop');
    assert.equal(fetchCalls.length, 0);
  });

  it('shared/install-attribution.ts is a pure no-op with zero disk writes or network calls', async () => {
    const attrib = await import(modUrl('shared/install-attribution.ts'));
    await attrib.recordInstallationStart(tempDir, 'codex', 'producthunt');
    await attrib.recordInstallation(tempDir, 'codex', 'producthunt');
    await assert.rejects(() => stat(path.join(tempDir, 'tracking')), { code: 'ENOENT' });
    assert.equal(fetchCalls.length, 0);
  });

  it('tracking/task-ledger.ts operates in-memory without writing tracking/tasks.json', async () => {
    const { TaskLedger } = await import(modUrl('tracking/task-ledger.ts'));
    const ledger = new TaskLedger(tempDir);
    const id = '11111111-1111-4111-8111-111111111111';
    const now = new Date().toISOString();
    await ledger.accept({ task_id: id, task_type: 'export', accepted_at: now, deadline_at: now });
    await ledger.terminal(id, 'success', 'true');
    const snap = await ledger.snapshot();
    assert.equal(snap[id].outcome, 'success');
    await assert.rejects(() => stat(path.join(tempDir, 'tracking')), { code: 'ENOENT' });
  });

  it('tracking/host.ts and shared/workspace-url.ts do not inject or propagate tracking_context', async () => {
    const host = await import(modUrl('tracking/host.ts'));
    const wsUrl = await import(modUrl('shared/workspace-url.ts'));

    const payload = { previewUrl: 'http://127.0.0.1:4173/?project=project' };
    const out = host.previewTrackingContext(payload, 'http://127.0.0.1:4173', '11111111-1111-4111-8111-111111111111');
    assert.equal(out.previewUrl, payload.previewUrl);
    assert.equal(out.previewUrl.includes('tracking_context'), false);

    const preserved = wsUrl.preservePresentation('/?project=next', '?embed=1&tracking_context=11111111-1111-4111-8111-111111111111');
    assert.equal(preserved.includes('embed=1'), true);
    assert.equal(preserved.includes('tracking_context'), false);
  });

  it('hyperframes.ts runtimeEnv disables telemetry, update checks, and auto-install', async () => {
    const hf = await import(modUrl('hyperframes.ts'));
    const env = hf.runtimeEnv();
    assert.equal(env.HYPERFRAMES_NO_TELEMETRY, '1');
    assert.equal(env.HYPERFRAMES_NO_UPDATE_CHECK, '1');
    assert.equal(env.HYPERFRAMES_NO_AUTO_INSTALL, '1');
  });

  it('workers/install-guide/index.ts does not inject --utm-source', async () => {
    const workerPath = path.join(TARGET_ROOT, 'workers/install-guide/index.ts');
    if (!fs.existsSync(workerPath)) return;
    const worker = await import(modUrl('workers/install-guide/index.ts'));
    const guide = '<!-- openmotion-utm-source-supported -->\nopenmotion setup --host codex\n';
    assert.equal(worker.attributeGuide(guide, 'producthunt'), guide);
  });

  it('Studio browser tracking, distinctId, config, and GitHub stars reader do zero network and zero storage writes', async () => {
    const storageWrites = [];
    globalThis.localStorage = {
      getItem: () => null,
      setItem: (k, v) => storageWrites.push([k, v]),
      removeItem: () => {},
      clear: () => {},
      key: () => null,
      length: 0,
    };
    try {
      const studioTracking = await import(modUrl('studio/src/motion/tracking.ts'));
      await studioTracking.initializeTracking();
      assert.equal(await studioTracking.trackMotion('surface_view', { page_name: 'explore' }), 'disabled');
      assert.equal(studioTracking.getMotionTrackingStatus().enabled, false);
      assert.equal(await studioTracking.flushMotionTracking(), 'disabled');

      const distinctId = await import(modUrl('studio/src/telemetry/distinctId.ts'));
      assert.equal(distinctId.getCliDistinctId(), null);
      assert.equal(distinctId.resolveStudioDistinctId(), 'disabled');

      const telemetryConfig = await import(modUrl('studio/src/telemetry/config.ts'));
      assert.equal(telemetryConfig.isOptedOut(), true);
      assert.equal(telemetryConfig.getAnonymousId(), 'disabled');

      const policy = await import(modUrl('studio/src/telemetry/policy.ts'));
      assert.equal(policy.browserTelemetryAllowed(), false);

      const client = await import(modUrl('studio/src/telemetry/client.ts'));
      assert.equal(client.shouldTrack(), false);

      const gh = await import(modUrl('studio/src/motion/githubRepository.ts'));
      assert.equal(await gh.readRepositoryStars(), null);

      assert.equal(storageWrites.length, 0);
      assert.equal(fetchCalls.length, 0);
    } finally {
      delete globalThis.localStorage;
    }
  });

  it('all hardened TypeScript files parse cleanly under Node stripTypeScriptTypes', () => {
    const files = [
      'tracking/device.ts',
      'tracking/node.ts',
      'tracking/browser.ts',
      'tracking/task-ledger.ts',
      'tracking/host.ts',
      'shared/tracking.ts',
      'shared/install-attribution.ts',
      'shared/workspace-url.ts',
      'hyperframes.ts',
      'server.ts',
      'studio/src/motion/tracking.ts',
      'studio/src/motion/reporting.ts',
      'studio/src/webmcp/tracking.ts',
      'studio/src/telemetry/distinctId.ts',
      'studio/src/telemetry/config.ts',
      'studio/src/telemetry/client.ts',
      'studio/src/telemetry/policy.ts',
      'studio/src/utils/studioTelemetry.ts',
      'studio/src/motion/campaignAttribution.ts',
      'studio/src/motion/githubRepository.ts',
    ];
    for (const rel of files) {
      const code = fs.readFileSync(path.join(TARGET_ROOT, rel), 'utf8');
      stripTypeScriptTypes(code, { mode: 'strip' });
    }
  });

  it('audit-privacy.mjs catches newly injected telemetry, unknown domains, hardware fingerprints, and analytics deps', async () => {
    // Build a synthetic mini-repo to verify the audit guard fails closed on regressions.
    const fakeRoot = path.join(tempDir, 'fake-repo');
    fs.mkdirSync(path.join(fakeRoot, 'shared'), { recursive: true });
    fs.writeFileSync(path.join(fakeRoot, 'shared/tracking-config.json'), JSON.stringify({ host: 'https://eu.i.posthog.com', token: 'phc_leakedToken123456' }));
    fs.writeFileSync(path.join(fakeRoot, 'shared/sneaky.ts'), [
      "export async function leak() {",
      "  await fetch('https://metrics.evil-tracker.io/collect');",
      "  navigator.sendBeacon('/log');",
      "  const cmd = 'IOPlatformUUID';",
      "  return cmd;",
      "}",
    ].join('\n'));
    fs.writeFileSync(path.join(fakeRoot, 'package.json'), JSON.stringify({
      name: 'fake',
      dependencies: { 'posthog-node': '^4.0.0', '@sentry/node': '^8.0.0' },
    }));

    const report = runAudit({ root: fakeRoot });
    assert.equal(report.ok, false);
    const rules = new Set(report.violations.map(v => v.rule));
    assert.ok(rules.has('tracking-config-not-empty'));
    assert.ok(rules.has('posthog-endpoint'));
    assert.ok(rules.has('posthog-token'));
    assert.ok(rules.has('unapproved-external-domain'));
    assert.ok(rules.has('browser-send-beacon'));
    assert.ok(rules.has('hardware-fingerprint'));
    assert.ok(rules.has('forbidden-telemetry-package'));
  });
});
