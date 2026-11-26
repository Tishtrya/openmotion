#!/usr/bin/env node
/**
 * OpenMotion Privacy Hardening Script
 *
 * Strips all telemetry, analytics, hardware device fingerprinting, install/campaign
 * attribution, and unsolicited background network calls from an OpenMotion checkout
 * while preserving TypeScript types, Studio builds, MCP tools, and core features.
 *
 * Designed to be:
 *   - Idempotent: running it multiple times produces the exact same tree.
 *   - Drift-aware: fails loudly (non-zero exit) if expected upstream anchors vanish.
 *   - Portable: works in-place in a fork or against any checkout via `--root <dir>`.
 *
 * Usage:
 *   node privacy/strip-telemetry.mjs [--root <dir>] [--dry-run] [--json]
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const MARKER = 'OPENMOTION_PRIVACY_HARDENED';

function parseArgs(argv) {
  let root = process.cwd();
  let dryRun = false;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--root') {
      const next = argv[++i];
      if (!next) throw new Error('--root requires a directory path');
      root = path.resolve(next);
    } else if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '-h' || arg === '--help') {
      console.log('Usage: node privacy/strip-telemetry.mjs [--root <dir>] [--dry-run] [--json]');
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { root, dryRun, json };
}

class Stripper {
  constructor(root, dryRun) {
    this.root = root;
    this.dryRun = dryRun;
    this.actions = [];
    this.errors = [];
  }

  abs(rel) {
    return path.join(this.root, rel);
  }

  exists(rel) {
    return fs.existsSync(this.abs(rel));
  }

  read(rel) {
    return fs.readFileSync(this.abs(rel), 'utf8');
  }

  write(rel, content, summary) {
    const target = this.abs(rel);
    const prev = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
    if (prev === content) {
      this.actions.push({ file: rel, status: 'unchanged', summary });
      return;
    }
    if (!this.dryRun) {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, 'utf8');
    }
    this.actions.push({ file: rel, status: this.dryRun ? 'would-update' : 'updated', summary });
  }

  remove(rel, summary) {
    const target = this.abs(rel);
    if (!fs.existsSync(target)) {
      this.actions.push({ file: rel, status: 'already-removed', summary });
      return;
    }
    if (!this.dryRun) {
      fs.rmSync(target, { force: true });
    }
    this.actions.push({ file: rel, status: this.dryRun ? 'would-remove' : 'removed', summary });
  }

  requireFile(rel, stepName) {
    if (!this.exists(rel)) {
      this.errors.push(`[DRIFT] ${stepName}: expected file '${rel}' does not exist`);
      return false;
    }
    return true;
  }

  patchRegex(rel, stepName, alreadyPatchedTest, regex, replacement, summary) {
    if (!this.requireFile(rel, stepName)) return;
    const current = this.read(rel);
    if (alreadyPatchedTest(current)) {
      this.actions.push({ file: rel, status: 'unchanged', summary });
      return;
    }
    if (!regex.test(current)) {
      this.errors.push(`[DRIFT] ${stepName}: anchor pattern not found in '${rel}'`);
      return;
    }
    const next = current.replace(regex, replacement);
    this.write(rel, next, summary);
  }
}

// ---------------------------------------------------------------------------
// Replacement module bodies (type-compatible, zero network, zero disk, zero IDs)
// ---------------------------------------------------------------------------

const TRACKING_DEVICE_TS = `// ${MARKER}: hardware/OS device fingerprinting permanently removed.
export type DeviceIdentity = { device_id: string; device_id_source: 'platform' | 'unavailable' };
export const unknownDevice: DeviceIdentity = { device_id: 'unknown', device_id_source: 'unavailable' };

export function deviceIdentity(_platform: string, _identifier: string): DeviceIdentity {
  return unknownDevice;
}

export function loadDeviceIdentity(): Promise<DeviceIdentity> {
  return Promise.resolve(unknownDevice);
}
`;

const TRACKING_NODE_TS = `// ${MARKER}: PostHog sender and persistent installation identity permanently removed.
import { createTracker } from './core.ts';
import type { Entry, Registry, PendingEvent, Receipt } from './core.ts';
import type { DeviceIdentity } from './device.ts';

export type Identity = { installation_id: string; utm_source: string | null; created_at: string };

const DISABLED_IDENTITY: Identity = Object.freeze({
  installation_id: '00000000-0000-4000-8000-000000000000',
  utm_source: null,
  created_at: '1970-01-01T00:00:00.000Z',
});

export async function loadIdentity(_directory: string, _source?: string): Promise<Identity> {
  return { ...DISABLED_IDENTITY };
}

export async function saveInstallationSource(_directory: string, _source?: string): Promise<Identity> {
  return { ...DISABLED_IDENTITY };
}

export function createPosthogSender(_options: {
  host: string; token: string; identity: Identity; appVersion: string; device?: () => Promise<DeviceIdentity>;
  env: 'development' | 'test' | 'production'; testRunId?: string; timeoutMs?: number; fetch?: typeof fetch; geoip?: boolean; source?: () => string | null;
}) {
  return async (_events: readonly PendingEvent[], _signal: AbortSignal): Promise<Receipt> => 'drop';
}

export function createNodeTracking<const R extends Registry>(options: {
  registry: R; identity: Identity; host: string; token?: string; appVersion: string; device?: () => Promise<DeviceIdentity>;
  env: 'development' | 'test' | 'production'; testRunId?: string; entrypoint: Entry;
  enabled: boolean; timeoutMs?: number; flushIntervalMs?: number; maxQueue?: number; geoip?: boolean; source?: () => string | null; isEnabled?: () => boolean;
}) {
  return createTracker({
    registry: options.registry,
    entrypoint: options.entrypoint,
    enabled: false,
    isEnabled: () => false,
    send: async () => 'drop' as const,
  });
}
`;

const TRACKING_BROWSER_TS = `// ${MARKER}: browser telemetry transport permanently disabled.
import { createTracker } from './core.ts';
import type { Registry } from './core.ts';

export function createBrowserTracking<const R extends Registry>(options: {
  endpoint: string; registry: R; enabled: boolean; flushIntervalMs?: number; isEnabled?: () => boolean;
}) {
  return createTracker({
    registry: options.registry,
    entrypoint: 'studio',
    enabled: false,
    isEnabled: () => false,
    send: async () => 'drop' as const,
  });
}
`;

const TRACKING_TASK_LEDGER_TS = `// ${MARKER}: in-memory no-op task ledger (no tracking/tasks.json written to disk).
import path from 'node:path';

export type LedgerTaskType = 'asset_import' | 'edit' | 'export';
export type LedgerOutcome = 'success' | 'failure' | 'unknown' | 'cancelled';
export type LedgerTask = {
  task_id: string;
  task_type: LedgerTaskType;
  project_id?: string;
  run_id?: string;
  operation_id?: string;
  accepted_at: string;
  deadline_at: string;
  terminal_at?: string;
  outcome?: LedgerOutcome;
  applied?: 'true' | 'false' | 'unknown';
  error_code?: string;
};

export class TaskLedger {
  readonly folder: string;
  readonly file: string;
  private tasks: Record<string, LedgerTask> = {};

  constructor(directory: string) {
    this.folder = path.join(directory, 'tracking');
    this.file = path.join(this.folder, 'tasks.json');
  }

  async accept(task: LedgerTask): Promise<LedgerTask> {
    this.tasks[task.task_id] = { ...task };
    return this.tasks[task.task_id];
  }

  async terminal(taskId: string, outcome: LedgerOutcome, applied: LedgerTask['applied'], errorCode?: string): Promise<LedgerTask> {
    const now = new Date().toISOString();
    const existing = this.tasks[taskId] ?? {
      task_id: taskId,
      task_type: 'export' as const,
      accepted_at: now,
      deadline_at: now,
    };
    const next: LedgerTask = {
      ...existing,
      outcome,
      applied,
      terminal_at: existing.terminal_at ?? now,
      ...(errorCode ? { error_code: errorCode } : {}),
    };
    this.tasks[taskId] = next;
    return next;
  }

  async snapshot(): Promise<Record<string, LedgerTask>> {
    return { ...this.tasks };
  }
}
`;

const SHARED_TRACKING_TS = `// ${MARKER}: application telemetry permanently disabled and locked off.
export { trackingError } from '../tracking/tool-fields.ts';
import { createTracker } from '../tracking/core.ts';
import type { Entry } from '../tracking/core.ts';
import { omEvents } from '../tracking/events.ts';
import type { HostContext } from '../tracking/host.ts';

export type OmTracking = ReturnType<typeof createTracker<typeof omEvents>>;

export function trackingLockReason(): 'environment' | null {
  return 'environment' as const;
}

export function trackingLocked(): boolean {
  return true;
}

export function trackingPreference(_directory: string): boolean {
  return false;
}

export async function saveTrackingPreference(_directory: string, _enabled: boolean): Promise<void> {
  // Telemetry is permanently disabled; do not create tracking/preferences.json.
}

export async function createAppTracking(_directory: string, entrypoint: Entry): Promise<OmTracking> {
  return createTracker({
    registry: omEvents,
    entrypoint,
    enabled: false,
    isEnabled: () => false,
    send: async () => 'drop' as const,
  });
}

export async function closeTracking(tracking?: OmTracking): Promise<void> {
  tracking?.close();
}

export function trackPhase1Result(
  _tracking: OmTracking | undefined,
  _name: string,
  _args: any,
  _result: any,
  _error?: unknown,
  _host?: HostContext,
): void {
  // No-op in privacy-hardened build.
}
`;

const SHARED_INSTALL_ATTRIBUTION_TS = `// ${MARKER}: installation attribution permanently removed.
export async function recordInstallationStart(_directory: string, _host: string, _source?: string): Promise<void> {
  // No-op in privacy-hardened build.
}

export async function recordInstallation(_directory: string, _host: string, _source?: string): Promise<void> {
  // No-op in privacy-hardened build.
}
`;

const STUDIO_MOTION_TRACKING_TS = `// ${MARKER}: Studio browser tracking permanently disabled (no /motion-api/tracking requests).
import type { studioEvents } from '../../../tracking/events.ts';
import type { StudioEvent } from '../../../tracking/events.ts';
import type { EventFields } from '../../../tracking/core.ts';

export function initializeTracking(): Promise<void> {
  return Promise.resolve();
}

export async function trackMotion<E extends StudioEvent>(_event: E, _properties: EventFields<typeof studioEvents[E]>) {
  return 'disabled' as const;
}

export function getMotionTrackingStatus() {
  return { configuration: 'disabled' as const, enabled: false, pending: 0, retryAfterMs: 0 };
}

export function flushMotionTracking() {
  return Promise.resolve('disabled' as const);
}

export function setMotionTrackingEnabled(_enabled: boolean): void {
  // Permanently disabled.
}
`;

const STUDIO_WEBMCP_TRACKING_TS = `// ${MARKER}: WebMCP telemetry permanently disabled.
import type { ModelContextTool } from './types';

export function withWebMcpTracking(tool: ModelContextTool): ModelContextTool {
  return tool;
}

export function trackWebMcpRegistration(_name: string, _result: 'success' | 'failure' | 'cancelled', _started: number): void {
  // No-op in privacy-hardened build.
}
`;

const STUDIO_TELEMETRY_CLIENT_TS = `// ${MARKER}: Studio telemetry client permanently disabled.
type EventProperties = Record<string, string | number | boolean | undefined>;

export function shouldTrack(): boolean {
  return false;
}

export function trackEvent(_event: string, _properties: EventProperties = {}): void {
  // No-op in privacy-hardened build.
}
`;

const STUDIO_TELEMETRY_POLICY_TS = `// ${MARKER}: Studio telemetry policy permanently locked off.
export function browserTelemetryAllowed(): boolean {
  return false;
}

declare global {
  interface Window {
    __HF_CLI_TELEMETRY_DISABLED?: boolean;
  }
}
`;

const STUDIO_UTILS_TELEMETRY_TS = `// ${MARKER}: Studio legacy telemetry wrapper permanently disabled.
interface EventProperties {
  [key: string]: string | number | boolean | null | undefined;
}

export function trackStudioEvent(_event: string, _properties: EventProperties = {}): void {
  // No-op in privacy-hardened build.
}

export function flushViaBeacon(): void {
  // No-op in privacy-hardened build.
}
`;

const STUDIO_TELEMETRY_DISTINCT_ID_TS = `// ${MARKER}: persistent browser distinct_id minting and storage permanently removed.
export const DISTINCT_ID_KEY = 'hyperframes-studio:anonymousId';
export const LEGACY_STUDIO_ANON_ID_KEY = 'hf-studio-anon-id';

declare global {
  interface Window {
    __HF_CLI_DISTINCT_ID?: string;
  }
}

export function getCliDistinctId(): string | null {
  return null;
}

export function resolveStudioDistinctId(): string {
  return 'disabled';
}

export function __resetStudioDistinctIdForTests(): void {
  // No-op: no cached identity.
}
`;

const STUDIO_TELEMETRY_CONFIG_TS = `// ${MARKER}: Studio telemetry config permanently opted out with zero storage writes.
export function getAnonymousId(): string {
  return 'disabled';
}

export function isOptedOut(): boolean {
  return true;
}

export function hasShownNotice(): boolean {
  return true;
}

export function markNoticeShown(): void {
  // No-op.
}

export function hasFiredSessionStart(): boolean {
  return true;
}

export function markSessionStartFired(): void {
  // No-op.
}
`;

const STUDIO_CAMPAIGN_ATTRIBUTION_TS = `// ${MARKER}: marketing banner and cross-site attribution query parameters permanently removed.
import { useState } from 'react';

export const BLACK_FRIDAY_CAMPAIGN = 'black_friday_2026';
export const BLACK_FRIDAY_STARTS_AT = 0;
export const BLACK_FRIDAY_ENDS_AT = 0;

export function blackFridayActive(_now?: number): boolean {
  return false;
}

export function bannerDismissedToday(_now?: Date): boolean {
  return true;
}

export function dismissBannerToday(_now?: Date): void {
  // No-op.
}

export function resetBannerDismissal(): void {
  // No-op.
}

export function useMinuteCondition(read: () => boolean) {
  const [value, setValue] = useState(read);
  return [value, setValue] as const;
}

export const useBlackFridayActive = () => false;
export const shouldShowBlackFridayBanner = () => false;

export type CampaignEntrySource = 'openmotion_bf_banner' | 'openmotion_header_pricing';

export function newCampaignEntryId(): string {
  return '';
}

export function campaignPricingUrl(
  locale: string,
  _source?: CampaignEntrySource,
  _entryId?: string,
  _at?: Date,
  _campaign?: boolean,
): string {
  return locale.startsWith('zh') ? 'https://open-design.ai/zh/pricing/' : 'https://open-design.ai/pricing/';
}
`;

const STUDIO_FEEDBACK_CARD_TSX = `// ${MARKER}: external feedback prompt and interview booking link permanently removed.
import { memo } from 'react';

export const StudioFeedbackCard = memo(function StudioFeedbackCard() {
  return null;
});
`;

const STUDIO_PRIVACY_SETTINGS_TSX = `// ${MARKER}: telemetry permanently disabled in this privacy-hardened build.
import { IconButton } from 'open-design-ui/icon-button';
import { useEffect, useRef } from 'react';
import { useI18n } from '../i18n/I18n';
import { DiagnosticExport } from './DiagnosticExport';
import { Toggle } from './settingsPrimitives';

export function PrivacySettings({ onClose, embedded = false }: { onClose: () => void; embedded?: boolean }) {
  const { t } = useI18n(), dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (!embedded) dialog.current?.showModal(); return () => dialog.current?.close(); }, [embedded]);

  const content = <>
    <section className={embedded ? 'om-card om-card-stack' : undefined}>
      <div className="om-settings-row">
        <label className="om-subtitle">{t('Share usage data')}</label>
        <Toggle label={t('Share usage data')} checked={false} disabled onChange={() => {}} />
      </div>
      <p className="om-muted" role="status">
        {t('Telemetry, hardware fingerprinting, and usage reporting have been permanently removed in this privacy-hardened build.')}
      </p>
    </section>
    <section className={embedded ? 'om-card om-card-stack' : undefined}>
      <DiagnosticExport />
    </section>
  </>;

  if (embedded) return content;
  return <dialog ref={dialog} className="motion-model-dialog motion-media-surface motion-privacy-dialog" aria-labelledby="privacy-settings-title" onCancel={event => { event.preventDefault(); onClose(); }}>
    <header><h2 id="privacy-settings-title">{t('Privacy settings')}</h2><IconButton variant="plain" className="motion-media-close" aria-label={t('Close')} onClick={onClose} icon="×" /></header>
    {content}
  </dialog>;
}
`;

export function runStrip({ root = process.cwd(), dryRun = false } = {}) {
  const s = new Stripper(root, dryRun);

  // 1. Wipe PostHog project config (projectId, host, token, geoip)
  if (s.requireFile('shared/tracking-config.json', 'tracking-config')) {
    s.write('shared/tracking-config.json', '{}\n', 'Remove hardcoded PostHog host, token, projectId, and geoip flag');
  }

  // 2. Replace tracking runtime modules with strict no-op / zero-fingerprint / zero-disk stubs
  if (s.requireFile('tracking/device.ts', 'tracking-device')) {
    s.write('tracking/device.ts', TRACKING_DEVICE_TS, 'Remove hardware/OS device fingerprinting (ioreg, MachineGuid, machine-id)');
  }
  if (s.requireFile('tracking/node.ts', 'tracking-node')) {
    s.write('tracking/node.ts', TRACKING_NODE_TS, 'Remove PostHog HTTP sender and tracking/identity.json disk persistence');
  }
  if (s.requireFile('tracking/browser.ts', 'tracking-browser')) {
    s.write('tracking/browser.ts', TRACKING_BROWSER_TS, 'Remove browser /motion-api/tracking sender and tracking_context reader');
  }
  if (s.requireFile('tracking/task-ledger.ts', 'tracking-task-ledger')) {
    s.write('tracking/task-ledger.ts', TRACKING_TASK_LEDGER_TS, 'Replace tracking/tasks.json disk ledger with in-memory no-op');
  }

  // 3. Neutralize previewTrackingContext in tracking/host.ts
  s.patchRegex(
    'tracking/host.ts',
    'tracking-host-preview-context',
    src => src.includes(MARKER) && !src.includes("url.searchParams.set('tracking_context'"),
    /\/\*\* Attribute a page to its opening link[\s\S]*?export function previewTrackingContext\([\s\S]*$/,
    `// ${MARKER}: tracking_context URL injection removed.\nexport function previewTrackingContext(value: any, _origin: string, _token: string): any {\n  return value;\n}\n`,
    'Disable tracking_context URL parameter injection in tracking/host.ts'
  );

  // 4. Delete PostHog GeoIP Hog script and remove it from scripts/distribution.ts
  s.remove('tracking/posthog-geoip.hog', 'Delete PostHog GeoIP transformation script');
  s.patchRegex(
    'scripts/distribution.ts',
    'distribution-remove-hog',
    src => !src.includes('tracking/posthog-geoip.hog'),
    /,\s*'tracking\/posthog-geoip\.hog'/g,
    '',
    'Remove deleted tracking/posthog-geoip.hog from distribution manifest'
  );

  // 5. Lock shared/tracking.ts and neutralize shared/install-attribution.ts
  if (s.requireFile('shared/tracking.ts', 'shared-tracking')) {
    s.write('shared/tracking.ts', SHARED_TRACKING_TS, 'Permanently lock telemetry off and disable tracking-config/env overrides');
  }
  if (s.requireFile('shared/install-attribution.ts', 'shared-install-attribution')) {
    s.write('shared/install-attribution.ts', SHARED_INSTALL_ATTRIBUTION_TS, 'Disable installer UTM attribution and event reporting');
  }

  // 6. Stop propagating tracking_context in shared/workspace-url.ts
  s.patchRegex(
    'shared/workspace-url.ts',
    'workspace-url-tracking-context',
    src => src.includes(MARKER) && !src.includes('tracking_context'),
    /\n\s*const tracking = current\.get\('tracking_context'\);\n\s*if \(tracking && [^\n]+\) url\.searchParams\.set\('tracking_context', tracking\);/,
    `\n  // ${MARKER}: tracking context URL propagation removed.`,
    'Stop propagating tracking_context query parameter in shared/workspace-url.ts'
  );

  // 7. Harden hyperframes.ts child-process environment (no telemetry, no update check, no auto-install)
  s.patchRegex(
    'hyperframes.ts',
    'hyperframes-env-hardening',
    src => src.includes('HYPERFRAMES_NO_TELEMETRY') && src.includes('HYPERFRAMES_NO_UPDATE_CHECK') && src.includes('HYPERFRAMES_NO_AUTO_INSTALL'),
    /HYPERFRAMES_NO_TELEMETRY:\s*'1',/,
    `HYPERFRAMES_NO_TELEMETRY: '1', HYPERFRAMES_NO_UPDATE_CHECK: '1', HYPERFRAMES_NO_AUTO_INSTALL: '1',`,
    'Add HYPERFRAMES_NO_UPDATE_CHECK=1 and HYPERFRAMES_NO_AUTO_INSTALL=1 to hyperframes.ts'
  );

  // 8. Disable unsolicited background gateway.account.prefetch() on server startup
  s.patchRegex(
    'server.ts',
    'server-disable-account-prefetch',
    src => src.includes(`${MARKER}: account prefetch disabled`) && !/^\s*if \([^)]*\) gateway\.account\.prefetch\(\);/m.test(src),
    /^([ \t]*)if \(!process\.env\.NODE_TEST_CONTEXT\) gateway\.account\.prefetch\(\);/m,
    `$1// ${MARKER}: account prefetch disabled; connector prepares on demand when user explicitly signs in.`,
    'Disable automatic background npm connector download (gateway.account.prefetch) on server startup'
  );

  // 9. Disable Studio browser tracking, reporting transport, and WebMCP tracking
  if (s.requireFile('studio/src/motion/tracking.ts', 'studio-motion-tracking')) {
    s.write('studio/src/motion/tracking.ts', STUDIO_MOTION_TRACKING_TS, 'Replace Studio motion tracking with zero-network no-op');
  }
  s.patchRegex(
    'studio/src/motion/reporting.ts',
    'studio-motion-reporting',
    src => src.includes(MARKER) && !src.includes("import('./tracking')"),
    /type Transport = typeof import\('\.\/tracking'\);[\s\S]*?export const send = <E extends StudioEvent>\([\s\S]*?\n\};/,
    `// ${MARKER}: Studio reporting transport permanently disabled.\nexport const loadReportingTransport = async () => ({});\nexport const send = <E extends StudioEvent>(_event: E, _properties: Fields<E>) => {};`,
    'Disable dynamic tracking transport in studio/src/motion/reporting.ts'
  );
  if (s.requireFile('studio/src/webmcp/tracking.ts', 'studio-webmcp-tracking')) {
    s.write('studio/src/webmcp/tracking.ts', STUDIO_WEBMCP_TRACKING_TS, 'Disable WebMCP telemetry wrapper');
  }

  // 10. Harden Studio legacy/Hyperframes telemetry modules (no localStorage IDs, no sendBeacon)
  if (s.requireFile('studio/src/telemetry/client.ts', 'studio-telemetry-client')) {
    s.write('studio/src/telemetry/client.ts', STUDIO_TELEMETRY_CLIENT_TS, 'Lock studio/src/telemetry/client.ts to no-op');
  }
  if (s.requireFile('studio/src/telemetry/policy.ts', 'studio-telemetry-policy')) {
    s.write('studio/src/telemetry/policy.ts', STUDIO_TELEMETRY_POLICY_TS, 'Lock studio/src/telemetry/policy.ts to false');
  }
  if (s.requireFile('studio/src/utils/studioTelemetry.ts', 'studio-utils-telemetry')) {
    s.write('studio/src/utils/studioTelemetry.ts', STUDIO_UTILS_TELEMETRY_TS, 'Lock studio/src/utils/studioTelemetry.ts to no-op');
  }
  if (s.requireFile('studio/src/telemetry/distinctId.ts', 'studio-telemetry-distinct-id')) {
    s.write('studio/src/telemetry/distinctId.ts', STUDIO_TELEMETRY_DISTINCT_ID_TS, 'Remove localStorage distinct_id persistence and CLI ID adoption');
  }
  if (s.requireFile('studio/src/telemetry/config.ts', 'studio-telemetry-config')) {
    s.write('studio/src/telemetry/config.ts', STUDIO_TELEMETRY_CONFIG_TS, 'Lock studio/src/telemetry/config.ts to opted-out with zero storage writes');
  }

  // 11. Strip Black Friday banner & cross-site pricing attribution parameters
  if (s.requireFile('studio/src/motion/campaignAttribution.ts', 'studio-campaign-attribution')) {
    s.write('studio/src/motion/campaignAttribution.ts', STUDIO_CAMPAIGN_ATTRIBUTION_TS, 'Remove campaign banner and od_*/utm_* cross-site attribution parameters');
  }

  // 12. Disable unsolicited background GitHub Stars API fetch in studio/src/motion/githubRepository.ts
  s.patchRegex(
    'studio/src/motion/githubRepository.ts',
    'studio-github-stars-fetch',
    src => src.includes(MARKER) && !src.includes('api.github.com/repos/nexu-io/openmotion'),
    /const STARS_API = 'https:\/\/api\.github\.com\/repos\/nexu-io\/openmotion';\nconst CACHE_KEY = 'openmotion\.github-stars';\nconst CACHE_TTL = 5 \* 60 \* 1000;\ntype StarsCache = \{ count: number; at: number \};/,
    `// ${MARKER}: background GitHub Stars API fetch removed.`,
    'Remove STARS_API constant from studio/src/motion/githubRepository.ts'
  );
  s.patchRegex(
    'studio/src/motion/githubRepository.ts',
    'studio-github-stars-reader',
    src => src.includes(MARKER) && !src.includes('fetch(STARS_API'),
    /\/\*\* One public request shared by both headers[\s\S]*?export function createRepositoryStarsReader\(\) \{[\s\S]*?\n\}\n\nexport const readRepositoryStars = createRepositoryStarsReader\(\);/,
    `// ${MARKER}: background GitHub Stars API reader disabled.\nexport function createRepositoryStarsReader() {\n  return function readStars(): Promise<number | null> {\n    return Promise.resolve(null);\n  };\n}\n\nexport const readRepositoryStars = createRepositoryStarsReader();`,
    'Disable background GitHub Stars API request in studio/src/motion/githubRepository.ts'
  );

  // 13. Disable StudioFeedbackCard (removes external Google Calendar interview link & telemetry)
  if (s.requireFile('studio/src/components/feedback/StudioFeedbackCard.tsx', 'studio-feedback-card')) {
    s.write('studio/src/components/feedback/StudioFeedbackCard.tsx', STUDIO_FEEDBACK_CARD_TSX, 'Disable StudioFeedbackCard prompt and external interview link');
  }

  // 14. Update PrivacySettings UI to reflect permanently removed telemetry (keep local DiagnosticExport)
  if (s.requireFile('studio/src/motion/PrivacySettings.tsx', 'studio-privacy-settings')) {
    s.write('studio/src/motion/PrivacySettings.tsx', STUDIO_PRIVACY_SETTINGS_TSX, 'Lock PrivacySettings toggle off with no /tracking/preferences network calls');
  }

  // 15. Neutralize Cloudflare install-guide worker UTM injection
  if (s.exists('workers/install-guide/index.ts')) {
    s.patchRegex(
      'workers/install-guide/index.ts',
      'worker-install-guide-utm',
      src => src.includes(MARKER) && !src.includes('--utm-source'),
      /export function attributeGuide\(text: string, source: string \| null\): string \{[\s\S]*?\n\}/,
      `// ${MARKER}: install guide UTM injection disabled.\nexport function attributeGuide(text: string, _source: string | null): string {\n  return text;\n}`,
      'Disable --utm-source injection in workers/install-guide/index.ts'
    );
  }

  // 16. Harden Docker deployment defaults
  s.patchRegex(
    'deploy/.env.example',
    'deploy-env-example',
    src => /^DO_NOT_TRACK=1$/m.test(src) && /^OPENMOTION_TELEMETRY=0$/m.test(src),
    /# Set to 1 to disable analytics\.\nDO_NOT_TRACK=/,
    `# Telemetry is permanently disabled in this privacy-hardened build.\nDO_NOT_TRACK=1\nOPENMOTION_TELEMETRY=0\nHYPERFRAMES_NO_TELEMETRY=1\nHYPERFRAMES_NO_UPDATE_CHECK=1`,
    'Set privacy-safe defaults in deploy/.env.example'
  );
  s.patchRegex(
    'deploy/docker-compose.yml',
    'deploy-docker-compose',
    src => src.includes('OPENMOTION_TELEMETRY: "0"') && src.includes('DO_NOT_TRACK: "1"'),
    /DO_NOT_TRACK:\s*\$\{DO_NOT_TRACK:-\}/,
    `DO_NOT_TRACK: "1"\n      OPENMOTION_TELEMETRY: "0"\n      HYPERFRAMES_NO_TELEMETRY: "1"\n      HYPERFRAMES_NO_UPDATE_CHECK: "1"`,
    'Force telemetry-off env defaults in deploy/docker-compose.yml'
  );

  // 17. Strip cross-site attribution parameters from gateway/account.ts subscription link
  s.patchRegex(
    'gateway/account.ts',
    'gateway-account-subscription-attribution',
    src => src.includes(`${MARKER}: subscription link attribution removed`) && !src.includes('od_entry_id'),
    /const target = '\/dashboard\?' \+ new URLSearchParams\(\{ billing: 'plan', od_origin: 'openmotion', od_entry_source: 'openmotion_manage_subscription',\n\s*od_entry_id: randomUUID\(\), od_entry_at: new Date\(\)\.toISOString\(\) \}\);/,
    `// ${MARKER}: subscription link attribution removed.\n    const target = '/dashboard?' + new URLSearchParams({ billing: 'plan' });`,
    'Strip od_origin/od_entry_* cross-site attribution params from gateway/account.ts openSubscription()'
  );

  // 18. Remove PostHog token allowlist entry from .github/gitleaks.toml
  if (s.exists('.github/gitleaks.toml')) {
    s.patchRegex(
      '.github/gitleaks.toml',
      'gitleaks-remove-posthog-allowlist',
      src => !/phc_[A-Za-z0-9_]+/.test(src),
      /\n\[\[allowlists\]\]\ndescription = "Existing public, write-only OpenMotion analytics identifier[^\n]*\nregexTarget = "secret"\nregexes = \['''\^phc_[^']+'''\]\n/,
      '\n',
      'Remove PostHog token allowlist from .github/gitleaks.toml'
    );
  }

  // 19. Remove upstream hardware device-identity CI workflow
  s.remove('.github/workflows/device-identity-check.yml', 'Remove obsolete native device-identity CI workflow');

  return {
    root,
    dryRun,
    ok: s.errors.length === 0,
    actions: s.actions,
    errors: s.errors,
    counts: {
      updated: s.actions.filter(a => a.status === 'updated' || a.status === 'would-update').length,
      removed: s.actions.filter(a => a.status === 'removed' || a.status === 'would-remove').length,
      unchanged: s.actions.filter(a => a.status === 'unchanged' || a.status === 'already-removed').length,
      errors: s.errors.length,
    },
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = runStrip(args);
    if (args.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      for (const action of result.actions) {
        console.log(`[${action.status.toUpperCase()}] ${action.file} — ${action.summary}`);
      }
      if (result.errors.length) {
        console.error('\nDrift / Errors detected:');
        for (const err of result.errors) console.error('  ' + err);
      }
      console.log(
        `\nSummary: ${result.counts.updated} updated, ${result.counts.removed} removed, ${result.counts.unchanged} unchanged, ${result.counts.errors} errors.`
      );
    }
    if (!result.ok) process.exit(1);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
