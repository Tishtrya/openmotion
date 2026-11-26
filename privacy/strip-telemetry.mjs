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

  // For anchors upstream has legitimately removed. The fail-closed audit is still the
  // backstop: if the dangerous behaviour returns in a new shape, audit-privacy.mjs fails.
  patchRegexOptional(rel, stepName, alreadyPatchedTest, regex, replacement, summary) {
    if (!this.exists(rel)) {
      this.actions.push({ file: rel, status: 'unchanged', summary: `${stepName}: file absent upstream` });
      return;
    }
    const current = this.read(rel);
    if (alreadyPatchedTest(current)) {
      this.actions.push({ file: rel, status: 'unchanged', summary });
      return;
    }
    if (!regex.test(current)) {
      this.actions.push({ file: rel, status: 'unchanged', summary: `${stepName}: anchor absent upstream` });
      return;
    }
    const next = current.replace(regex, replacement);
    this.write(rel, next, summary);
  }

  transform(rel, stepName, alreadyPatchedTest, transform, summary) {
    if (!this.requireFile(rel, stepName)) return;
    const current = this.read(rel);
    if (alreadyPatchedTest(current)) {
      this.actions.push({ file: rel, status: 'unchanged', summary });
      return;
    }
    const next = transform(current);
    if (next === current) {
      this.errors.push(`[DRIFT] ${stepName}: transform produced no change in '${rel}'`);
      return;
    }
    this.write(rel, next, summary);
  }

  // For files/anchors that only exist in the current upstream layout. Older fork
  // checkouts must remain idempotent so the push/PR privacy guard still passes
  // while an upstream-sync PR is in flight.
  transformOptional(rel, stepName, alreadyPatchedTest, transform, summary) {
    if (!this.exists(rel)) {
      this.actions.push({ file: rel, status: 'unchanged', summary: `${stepName}: file absent in this checkout` });
      return;
    }
    const current = this.read(rel);
    if (alreadyPatchedTest(current)) {
      this.actions.push({ file: rel, status: 'unchanged', summary });
      return;
    }
    const next = transform(current);
    if (next === current) {
      this.actions.push({ file: rel, status: 'unchanged', summary: `${stepName}: no applicable anchor in this checkout` });
      return;
    }
    this.write(rel, next, summary);
  }

  hardenIfExists(rel, content, summary) {
    if (!this.exists(rel)) {
      this.actions.push({ file: rel, status: 'unchanged', summary: `${summary} (file absent in this checkout)` });
      return;
    }
    this.write(rel, content, summary);
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

const STUDIO_CAMPAIGN_ATTRIBUTION_TS = `// ${MARKER}: campaign links and cross-site attribution permanently removed.
import { useCallback, useEffect, useState } from 'react';
import type { ExploreFilters } from './workspacePageRouting';

export const BLACK_FRIDAY_CAMPAIGN = 'black_friday_2026';
export const BLACK_FRIDAY_STARTS_AT = 0;
export const BLACK_FRIDAY_ENDS_AT = 0;
export const BLACK_FRIDAY_HERO_STARTS_AT = 0;
export const BLACK_FRIDAY_HERO_ENDS_AT = 0;
export const COUNTDOWN_CYCLE_SECONDS = 12 * 60 * 60;

export function blackFridayActive(_now = Date.now()): boolean {
  return false;
}

export function blackFridayHeroActive(_now = Date.now()): boolean {
  return false;
}

export function readBlackFridayCountdown(_now = Date.now()) {
  return { hours: '00', minutes: '00', seconds: '00', datetime: 'PT00H00M00S' };
}

export function bannerDismissedToday(_now = new Date()): boolean {
  return true;
}

export function dismissBannerToday(_now = new Date()): void {
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

export function useExploreCampaign(_filters: ExploreFilters) {
  const [active, setActive] = useMinuteCondition(() => false);
  const expire = useCallback(() => setActive(false), [setActive]);
  return { showHero: active, expire };
}

export type ExploreCampaign = ReturnType<typeof useExploreCampaign>;

export const shouldShowBlackFridayBanner = () => false;

export type CampaignEntrySource = 'openmotion_bf_banner' | 'openmotion_bf_hero' | 'openmotion_bf_hub' | 'openmotion_header_pricing';

export function newCampaignEntryId(): string {
  return '';
}

export function campaignPricingUrl(
  locale: string,
  _source?: CampaignEntrySource,
  _entryId?: string,
  _at = new Date(),
  _campaign = false,
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


const STUDIO_STUDIO_TRACKING_TS = `// ${MARKER}: Studio usage reporting permanently disabled.
export function trackStudioUsage(_event: string, _properties: Record<string, unknown> = {}): void {
  // No-op in privacy-hardened build.
}

export async function flushStudioUsage(): Promise<void> {
  // No-op in privacy-hardened build.
}
`;

const CLOUD_TRACKING_TS = `// ${MARKER}: cloud PostHog ingestion permanently disabled.
import { isEntitlementHookId, type EntitlementHookId } from '../shared/entitlement-hooks.ts';

export interface CloudTrackingHandle {
  isEnabled(): boolean;
  lockReason(): 'environment' | null;
  acceptBrowserBatch(payload: unknown): number;
  trackWebSignInResult(params: {
    outcome: 'success' | 'failure' | 'cancelled';
    hookId?: string | null;
    entryId?: string | null;
    userId?: string | null;
    durationMs?: number;
  }): void;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function cloudTrackingLockReason(_env: NodeJS.ProcessEnv = process.env): 'environment' | null {
  return 'environment';
}

export function sanitizeHookId(value: string | null | undefined): EntitlementHookId | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return isEntitlementHookId(trimmed) ? trimmed : undefined;
}

export function sanitizeEntryId(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return UUID_PATTERN.test(trimmed) ? trimmed : undefined;
}

export function createCloudTracking(_appVersion: string, _env: NodeJS.ProcessEnv = process.env): CloudTrackingHandle {
  return {
    isEnabled: () => false,
    lockReason: () => 'environment',
    acceptBrowserBatch: () => 0,
    trackWebSignInResult: () => {},
  };
}
`;

const OBSERVABILITY_CONFIG_TS = `// ${MARKER}: browser error/performance observability permanently disabled.
export const RUNTIME_CONFIG_GLOBAL_KEY = '__OPENMOTION_OBSERVABILITY__' as const;
export const RUNTIME_CONFIG_PLACEHOLDER = '<!-- openmotion:observability-config -->' as const;
export const DEFAULT_TRACES_SAMPLE_RATE = 0;

export interface BrowserObservabilityConfig {
  readonly dsn: string;
  readonly environment: string;
  readonly release?: string;
  readonly tracesSampleRate: number;
  readonly tracePropagationTargets?: readonly string[];
  readonly previewOrigin?: string | null;
  readonly appVersion?: string;
  readonly deploymentMode?: string;
}

export interface BrowserObservabilityInput {
  readonly dsn?: string | null;
  readonly environment?: string | null;
  readonly release?: string | null;
  readonly tracesSampleRate?: number | string | null;
  readonly tracePropagationTargets?: readonly string[];
  readonly previewOrigin?: string | null;
  readonly appVersion?: string | null;
  readonly deploymentMode?: string | null;
}

export function parseSentryDsn(_raw: unknown): string | null {
  return null;
}

export function normalizeSampleRate(raw: unknown, fallback = DEFAULT_TRACES_SAMPLE_RATE): number {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const numeric = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(1, Math.max(0, numeric));
}

export function buildBrowserObservabilityConfig(_input: BrowserObservabilityInput): BrowserObservabilityConfig | null {
  return null;
}

export function serializeRuntimeConfigScript(_config: BrowserObservabilityConfig | null): string {
  return '';
}

export function injectRuntimeConfigIntoHtml(html: string, _config: BrowserObservabilityConfig | null): string {
  return html;
}

export function readBrowserObservabilityConfig(_win?: unknown): BrowserObservabilityConfig | null {
  return null;
}
`;

const OBSERVABILITY_BROWSER_TS = `// ${MARKER}: Sentry browser SDK permanently disabled.
import type { ErrorInfo } from 'react';
import type { BrowserObservabilityConfig } from './config.ts';

export interface SentryBrowserSdkLike {
  init: (...args: any[]) => any;
  browserTracingIntegration: (...args: any[]) => any;
  captureException: (...args: any[]) => string | undefined;
  captureReactException: (...args: any[]) => string | undefined;
  reactErrorHandler: (...args: any[]) => any;
  setUser: (...args: any[]) => void;
  setTag: (...args: any[]) => void;
  setContext: (...args: any[]) => void;
  addBreadcrumb: (...args: any[]) => void;
  flush: (...args: any[]) => Promise<boolean>;
  metrics: { distribution: (...args: any[]) => void; [key: string]: any };
}

export interface InitBrowserObservabilityOptions {
  readonly config?: BrowserObservabilityConfig | null;
  readonly sdk?: SentryBrowserSdkLike;
  readonly loader?: () => Promise<SentryBrowserSdkLike>;
}

export interface ObservabilityContextPatch {
  readonly userId?: string | null;
  readonly workspaceId?: string | null;
  readonly workspaceRole?: string | null;
  readonly projectId?: string | null;
  readonly sessionId?: string | null;
  readonly page?: string | null;
  readonly authMode?: string | null;
  readonly hostKind?: 'desktop' | 'connect-script' | 'web' | null;
  readonly shellVersion?: string | null;
  readonly hostPlatform?: string | null;
  readonly releaseChannel?: string | null;
}

export interface CaptureExceptionContext {
  readonly area?: string;
  readonly tags?: Record<string, string>;
  readonly extra?: Record<string, unknown>;
}

export interface PerformanceMetricOptions {
  readonly unit?: 'millisecond' | 'second' | 'none' | 'ratio';
  readonly attributes?: Record<string, string | number | boolean>;
}

export interface ObservabilityBreadcrumbInput {
  readonly category: string;
  readonly message?: string;
  readonly level?: 'info' | 'warning' | 'error';
  readonly data?: Record<string, string | number | boolean>;
}

export function initBrowserObservability(_options: InitBrowserObservabilityOptions = {}): boolean {
  return false;
}

export function isBrowserObservabilityEnabled(): boolean {
  return false;
}

export function getActiveBrowserObservabilityConfig(): BrowserObservabilityConfig | null {
  return null;
}

export async function waitForBrowserObservabilityReady(): Promise<boolean> {
  return false;
}

export function captureBrowserException(_error: unknown, _context: CaptureExceptionContext = {}): string | undefined {
  return undefined;
}

export function captureReactBoundaryError(
  _error: Error,
  _info: Pick<ErrorInfo, 'componentStack'>,
  _boundaryName = 'StudioErrorBoundary',
): string | undefined {
  return undefined;
}

export function createReactRootErrorHandlers(): {
  onUncaughtError?: (error: unknown, errorInfo: ErrorInfo) => void;
  onRecoverableError?: (error: unknown, errorInfo: ErrorInfo) => void;
} {
  return {};
}

export function setObservabilityContext(_patch: ObservabilityContextPatch): void {
  // No-op in privacy-hardened build.
}

export function recordPerformanceMetric(_name: string, _value: number, _options: PerformanceMetricOptions = {}): void {
  // No-op in privacy-hardened build.
}

export function addObservabilityBreadcrumb(_breadcrumb: ObservabilityBreadcrumbInput): void {
  // No-op in privacy-hardened build.
}

export async function flushBrowserObservability(_timeoutMs = 2000): Promise<boolean> {
  return false;
}

export function resetBrowserObservabilityForTests(): void {
  // No-op.
}
`;

const OBSERVABILITY_VITE_TS = `// ${MARKER}: sourcemap/error-reporting build plugin permanently disabled.
import { createHash } from 'node:crypto';
import type { PluginOption } from 'vite';

export interface ResolvedObservabilityBuildConfig {
  readonly sourcemap: boolean | 'hidden';
  readonly injectDebugIds: boolean;
}

export function deriveDeterministicDebugId(seed: string): string {
  const bytes = createHash('sha256').update(seed).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20, 32);
}

export function buildDebugIdFooter(_debugId: string): string {
  return '';
}

export function resolveStudioSourcemapOption(_env: NodeJS.ProcessEnv = process.env): boolean | 'hidden' {
  return true;
}

export function resolveObservabilityBuildConfig(_env: NodeJS.ProcessEnv = process.env): ResolvedObservabilityBuildConfig {
  return { sourcemap: true, injectDebugIds: false };
}

export function createSentryVitePlugins(_env: NodeJS.ProcessEnv = process.env): PluginOption[] {
  return [];
}
`;

const DESKTOP_SENTRY_TS = `// ${MARKER}: Electron Sentry error/crash reporting permanently disabled.
import type { HostPlatform, HostReleaseChannel } from '../../shared/desktop-contract.ts';

export type ParsedSentryEndpoints = {
  dsn: string;
  envelopeUrl: string;
  minidumpUrl: string;
  publicKey: string;
  projectId: string;
};

export type ElectronCrashReporterLike = {
  start: (options: {
    submitURL: string;
    productName?: string;
    compress?: boolean;
    uploadToServer?: boolean;
    ignoreSystemCrashHandler?: boolean;
    extra?: Record<string, string>;
    globalExtra?: Record<string, string>;
  }) => void;
  setUploadToServer?: (uploadToServer: boolean) => void;
};

export type DesktopSentryReporterOptions = {
  dsn?: string | null;
  environment?: string;
  release: string;
  channel: HostReleaseChannel;
  platform: HostPlatform;
  arch: string;
  shellVersion: string;
  appDistDir?: string;
  redactPaths?: readonly string[];
  outboxPath?: string;
  getInstallId?: () => string | undefined;
  osVersion?: string;
  electronVersion?: string;
  chromeVersion?: string;
  nodeVersion?: string;
  appStartTime?: number;
  maxBreadcrumbs?: number;
  debugIds?: Record<string, string>;
  env?: NodeJS.ProcessEnv;
  maxEventsPerMinute?: number;
  sendTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
  onCapture?: (level: 'info' | 'warning' | 'error' | 'fatal') => void;
  onDisabled?: () => void;
};

export type DesktopSentrySessionUpdate = {
  sid: string;
  did?: string;
  init: boolean;
  startedAt: number;
  timestamp: number;
  status: 'ok' | 'exited' | 'crashed' | 'abnormal';
  errors: number;
  durationSeconds?: number;
  release: string;
};

export type DesktopSentryBreadcrumbInput = {
  category: string;
  message?: string;
  level?: 'debug' | 'info' | 'warning' | 'error' | 'fatal';
  type?: string;
  data?: Record<string, unknown>;
};

export type DesktopSentrySpanInput = {
  op: string;
  description?: string;
  startMs: number;
  endMs: number;
  status?: 'ok' | 'cancelled' | 'unknown_error' | 'deadline_exceeded' | 'internal_error' | 'unavailable';
  data?: Record<string, unknown>;
};

export type DesktopSentryTransactionInput = {
  name: string;
  op: string;
  startMs: number;
  endMs: number;
  status?: 'ok' | 'cancelled' | 'unknown_error' | 'deadline_exceeded' | 'internal_error' | 'unavailable';
  tags?: Record<string, string>;
  data?: Record<string, unknown>;
  measurements?: Record<string, { value: number; unit?: 'millisecond' | 'second' | 'none' | 'ratio' }>;
  spans?: readonly DesktopSentrySpanInput[];
};

export type DesktopSentryCaptureContext = {
  area?: string;
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
};

export type DesktopSentryReporter = {
  isEnabled: () => boolean;
  setEnabled: (enabled: boolean) => void;
  getEndpoints: () => ParsedSentryEndpoints | null;
  addBreadcrumb: (crumb: DesktopSentryBreadcrumbInput) => void;
  flushOutbox: () => Promise<number>;
  startCrashReporter: (crashReporter: ElectronCrashReporterLike) => boolean;
  captureException: (error: unknown, context?: DesktopSentryCaptureContext) => Promise<boolean>;
  captureMessage: (message: string, level?: 'info' | 'warning' | 'error' | 'fatal', context?: DesktopSentryCaptureContext) => Promise<boolean>;
  captureTransaction: (transaction: DesktopSentryTransactionInput) => Promise<boolean>;
  sendSession: (update: DesktopSentrySessionUpdate) => Promise<boolean>;
};

export type SentryDebugMetaImage = {
  type: 'sourcemap';
  code_file: string;
  debug_id: string;
};

export function resolveDesktopSentryDsn(
  _env: NodeJS.ProcessEnv = process.env,
  _embedded: string | undefined = undefined,
): string | undefined {
  return undefined;
}

export function parseSentryEnvelopeEndpoints(_rawDsn: unknown): ParsedSentryEndpoints | null {
  return null;
}

export function extractDebugMetaImages(_debugIds: Record<string, string> | undefined, _appDistDir?: string): SentryDebugMetaImage[] {
  return [];
}

export function createDesktopSentryReporter(_options: DesktopSentryReporterOptions): DesktopSentryReporter {
  return {
    isEnabled: () => false,
    setEnabled: () => {},
    getEndpoints: () => null,
    addBreadcrumb: () => {},
    flushOutbox: async () => 0,
    startCrashReporter: () => false,
    captureException: async () => false,
    captureMessage: async () => false,
    captureTransaction: async () => false,
    sendSession: async () => false,
  };
}
`;

const DESKTOP_TELEMETRY_TS = `// ${MARKER}: desktop edge-health telemetry permanently disabled.
import type { HostPlatform, HostReleaseChannel } from '../../shared/desktop-contract.ts';
import type { DesktopTelemetryEvent, DesktopTelemetryRecordInput, DesktopTelemetrySummary } from '../../shared/desktop-telemetry.ts';

export type DesktopTelemetryCollectorOptions = {
  dataDir?: string;
  channel?: HostReleaseChannel;
  platform?: HostPlatform;
  arch?: string;
  shellVersion?: string;
  allowLocalDevLoopback?: boolean;
  maxRetainedEvents?: number;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  flushEndpointUrl?: string;
  fetchImpl?: typeof fetch;
};

export class DesktopTelemetryCollector {
  private readonly channel: HostReleaseChannel;
  private readonly platform: HostPlatform;
  private readonly arch: string;
  private readonly shellVersion: string;
  private readonly updatedAt: string;

  constructor(options: DesktopTelemetryCollectorOptions = {}) {
    this.channel = options.channel ?? 'stable';
    this.platform = options.platform ?? (process.platform as HostPlatform);
    this.arch = options.arch ?? process.arch;
    this.shellVersion = options.shellVersion ?? '0.0.1';
    this.updatedAt = new Date(0).toISOString();
  }

  isEnabled(): boolean {
    return false;
  }

  setEnabled(_enabled: boolean): DesktopTelemetrySummary {
    return this.getSummary();
  }

  reset(): DesktopTelemetrySummary {
    return this.getSummary();
  }

  record(_rawInput: DesktopTelemetryRecordInput): DesktopTelemetryEvent | null {
    return null;
  }

  getSummary(): DesktopTelemetrySummary {
    return {
      schemaVersion: 1,
      enabled: false,
      channel: this.channel,
      platform: this.platform,
      arch: this.arch,
      shellVersion: this.shellVersion,
      totalEvents: 0,
      retainedEvents: 0,
      updatedAt: this.updatedAt,
      categories: {},
      recentEvents: [],
    };
  }

  async flush(): Promise<{ ok: boolean; reason?: string }> {
    return { ok: false, reason: 'disabled' };
  }
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

  // 4. Delete PostHog GeoIP Hog script and remove its packaging reference
  s.remove('tracking/posthog-geoip.hog', 'Delete PostHog GeoIP transformation script');
  if (s.exists('tracking/package.json')) {
    const current = s.read('tracking/package.json');
    if (current.includes('posthog-geoip.hog')) {
      const next = current
        .replace(/,\s*"posthog-geoip\.hog"/, '')
        .replace(/"posthog-geoip\.hog",\s*/, '');
      s.write('tracking/package.json', next, 'Remove deleted tracking/posthog-geoip.hog from package files');
    } else {
      s.actions.push({ file: 'tracking/package.json', status: 'unchanged', summary: 'Remove deleted tracking/posthog-geoip.hog from package files' });
    }
  }

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

  // 8. Disable unsolicited background gateway.account.prefetch() on server startup when present
  s.patchRegexOptional(
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
  s.hardenIfExists('studio/src/motion/studioTracking.ts', STUDIO_STUDIO_TRACKING_TS, 'Disable Studio usage reporting transport');

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

  // 10a. Disable cloud PostHog ingestion and browser Sentry observability at the source
  s.hardenIfExists('src/cloud-tracking.ts', CLOUD_TRACKING_TS, 'Replace cloud PostHog tracker with a permanently disabled handle');
  s.hardenIfExists('packages/observability/config.ts', OBSERVABILITY_CONFIG_TS, 'Disable browser Sentry DSN configuration and runtime injection');
  s.hardenIfExists('packages/observability/browser.ts', OBSERVABILITY_BROWSER_TS, 'Replace browser Sentry SDK integration with zero-network no-ops');
  s.hardenIfExists('packages/observability/vite.ts', OBSERVABILITY_VITE_TS, 'Remove Sentry sourcemap/debug-id build tooling');
  s.patchRegexOptional(
    'packages/observability/sanitize.ts',
    'observability-sanitize-tracking-context',
    src => !src.includes("'tracking_context'"),
    /\n  'tracking_context',/,
    '',
    'Remove obsolete tracking_context marker from observability sanitizer'
  );

  // 10b. Strip cross-site attribution parameters from Studio subscription links
  s.patchRegexOptional(
    'studio/src/motion/accountOffer.ts',
    'studio-account-offer-attribution',
    src => src.includes(MARKER) && !src.includes('od_entry_id'),
    /export function buildSubscriptionUrl\([\s\S]*?\n\}/,
    `// ${MARKER}: subscription link attribution removed.
export function buildSubscriptionUrl(
  consoleUrl?: string | null,
  _entrySource = 'openmotion_manage_subscription',
): string {
  const url = new URL((consoleUrl || DEFAULT_CONSOLE_URL).replace(/\\/+$/, '') + '/dashboard');
  url.search = new URLSearchParams({ billing: 'plan' }).toString();
  return url.href;
}`,
    'Strip od_origin/od_entry_* cross-site attribution params from studio/src/motion/accountOffer.ts'
  );

  // 10c. Disable desktop Sentry reporting and local edge-health telemetry
  s.hardenIfExists('desktop/src/sentry.ts', DESKTOP_SENTRY_TS, 'Replace Electron Sentry reporter, crash upload, and outbox with no-ops');
  s.hardenIfExists('desktop/src/telemetry.ts', DESKTOP_TELEMETRY_TS, 'Disable desktop edge-health telemetry collection and persistence');
  s.transformOptional(
    'desktop/scripts/build.mjs',
    'desktop-build-sentry-dsn',
    src => src.includes(MARKER) && !src.includes('env.SENTRY_DESKTOP_DSN || env.OPENMOTION_DESKTOP_SENTRY_DSN'),
    src => {
      let next = src;
      next = next.replace(
        /const rawSentryDsn = \(env\.SENTRY_DESKTOP_DSN \|\| env\.OPENMOTION_DESKTOP_SENTRY_DSN \|\| ''\)\.trim\(\);/,
        `const rawSentryDsn = ''; // ${MARKER}: build-time Sentry DSN injection disabled.`
      );
      next = next.replace(
        "} else if (/^(1|true)$/i.test(env.OPENMOTION_DESKTOP_REQUIRE_SENTRY_DSN?.trim() ?? '')) {",
        '} else if (false) { // Sentry DSN requirement disabled in privacy-hardened build.'
      );
      return next;
    },
    'Disable build-time Sentry DSN injection in desktop/scripts/build.mjs'
  );

  // 10d. Remove Sentry sourcemap upload steps and credentials from release workflows
  for (const workflow of ['.github/workflows/container-images.yml', '.github/workflows/desktop-release.yml']) {
    if (!s.exists(workflow)) continue;
    s.transformOptional(
      workflow,
      `workflow-sentry-${path.basename(workflow)}`,
      src => !src.includes('@sentry/cli') && !src.includes('SENTRY_AUTH_TOKEN'),
      src => {
        let next = src.replace(
          /\n[ \t]*- name: (?:Export and upload Studio sourcemaps to Sentry|Upload desktop sourcemaps to Sentry)\n[\s\S]*?(?=\n[ \t]*- name: )/g,
          '\n'
        );
        next = next.replace(/^[ \t]*(?:SENTRY_[A-Z0-9_]+|OPENMOTION_DESKTOP_REQUIRE_SENTRY_DSN):[^\n]*\n/gm, '');
        return next;
      },
      'Remove Sentry sourcemap upload steps and credentials from release workflows'
    );
  }

  // 10e. Remove Sentry packages from the dependency manifests and lockfile
  if (s.exists('package.json')) {
    const current = s.read('package.json');
    const pkg = JSON.parse(current);
    let changed = false;
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      if (!pkg[section] || typeof pkg[section] !== 'object') continue;
      for (const name of Object.keys(pkg[section])) {
        if (/^@sentry\//.test(name)) {
          delete pkg[section][name];
          changed = true;
        }
      }
    }
    if (changed) s.write('package.json', JSON.stringify(pkg, null, 2) + '\n', 'Remove Sentry telemetry packages from package.json');
    else s.actions.push({ file: 'package.json', status: 'unchanged', summary: 'Remove Sentry telemetry packages from package.json' });
  }
  if (s.exists('package-lock.json')) {
    const lock = JSON.parse(s.read('package-lock.json'));
    let changed = false;
    const root = lock.packages && lock.packages[''];
    if (root) {
      for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        if (!root[section] || typeof root[section] !== 'object') continue;
        for (const name of Object.keys(root[section])) {
          if (/^@sentry\//.test(name)) {
            delete root[section][name];
            changed = true;
          }
        }
      }
    }
    if (lock.packages && typeof lock.packages === 'object') {
      for (const key of Object.keys(lock.packages)) {
        if (key.startsWith('node_modules/@sentry/')) {
          delete lock.packages[key];
          changed = true;
        }
      }
    }
    if (changed) s.write('package-lock.json', JSON.stringify(lock, null, 2) + '\n', 'Remove Sentry telemetry packages from package-lock.json');
    else s.actions.push({ file: 'package-lock.json', status: 'unchanged', summary: 'Remove Sentry telemetry packages from package-lock.json' });
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

  // 16. Harden Docker/Kubernetes deployment defaults
  s.transformOptional(
    'deploy/.env.example',
    'deploy-env-example',
    src => !/SENTRY_|POSTHOG|OPENMOTION_TRACKING/.test(src) && /^OPENMOTION_TELEMETRY=0$/m.test(src) && /^DO_NOT_TRACK=1$/m.test(src),
    src => {
      let next = src.replace(/^# -+\n# Cloud Web Observability[\s\S]*?^OPENMOTION_TRACKING_INSTALLATION_ID=.*$/m, '');
      next = next.replace(/^[ \t]*(?:SENTRY_[A-Z0-9_]+|OPENMOTION_POSTHOG_[A-Z0-9_]+|OPENMOTION_TRACKING_[A-Z0-9_]+|OPENMOTION_TELEMETRY|DO_NOT_TRACK)=[^\n]*\n/gm, '');
      if (next.includes(MARKER)) return src;
      const block = `# -----------------------------------------------------------------------------
# ${MARKER}: deployment telemetry disabled.
# -----------------------------------------------------------------------------
OPENMOTION_TELEMETRY=0
DO_NOT_TRACK=1
HYPERFRAMES_NO_TELEMETRY=1
HYPERFRAMES_NO_UPDATE_CHECK=1
HYPERFRAMES_NO_AUTO_INSTALL=1`;
      return next.trimEnd() + '\n\n' + block + '\n';
    },
    'Remove Sentry/PostHog deployment settings and force telemetry off in deploy/.env.example'
  );
  s.transformOptional(
    'deploy/docker-compose.yml',
    'deploy-docker-compose',
    src => !/SENTRY_|POSTHOG|OPENMOTION_TRACKING/.test(src) && /OPENMOTION_TELEMETRY: "0"/.test(src) && /DO_NOT_TRACK: "1"/.test(src),
    src => {
      let next = src.replace(
        /^([ \t]*)SENTRY_WEB_DSN:[^\n]*\n(?:[ \t]*SENTRY_[^\n]*\n)*[ \t]*OPENMOTION_TRACKING_ENABLED:[^\n]*\n(?:[ \t]*OPENMOTION_POSTHOG_[^\n]*\n)*[ \t]*OPENMOTION_TRACKING_INSTALLATION_ID:[^\n]*\n(?:[ \t]*OPENMOTION_TELEMETRY:[^\n]*\n)?/m,
        (_match, indent) => `${indent}__PRIVACY_ENV_BLOCK__\n`
      );
      if (!next.includes('__PRIVACY_ENV_BLOCK__')) {
        next = next.replace(/^([ \t]*)ALLOW_DOH_FAKEIP_FALLBACK:[^\n]*\n/m, '$1__PRIVACY_ENV_BLOCK__\n');
      }
      next = next.replace(/^[ \t]*(?:SENTRY_[A-Z0-9_]+|OPENMOTION_POSTHOG_[A-Z0-9_]+|OPENMOTION_TRACKING_[A-Z0-9_]+|OPENMOTION_TELEMETRY|DO_NOT_TRACK):[^\n]*\n/gm, '');
      if (!next.includes('__PRIVACY_ENV_BLOCK__')) return src;
      return next.replace(
        '__PRIVACY_ENV_BLOCK__',
        `# ${MARKER}: compose telemetry disabled.
      OPENMOTION_TELEMETRY: "0"
      DO_NOT_TRACK: "1"
      HYPERFRAMES_NO_TELEMETRY: "1"
      HYPERFRAMES_NO_UPDATE_CHECK: "1"
      HYPERFRAMES_NO_AUTO_INSTALL: "1"`
      );
    },
    'Remove Sentry/PostHog Compose settings and force telemetry off in deploy/docker-compose.yml'
  );
  s.transformOptional(
    'deploy/k8s/configmap.yaml',
    'deploy-k8s-configmap',
    src => src.includes(`${MARKER}: cloud observability disabled`),
    src => src
      .replace(/^([ \t]*)SENTRY_WEB_DSN: .*$/m, '$1SENTRY_WEB_DSN: ""')
      .replace(/^([ \t]*)SENTRY_ENVIRONMENT: .*$/m, '$1SENTRY_ENVIRONMENT: ""')
      .replace(/^([ \t]*)SENTRY_RELEASE: .*$/m, '$1SENTRY_RELEASE: ""')
      .replace(/^([ \t]*)SENTRY_TRACES_SAMPLE_RATE: .*$/m, '$1SENTRY_TRACES_SAMPLE_RATE: "0"')
      .replace(/^([ \t]*)# Cloud web observability.*$/m, `$1# ${MARKER}: cloud observability disabled`),
    'Disable Sentry runtime settings in deploy/k8s/configmap.yaml'
  );

  // 17. Older upstream layout kept the subscription link builder under gateway/account.ts.
  // Current upstream moved it to studio/src/motion/accountOffer.ts (handled above). If the old
  // file returns, the fail-closed audit still rejects any od_* attribution it carries.
  s.patchRegexOptional(
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
