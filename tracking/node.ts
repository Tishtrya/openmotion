// OPENMOTION_PRIVACY_HARDENED: PostHog sender and persistent installation identity permanently removed.
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
