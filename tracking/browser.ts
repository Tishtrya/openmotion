// OPENMOTION_PRIVACY_HARDENED: browser telemetry transport permanently disabled.
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
