// OPENMOTION_PRIVACY_HARDENED: application telemetry permanently disabled and locked off.
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
