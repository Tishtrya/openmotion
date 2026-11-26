// OPENMOTION_PRIVACY_HARDENED: Studio browser tracking permanently disabled (no /motion-api/tracking requests).
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
