// OPENMOTION_PRIVACY_HARDENED: Studio telemetry client permanently disabled.
type EventProperties = Record<string, string | number | boolean | undefined>;

export function shouldTrack(): boolean {
  return false;
}

export function trackEvent(_event: string, _properties: EventProperties = {}): void {
  // No-op in privacy-hardened build.
}
