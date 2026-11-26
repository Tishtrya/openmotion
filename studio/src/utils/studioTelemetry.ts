// OPENMOTION_PRIVACY_HARDENED: Studio legacy telemetry wrapper permanently disabled.
interface EventProperties {
  [key: string]: string | number | boolean | null | undefined;
}

export function trackStudioEvent(_event: string, _properties: EventProperties = {}): void {
  // No-op in privacy-hardened build.
}

export function flushViaBeacon(): void {
  // No-op in privacy-hardened build.
}
