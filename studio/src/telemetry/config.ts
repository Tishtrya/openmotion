// OPENMOTION_PRIVACY_HARDENED: Studio telemetry config permanently opted out with zero storage writes.
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
