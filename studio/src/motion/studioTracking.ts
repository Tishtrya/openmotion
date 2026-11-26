// OPENMOTION_PRIVACY_HARDENED: Studio usage reporting permanently disabled.
export function trackStudioUsage(_event: string, _properties: Record<string, unknown> = {}): void {
  // No-op in privacy-hardened build.
}

export async function flushStudioUsage(): Promise<void> {
  // No-op in privacy-hardened build.
}
