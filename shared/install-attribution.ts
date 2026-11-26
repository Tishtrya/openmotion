// OPENMOTION_PRIVACY_HARDENED: installation attribution permanently removed.
export async function recordInstallationStart(_directory: string, _host: string, _source?: string): Promise<void> {
  // No-op in privacy-hardened build.
}

export async function recordInstallation(_directory: string, _host: string, _source?: string): Promise<void> {
  // No-op in privacy-hardened build.
}
