// OPENMOTION_PRIVACY_HARDENED: persistent browser distinct_id minting and storage permanently removed.
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
