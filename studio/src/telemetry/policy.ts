// OPENMOTION_PRIVACY_HARDENED: Studio telemetry policy permanently locked off.
export function browserTelemetryAllowed(): boolean {
  return false;
}

declare global {
  interface Window {
    __HF_CLI_TELEMETRY_DISABLED?: boolean;
  }
}
