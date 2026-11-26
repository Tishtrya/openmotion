// OPENMOTION_PRIVACY_HARDENED: WebMCP telemetry permanently disabled.
import type { ModelContextTool } from './types';

export function withWebMcpTracking(tool: ModelContextTool): ModelContextTool {
  return tool;
}

export function trackWebMcpRegistration(_name: string, _result: 'success' | 'failure' | 'cancelled', _started: number): void {
  // No-op in privacy-hardened build.
}
