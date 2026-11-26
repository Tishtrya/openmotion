export const hostAgents = ['codex', 'claude', 'deepseek', 'cursor', 'opencode', 'gemini', 'workbuddy', 'chatgpt', 'other', 'unknown'] as const;
export type HostContext = { host_agent: typeof hostAgents[number]; host_agent_source: 'mcp_client_info' | 'launch_environment' | 'unknown'; mcp_client_name?: string; mcp_client_version?: string };
export const unknownHost: HostContext = { host_agent: 'unknown', host_agent_source: 'unknown' };
const clientNames = /^[A-Za-z0-9_.-]{1,64}$/;
const versions = /^\d{1,6}(?:\.\d{1,6}){0,3}(?:[-+][A-Za-z0-9.-]{1,48})?$/;
const names: Record<string, HostContext['host_agent']> = {
  codex: 'codex', 'codex-mcp-client': 'codex', codex_cli_rs: 'codex',
  'dsh-mcp-client': 'deepseek', 'dsh-mcp-probe': 'deepseek', dsh: 'deepseek', 'deepseek-harness': 'deepseek',
  claude: 'claude', 'claude-code': 'claude', 'claude-ai': 'claude',
  cursor: 'cursor', 'cursor-vscode': 'cursor', opencode: 'opencode',
  'gemini-cli': 'gemini', 'google-gemini-cli': 'gemini', workbuddy: 'workbuddy', chatgpt: 'chatgpt',
};
export function identifyHost(clientInfo: unknown, env: Record<string, string | undefined> = {}): HostContext {
  if (clientInfo && typeof clientInfo === 'object' && 'name' in clientInfo && typeof clientInfo.name === 'string' && clientInfo.name.length) {
    const name = clientInfo.name.toLowerCase(), version = 'version' in clientInfo ? clientInfo.version : undefined;
    return { host_agent: Object.hasOwn(names, name) ? names[name] : 'other', host_agent_source: 'mcp_client_info',
      ...(clientNames.test(name) ? { mcp_client_name: name } : {}),
      ...(typeof version === 'string' && versions.test(version) ? { mcp_client_version: version } : {}) };
  }
  const explicit = env.OPENMOTION_HOST_AGENT;
  const agent = explicit && (hostAgents as readonly string[]).includes(explicit) ? explicit as HostContext['host_agent']
    : env.CODEX_THREAD_ID ? 'codex' : env.CLAUDECODE === '1' ? 'claude' : undefined;
  return agent ? { host_agent: agent, host_agent_source: 'launch_environment' } : { ...unknownHost };
}
export function validHostContext(raw: unknown): raw is HostContext {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
  const host = raw as HostContext;
  return Object.keys(raw).every(key => ['host_agent', 'host_agent_source', 'mcp_client_name', 'mcp_client_version'].includes(key))
    && (hostAgents as readonly unknown[]).includes(host.host_agent)
    && ['mcp_client_info', 'launch_environment', 'unknown'].includes(host.host_agent_source)
    && (host.mcp_client_name === undefined || typeof host.mcp_client_name === 'string' && clientNames.test(host.mcp_client_name))
    && (host.mcp_client_version === undefined || typeof host.mcp_client_version === 'string' && versions.test(host.mcp_client_version));
}

// OPENMOTION_PRIVACY_HARDENED: tracking_context URL injection removed.
export function previewTrackingContext(value: any, _origin: string, _token: string): any {
  return value;
}
