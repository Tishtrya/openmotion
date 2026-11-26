#!/usr/bin/env node
/**
 * OpenMotion Privacy Audit Guard (Fail-Closed)
 *
 * Scans an OpenMotion checkout to verify:
 *   1. All privacy-hardening transforms are intact (structural checks).
 *   2. Zero forbidden telemetry endpoints, PostHog tokens, hardware fingerprint commands,
 *      cross-site attribution params, sendBeacon calls, or unsolicited startup fetches exist.
 *   3. Zero unknown/unapproved external domains exist in runtime code (domain drift detection).
 *   4. Zero known analytics/telemetry npm packages were introduced in package.json manifests.
 *
 * Exits 0 on clean pass, 1 on any violation.
 *
 * Usage:
 *   node privacy/audit-privacy.mjs [--root <dir>] [--allowlist <file>] [--json]
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const MARKER = 'OPENMOTION_PRIVACY_HARDENED';
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ALLOWLIST = path.join(SCRIPT_DIR, 'domain-allowlist.json');

function parseArgs(argv) {
  let root = process.cwd();
  let allowlistPath = DEFAULT_ALLOWLIST;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--root') {
      const next = argv[++i];
      if (!next) throw new Error('--root requires a directory path');
      root = path.resolve(next);
    } else if (arg === '--allowlist') {
      const next = argv[++i];
      if (!next) throw new Error('--allowlist requires a file path');
      allowlistPath = path.resolve(next);
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '-h' || arg === '--help') {
      console.log('Usage: node privacy/audit-privacy.mjs [--root <dir>] [--allowlist <file>] [--json]');
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { root, allowlistPath, json };
}

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  '.vite',
  'docs',
  'examples',
  'library',
  'skills',
  'template-library',
  'tests',
  'privacy',
]);

const CODE_EXTS = new Set([
  '.ts', '.tsx', '.js', '.mjs', '.cjs', '.json',
  '.sh', '.command', '.ps1', '.py', '.yml', '.yaml',
  '.html', '.toml', '.hog', '.css',
]);

function isRuntimeFile(rel) {
  const norm = rel.split(path.sep).join('/');
  const parts = norm.split('/');
  if (parts.some(p => SKIP_DIRS.has(p))) return false;
  if (norm.startsWith('studio/tests/') || norm.startsWith('studio/build/')) return false;
  if (norm.startsWith('mcp-ui/template-recommendations/build/')) return false;
  if (norm.startsWith('integrations/dsh/plugin/tests/')) return false;
  if (/\.test\.[cm]?[jt]sx?$/.test(norm) || /\.spec\.[cm]?[jt]sx?$/.test(norm) || /testHelpers/i.test(norm)) return false;
  if (norm.endsWith('package-lock.json') || norm.endsWith('runtime-lock.json')) return false;
  if (norm.endsWith('.md') || norm.endsWith('.txt') || norm === 'LICENSE' || norm.endsWith('.svg')) return false;
  const ext = path.extname(norm).toLowerCase();
  if (!CODE_EXTS.has(ext) && !norm.endsWith('.env.example') && !norm.endsWith('.env.development')) return false;
  return true;
}

function walkRuntimeFiles(root) {
  const out = [];
  function visit(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        visit(full);
      } else if (isRuntimeFile(rel)) {
        out.push(rel);
      }
    }
  }
  visit(root);
  return out.sort();
}

function stripSingleLineComment(line) {
  const trimmed = line.trim();
  if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
    return '';
  }
  return line;
}

const FORBIDDEN_RULES = [
  {
    id: 'posthog-endpoint',
    regex: /posthog\.(?:com|io)\b/i,
    description: 'PostHog telemetry endpoint found in runtime code/config',
    skipComments: true,
  },
  {
    id: 'posthog-token',
    regex: /\bph[cx]_[A-Za-z0-9_]{10,}\b/,
    description: 'Hardcoded PostHog API/project token found',
    skipComments: false,
  },
  {
    id: 'third-party-analytics',
    regex: /(?:sentry\.io|@sentry\/|mixpanel\.com|api\.amplitude\.com|api\.segment\.io|google-analytics\.com|googletagmanager\.com|\bgtag\s*\(|clarity\.ms|datadoghq\.com|plausible\.io|umami\.is|hotjar\.com|fullstory\.com|logrocket\.com|heapanalytics\.com|bugsnag\.com|rollbar\.com|telemetry\.heygen\.com)/i,
    description: 'Third-party telemetry/analytics SDK or endpoint found',
    skipComments: true,
  },
  {
    id: 'hardware-fingerprint',
    regex: /(?:IOPlatformUUID|IOPlatformExpertDevice|MachineGuid|\/etc\/machine-id|\/var\/lib\/dbus\/machine-id|SPHardwareDataType|\bwmic\b.*\bcsproduct\b)/,
    description: 'Hardware/OS machine fingerprint collection found',
    skipComments: true,
  },
  {
    id: 'browser-send-beacon',
    regex: /\bsendBeacon\s*\(/,
    description: 'navigator.sendBeacon call found in runtime code',
    skipComments: true,
  },
  {
    id: 'cross-site-attribution-params',
    regex: /\b(?:od_entry_id|od_entry_source|od_entry_at|tracking_context)\b/,
    description: 'Cross-site or cross-process tracking parameter found',
    skipComments: true,
  },
  {
    id: 'background-github-stars',
    regex: /api\.github\.com\/repos\/nexu-io\/openmotion/,
    description: 'Unsolicited background GitHub Stars API fetch found',
    skipComments: true,
    excludeFiles: [/^scripts\//, /^\.github\//, /^studio\/src\/motion\/githubRepositorySnapshot\.json$/],
  },
  {
    id: 'unsolicited-account-prefetch',
    regex: /gateway\.account\.prefetch\s*\(/,
    description: 'Unsolicited startup background account connector prefetch found',
    skipComments: true,
  },
  {
    id: 'external-interview-booking',
    regex: /calendar\.app\.google/i,
    description: 'External Google Calendar feedback interview prompt link found',
    skipComments: true,
  },
];

const FORBIDDEN_PACKAGES = [
  /^posthog-(?:js|node|react-native)$/,
  /^@sentry\//,
  /^mixpanel(?:-browser)?$/,
  /^@amplitude\//,
  /^@segment\//,
  /^analytics-node$/,
  /^@datadog\//,
  /^applicationinsights$/,
  /^plausible-tracker$/,
  /^@vercel\/(?:analytics|speed-insights)$/,
  /^react-ga4?$/,
  /^umami$/,
];

const REQUIRED_HARDENED_FILES = [
  'tracking/device.ts',
  'tracking/node.ts',
  'tracking/browser.ts',
  'tracking/task-ledger.ts',
  'tracking/host.ts',
  'shared/tracking.ts',
  'shared/install-attribution.ts',
  'studio/src/motion/tracking.ts',
  'studio/src/motion/reporting.ts',
  'studio/src/webmcp/tracking.ts',
  'studio/src/telemetry/distinctId.ts',
  'studio/src/telemetry/config.ts',
  'studio/src/telemetry/client.ts',
  'studio/src/telemetry/policy.ts',
  'studio/src/utils/studioTelemetry.ts',
  'studio/src/motion/campaignAttribution.ts',
  'studio/src/motion/githubRepository.ts',
  'studio/src/components/feedback/StudioFeedbackCard.tsx',
  'studio/src/motion/PrivacySettings.tsx',
];

function checkDomainAllowed(host, relFile, allowlistConfig) {
  if (allowlistConfig.ignoredHosts.includes(host)) return true;
  if (allowlistConfig.ignoredHostSuffixes.some(s => host.endsWith(s))) return true;
  for (const group of Object.values(allowlistConfig.allowlist)) {
    if (!group.domains.includes(host)) continue;
    if (!group.filePrefixes || group.filePrefixes.length === 0) return true;
    if (group.filePrefixes.some(prefix => relFile === prefix || relFile.startsWith(prefix))) return true;
  }
  return false;
}

export function runAudit({ root = process.cwd(), allowlistPath = DEFAULT_ALLOWLIST } = {}) {
  const violations = [];
  const allowlistConfig = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
  const staticExcluded = new Set(allowlistConfig.staticDataFilesExcludedFromDomainDrift ?? []);

  // 1. Structural checks
  const trackingConfigPath = path.join(root, 'shared/tracking-config.json');
  if (fs.existsSync(trackingConfigPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(trackingConfigPath, 'utf8'));
      const keys = Object.keys(cfg);
      if (keys.length > 0) {
        violations.push({
          category: 'structural',
          rule: 'tracking-config-not-empty',
          file: 'shared/tracking-config.json',
          line: 1,
          detail: `Expected empty {}, found keys: ${keys.join(', ')}`,
        });
      }
    } catch (err) {
      violations.push({
        category: 'structural',
        rule: 'tracking-config-invalid-json',
        file: 'shared/tracking-config.json',
        line: 1,
        detail: String(err),
      });
    }
  }

  for (const forbiddenFile of ['tracking/posthog-geoip.hog', '.github/workflows/device-identity-check.yml']) {
    if (fs.existsSync(path.join(root, forbiddenFile))) {
      violations.push({
        category: 'structural',
        rule: 'forbidden-file-present',
        file: forbiddenFile,
        line: 1,
        detail: 'Telemetry-only file should have been removed',
      });
    }
  }

  const hfPath = path.join(root, 'hyperframes.ts');
  if (fs.existsSync(hfPath)) {
    const hf = fs.readFileSync(hfPath, 'utf8');
    for (const envVar of ['HYPERFRAMES_NO_TELEMETRY', 'HYPERFRAMES_NO_UPDATE_CHECK', 'HYPERFRAMES_NO_AUTO_INSTALL']) {
      if (!hf.includes(envVar)) {
        violations.push({
          category: 'structural',
          rule: 'hyperframes-env-missing',
          file: 'hyperframes.ts',
          line: 1,
          detail: `Missing required privacy env var ${envVar} in runtimeEnv()`,
        });
      }
    }
  }

  for (const rel of REQUIRED_HARDENED_FILES) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full)) {
      violations.push({
        category: 'structural',
        rule: 'expected-hardened-file-missing',
        file: rel,
        line: 1,
        detail: 'Expected file to exist and carry privacy hardening marker',
      });
    } else {
      const content = fs.readFileSync(full, 'utf8');
      if (!content.includes(MARKER)) {
        violations.push({
          category: 'structural',
          rule: 'missing-hardening-marker',
          file: rel,
          line: 1,
          detail: `File does not contain ${MARKER} — run privacy/strip-telemetry.mjs`,
        });
      }
    }
  }

  // 2 & 3. Scan all runtime files for forbidden patterns and unapproved external domains
  const files = walkRuntimeFiles(root);
  const urlRegex = /https?:\/\/([a-zA-Z0-9.-]+)(:[0-9]+)?(\/[^\s"'`<>\)\]}]*)?/g;
  const unknownDomains = new Map();

  for (const rel of files) {
    const content = fs.readFileSync(path.join(root, rel), 'utf8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const codeLine = stripSingleLineComment(rawLine);

      for (const rule of FORBIDDEN_RULES) {
        if (rule.excludeFiles?.some(rx => rx.test(rel))) continue;
        const target = rule.skipComments ? codeLine : rawLine;
        if (!target) continue;
        if (rule.regex.test(target)) {
          violations.push({
            category: 'forbidden-pattern',
            rule: rule.id,
            file: rel,
            line: i + 1,
            detail: `${rule.description}: ${rawLine.trim().slice(0, 140)}`,
          });
        }
      }

      // Domain allowlist drift check (skip static link/catalog JSONs, .github/ CI workflows, and scripts/sync-* maintainer scrapers)
      if (!staticExcluded.has(rel) && !rel.startsWith('.github/') && !rel.startsWith('scripts/sync-')) {
        if (!codeLine) continue;
        for (const match of codeLine.matchAll(urlRegex)) {
          const host = match[1].toLowerCase();
          if (!checkDomainAllowed(host, rel, allowlistConfig)) {
            const key = `${host}@${rel}:${i + 1}`;
            if (!unknownDomains.has(key)) {
              unknownDomains.set(key, true);
              violations.push({
                category: 'domain-drift',
                rule: 'unapproved-external-domain',
                file: rel,
                line: i + 1,
                detail: `Unapproved external domain '${host}' (${match[0].slice(0, 120)}). Inspect for new telemetry or register in privacy/domain-allowlist.json if legitimate.`,
              });
            }
          }
        }
      }
    }
  }

  // 4. Package dependency audit
  const manifestCandidates = ['package.json', 'packages/npm/package.json', 'integrations/dsh/package.json', 'integrations/dsh/plugin/package.json', 'tracking/package.json'];
  for (const rel of manifestCandidates) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full)) continue;
    const pkg = JSON.parse(fs.readFileSync(full, 'utf8'));
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const deps = pkg[section];
      if (!deps || typeof deps !== 'object') continue;
      for (const name of Object.keys(deps)) {
        if (FORBIDDEN_PACKAGES.some(rx => rx.test(name))) {
          violations.push({
            category: 'dependency',
            rule: 'forbidden-telemetry-package',
            file: rel,
            line: 1,
            detail: `Forbidden telemetry/analytics package '${name}' found in ${section}`,
          });
        }
      }
    }
  }

  return {
    root,
    ok: violations.length === 0,
    filesScanned: files.length,
    violationCount: violations.length,
    violations,
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const report = runAudit(args);
    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else if (report.ok) {
      console.log(`PRIVACY AUDIT PASSED: scanned ${report.filesScanned} runtime files, 0 violations.`);
    } else {
      console.error(`PRIVACY AUDIT FAILED: ${report.violationCount} violation(s) across ${report.filesScanned} runtime files:\n`);
      for (const v of report.violations) {
        console.error(`  [${v.category}:${v.rule}] ${v.file}:${v.line}\n    ${v.detail}`);
      }
    }
    if (!report.ok) process.exit(1);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
