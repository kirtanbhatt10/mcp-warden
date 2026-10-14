import fs from 'node:fs';
import { loadConfigFile, locateLine } from './config.js';
import { discover, expandPaths, guessClient } from './discover.js';
import { SERVER_RULES, FILE_RULES, ALL_RULES, SEVERITIES, severityRank } from './rules.js';
import { scanTools, extractTools, ALL_TOOL_RULES as BASE_TOOL_RULES } from './tools.js';
import { checkLock, LOCK_RULES } from './lock.js';

const ALL_TOOL_RULES = [...BASE_TOOL_RULES, ...LOCK_RULES];
import { parseJsonc } from './parsers/jsonc.js';

export { SEVERITIES, severityRank, ALL_RULES, ALL_TOOL_RULES, scanTools, discover, expandPaths, loadConfigFile };
export { extractServers, normalizeServer } from './config.js';
export { detectSecret } from './secrets.js';
export { inspectStdio, inspectHttp } from './inspect.js';
export { checkLock, hashTool } from './lock.js';
export { writeBaseline, applyBaseline, fingerprint, loadSettings } from './baseline.js';
export { analyzeLaunch } from './packages.js';

export const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

/**
 * Audit one parsed set of servers (no file IO). Handy for programmatic use.
 * @param {import('./config.js').McpServer[]} servers
 * @param {{ignore?: string[]}} [opts]
 */
export function auditServers(servers, { ignore = [] } = {}) {
  const findings = [];
  for (const server of servers) {
    for (const rule of SERVER_RULES) {
      if (ignore.includes(rule.id) || ignore.includes(rule.name)) continue;
      let results = [];
      try {
        results = rule.check(server) || [];
      } catch (e) {
        results = [{ severity: 'info', message: `rule crashed: ${e.message}`, pointer: server.pointer }];
      }
      for (const r of results) {
        findings.push({
          ruleId: rule.id,
          rule: rule.name,
          severity: r.severity || rule.severity,
          title: rule.title,
          message: r.message,
          evidence: r.evidence,
          fix: rule.fix,
          server: server.name,
          file: server.file,
          pointer: r.pointer ?? server.pointer,
        });
      }
    }
  }
  return findings;
}

/**
 * Audit MCP config files.
 * @param {{paths?: string[], discover?: boolean, ignore?: string[], home?: string, cwd?: string}} opts
 */
export function audit(opts = {}) {
  const { paths = [], ignore = [] } = opts;
  const targets = [];
  if (paths.length) targets.push(...expandPaths(paths));
  if (opts.discover ?? paths.length === 0) {
    for (const t of discover({ home: opts.home, cwd: opts.cwd })) {
      if (!targets.some((x) => x.file === t.file)) targets.push(t);
    }
  }

  const files = [];
  const findings = [];
  let serverCount = 0;

  for (const t of targets) {
    if (t.missing) {
      files.push({ file: t.file, client: t.client, servers: 0, error: 'file not found' });
      continue;
    }
    const { servers, text, error } = loadConfigFile(t.file);
    let stat = null;
    try { stat = fs.statSync(t.file); } catch { /* ignore */ }
    const fileFindings = auditServers(servers, { ignore });
    for (const rule of FILE_RULES) {
      if (ignore.includes(rule.id) || ignore.includes(rule.name)) continue;
      for (const r of rule.check({ stat, servers, findings: fileFindings, file: t.file }) || []) {
        fileFindings.push({
          ruleId: rule.id,
          rule: rule.name,
          severity: r.severity || rule.severity,
          title: rule.title,
          message: r.message,
          evidence: r.evidence,
          fix: rule.fix,
          server: undefined,
          file: t.file,
          pointer: r.pointer || '',
        });
      }
    }
    for (const f of fileFindings) f.line = locateLine(text, f.pointer);
    findings.push(...fileFindings);
    serverCount += servers.length;
    files.push({ file: t.file, client: t.client || guessClient(t.file), servers: servers.length, error });
  }

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
  return { tool: 'mcp-warden', version: VERSION, kind: 'config', files, serverCount, findings, summary: summarize(findings) };
}

/** Audit a tools/list dump (file path or "-" for stdin). */
export function auditTools(file, opts = {}) {
  const text = file === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(file, 'utf8');
  return auditToolData(parseJsonc(text), { ...opts, source: file === '-' ? '<stdin>' : file });
}

/**
 * Audit already-parsed tool definitions.
 * @param {any} data  tools/list result, {tools}, array, or {server: tools}
 * @param {{ignore?: string[], source?: string, lock?: string, updateLock?: boolean}} [opts]
 */
export function auditToolData(data, { ignore = [], source = '<inline>', lock, updateLock = false } = {}) {
  const { findings, toolCount } = scanTools(data, source);
  const meta = {};
  if (lock) {
    const res = checkLock(extractTools(data), lock, { update: updateLock, source });
    findings.push(...res.findings);
    meta.lock = { file: lock, created: res.created, updated: res.updated };
  }
  const kept = findings.filter((f) => !ignore.includes(f.ruleId) && !ignore.includes(f.rule));
  kept.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  return { tool: 'mcp-warden', version: VERSION, kind: 'tools', files: [{ file: source, client: 'tools/list', servers: 0, tools: toolCount }], toolCount, findings: kept, summary: summarize(kept), ...meta };
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  const penalty = counts.critical * 30 + counts.high * 12 + counts.medium * 4 + counts.low * 1;
  const score = Math.max(0, 100 - penalty);
  let grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  if (counts.critical && grade < 'D') grade = 'D';
  if (counts.critical >= 2) grade = 'F';
  return { ...counts, total: findings.length, score, grade };
}

export function filterBySeverity(report, min) {
  const r = severityRank(min);
  const findings = report.findings.filter((f) => severityRank(f.severity) >= r);
  return { ...report, findings, summary: summarize(findings) };
}
