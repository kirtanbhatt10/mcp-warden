/**
 * Rug-pull detection: pin a hash of every tool definition and report when a
 * server silently changes what it tells the model.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import { writeFileAtomic } from './fsutil.js';

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Hash the parts of a tool definition the model actually sees. */
export function hashTool(tool) {
  const { name, title, description, inputSchema, input_schema, parameters, outputSchema, annotations } = tool || {};
  const relevant = { name, title, description, inputSchema: inputSchema ?? input_schema ?? parameters, outputSchema, annotations };
  return crypto.createHash('sha256').update(canonical(relevant)).digest('hex');
}

/**
 * Read a lock file. Returns null when it does not exist yet. A lock file that
 * exists but is unreadable or corrupt is an error: silently replacing it would
 * disable rug-pull detection.
 */
export function readLock(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw new Error(`cannot read lock file ${file}: ${e.code || e.message}`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`lock file ${file} is not valid JSON; refusing to overwrite it (delete it to start over)`);
  }
  if (!data || typeof data !== 'object' || !data.servers || typeof data.servers !== 'object') {
    throw new Error(`lock file ${file} has an unexpected format; refusing to overwrite it`);
  }
  return data;
}

/**
 * Compare tools against a lock file.
 * @param {{server?: string, tool: object}[]} entries
 * @param {string} lockFile
 * @param {{update?: boolean, source?: string}} [opts]
 * @returns {{findings: object[], created: boolean, updated: boolean}}
 */
export function checkLock(entries, lockFile, { update = false, source = lockFile } = {}) {
  const lock = readLock(lockFile);
  const current = {};
  for (const { server, tool } of entries) {
    const key = server || 'default';
    current[key] ??= {};
    current[key][String(tool.name)] = hashTool(tool);
  }

  const write = () => {
    const out = { version: 1, generator: 'mcp-warden', updated: new Date().toISOString(), servers: {} };
    const merged = { ...(lock?.servers || {}) };
    for (const [k, tools] of Object.entries(current)) merged[k] = { tools };
    for (const k of Object.keys(merged).sort()) {
      const tools = merged[k].tools || {};
      out.servers[k] = { tools: Object.fromEntries(Object.keys(tools).sort().map((t) => [t, tools[t]])) };
    }
    writeFileAtomic(lockFile, `${JSON.stringify(out, null, 2)}\n`);
  };

  if (!lock) {
    write();
    return { findings: [], created: true, updated: false };
  }

  const findings = [];
  const mk = (ruleId, rule, severity, title, message, server, fix) => ({
    ruleId, rule, severity, title, message, server, fix, file: source, pointer: `/servers/${server}`, line: 1,
  });
  for (const [server, tools] of Object.entries(current)) {
    const pinned = lock.servers[server]?.tools;
    if (!pinned) {
      findings.push(mk('TP013', 'tool-added', 'low', 'New server or tool not present in the lock file', `Server "${server}" is not in the lock file (${Object.keys(tools).length} tools)`, server, 'Review the tools, then run with --update-lock to pin them.'));
      continue;
    }
    for (const [name, hash] of Object.entries(tools)) {
      if (!(name in pinned)) {
        findings.push(mk('TP013', 'tool-added', 'low', 'New server or tool not present in the lock file', `New tool "${name}" appeared`, `${server}/${name}`, 'Review the new tool, then run with --update-lock to pin it.'));
      } else if (pinned[name] !== hash) {
        const f = mk('TP011', 'tool-definition-changed', 'high', 'Tool definition changed since it was pinned (possible rug pull)', `Tool "${name}" changed its description/schema since it was pinned`, `${server}/${name}`, 'Diff the definition against the previous version. Servers that change tool descriptions after approval are a known rug-pull vector. Run with --update-lock once reviewed.');
        f.evidence = `sha256 ${pinned[name].slice(0, 12)}… → ${hash.slice(0, 12)}…`;
        findings.push(f);
      }
    }
    for (const name of Object.keys(pinned)) {
      if (!(name in tools)) {
        findings.push(mk('TP012', 'tool-removed', 'info', 'Pinned tool no longer exposed', `Tool "${name}" was removed`, `${server}/${name}`, 'Run with --update-lock to accept the change.'));
      }
    }
  }
  if (update) write();
  return { findings, created: false, updated: update };
}

export const LOCK_RULES = [
  { id: 'TP011', name: 'tool-definition-changed', severity: 'high', title: 'Tool definition changed since it was pinned (possible rug pull)', description: 'A server changed the description or schema of a tool after you pinned it with --lock. Malicious servers can behave well during review and change their tool descriptions later.', fix: 'Diff the definition, then run with --update-lock once reviewed.' },
  { id: 'TP012', name: 'tool-removed', severity: 'info', title: 'Pinned tool no longer exposed', fix: 'Run with --update-lock to accept the change.' },
  { id: 'TP013', name: 'tool-added', severity: 'low', title: 'New server or tool not present in the lock file', fix: 'Review the new tool, then run with --update-lock to pin it.' },
];
