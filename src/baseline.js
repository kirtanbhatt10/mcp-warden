/**
 * Baselines let teams adopt mcp-warden in CI without fixing every existing
 * finding first: accepted findings are recorded once and suppressed after.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { writeFileAtomic } from './fsutil.js';

export function fingerprint(f, cwd = process.cwd()) {
  const rel = f.file && !f.file.startsWith('<') ? path.relative(cwd, f.file).split(path.sep).join('/') : f.file || '';
  // message text is deliberately excluded (it can contain line numbers); evidence identifies the value
  return crypto.createHash('sha256').update([f.ruleId, rel, f.server || '', f.pointer || '', f.evidence || ''].join('\u0000')).digest('hex').slice(0, 16);
}

export function writeBaseline(file, findings, cwd = process.cwd()) {
  const entries = findings
    .map((f) => ({ id: fingerprint(f, cwd), rule: f.ruleId, server: f.server || null, message: f.message }))
    .sort((a, b) => a.id.localeCompare(b.id));
  writeFileAtomic(file, `${JSON.stringify({ version: 1, generator: 'mcp-warden', findings: entries }, null, 2)}\n`);
  return entries.length;
}

export function applyBaseline(file, findings, cwd = process.cwd()) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    throw new Error(`cannot read baseline ${file}: ${e.code || e.message}`);
  }
  const known = new Set((data.findings || []).map((x) => x.id));
  const kept = findings.filter((f) => !known.has(fingerprint(f, cwd)));
  return { findings: kept, suppressed: findings.length - kept.length };
}

/** Load project settings from .mcp-warden.json (searched upwards from cwd). */
export function loadSettings(explicit, cwd = process.cwd()) {
  let file = explicit ? path.resolve(explicit) : null;
  if (!file) {
    let dir = cwd;
    for (;;) {
      const candidate = path.join(dir, '.mcp-warden.json');
      if (fs.existsSync(candidate)) { file = candidate; break; }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  if (!file) return { file: null, settings: {} };
  let settings;
  try {
    settings = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    throw new Error(`invalid settings file ${file}: ${e.message}`);
  }
  const base = path.dirname(file);
  if (settings.baseline) settings.baseline = path.resolve(base, settings.baseline);
  if (Array.isArray(settings.paths)) settings.paths = settings.paths.map((p) => path.resolve(base, p));
  return { file, settings };
}
