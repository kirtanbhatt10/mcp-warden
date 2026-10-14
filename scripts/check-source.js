#!/usr/bin/env node
// Repository hygiene checks run in CI (`npm run lint`):
//  1. every JS file parses (node --check)
//  2. no hidden control / bidi / zero-width characters in source ("Trojan Source")
//  3. docs/rules.md is in sync with the rule definitions
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP = new Set(['node_modules', '.git', 'coverage']);
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]|[\u{E0000}-\u{E007F}]/u;
let failed = 0;

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

const files = walk(root);
for (const f of files.filter((x) => x.endsWith('.js'))) {
  const r = spawnSync(process.execPath, ['--check', f], { encoding: 'utf8' });
  if (r.status !== 0) {
    failed++;
    console.error(`syntax error: ${path.relative(root, f)}\n${r.stderr}`);
  }
}
for (const f of files.filter((x) => /\.(js|mjs|json|md|ya?ml|toml|ts)$/.test(x))) {
  if (f.includes(`${path.sep}examples${path.sep}tools${path.sep}`)) continue; // intentionally malicious fixtures
  const text = fs.readFileSync(f, 'utf8');
  const m = HIDDEN.exec(text);
  if (m) {
    failed++;
    const line = text.slice(0, m.index).split('\n').length;
    console.error(`hidden character U+${m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} in ${path.relative(root, f)}:${line}`);
  }
}
const before = fs.readFileSync(path.join(root, 'docs', 'rules.md'), 'utf8');
spawnSync(process.execPath, [path.join(root, 'scripts', 'gen-rules-doc.js')], { stdio: 'ignore' });
const after = fs.readFileSync(path.join(root, 'docs', 'rules.md'), 'utf8');
if (before !== after) {
  failed++;
  fs.writeFileSync(path.join(root, 'docs', 'rules.md'), before);
  console.error('docs/rules.md is out of date: run `node scripts/gen-rules-doc.js`');
}
if (failed) {
  console.error(`\n${failed} problem(s) found`);
  process.exit(1);
}
console.log(`ok: ${files.length} files checked`);
