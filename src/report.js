import path from 'node:path';
import os from 'node:os';
import { ALL_RULES } from './rules.js';
import { ALL_TOOL_RULES } from './tools.js';
import { LOCK_RULES } from './lock.js';

const useColor = (stream = process.stdout) =>
  !process.env.NO_COLOR && process.env.TERM !== 'dumb' && (process.env.FORCE_COLOR || stream.isTTY);

function palette(on) {
  const w = (a, b) => (s) => (on ? `\x1b[${a}m${s}\x1b[${b}m` : String(s));
  return {
    bold: w(1, 22), dim: w(2, 22), red: w(31, 39), green: w(32, 39), yellow: w(33, 39),
    blue: w(34, 39), magenta: w(35, 39), cyan: w(36, 39), gray: w(90, 39),
    bgRed: w('41;97', '49;39'), bgYellow: w('43;30', '49;39'), bgGreen: w('42;30', '49;39'),
  };
}

const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

export function displayPath(file, cwd = process.cwd()) {
  if (!file || file.startsWith('<')) return file;
  const rel = path.relative(cwd, file);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel;
  const home = os.homedir();
  return file.startsWith(home) ? `~${file.slice(home.length)}` : file;
}

export function formatText(report, { color = useColor(), verbose = false } = {}) {
  const c = palette(color);
  const sevColor = { critical: c.magenta, high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  const lines = [];
  lines.push('');
  lines.push(`${c.bold('mcp-warden')} ${c.dim(`v${report.version}`)}  ${c.dim('·')}  ${report.kind === 'tools' ? 'MCP tool-poisoning scan' : 'MCP configuration security audit'}`);
  lines.push('');

  if (report.kind === 'config') {
    if (!report.files.length) {
      lines.push(c.yellow('No MCP config files found.'));
      lines.push(c.dim('Pass a path explicitly: mcp-warden scan ./path/to/mcp.json'));
      lines.push('');
      return lines.join('\n');
    }
    lines.push(c.bold('Scanned'));
    for (const f of report.files) {
      const meta = f.error ? c.red(f.error) : c.dim(`${f.servers} server${f.servers === 1 ? '' : 's'}`);
      lines.push(`  ${c.cyan('•')} ${f.client.padEnd(22)} ${displayPath(f.file)}  ${meta}`);
    }
    lines.push('');
  } else {
    const src = report.inspected ? `${report.inspected} live server${report.inspected === 1 ? '' : 's'}${report.failed ? c.red(` (${report.failed} failed)`) : ''}` : displayPath(report.files[0].file);
    lines.push(`${c.bold('Scanned')} ${report.toolCount} tool definition${report.toolCount === 1 ? '' : 's'} from ${src}`);
    if (report.lock) lines.push(c.dim(`Lock file: ${displayPath(report.lock.file)}${report.lock.created ? ' (created)' : report.lock.updated ? ' (updated)' : ''}`));
    lines.push('');
  }

  if (!report.findings.length) {
    lines.push(`${c.green('✔')} ${c.bold('No issues found.')} ${c.dim('Stay safe out there.')}`);
  } else {
    // group by file
    const byFile = new Map();
    for (const f of report.findings) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    for (const [file, list] of byFile) {
      lines.push(c.bold(c.cyan(displayPath(file))));
      for (const f of list) {
        const sev = sevColor[f.severity](SEV_LABEL[f.severity].padEnd(8));
        const where = f.line && f.line > 1 ? c.dim(`:${f.line}`) : '';
        lines.push(`  ${sev} ${c.bold(f.message)} ${c.dim(`[${f.ruleId} ${f.rule}]`)}`);
        const meta = [];
        if (f.server) meta.push(`${report.kind === 'tools' ? 'tool' : 'server'} ${c.bold(f.server)}${where}`);
        if (f.evidence) meta.push(`${c.dim('evidence')} ${f.evidence}`);
        if (meta.length) lines.push(`           ${meta.join(c.dim('  ·  '))}`);
        if (verbose && f.fix) lines.push(`           ${c.green('fix:')} ${f.fix}`);
      }
      lines.push('');
    }
  }

  const s = report.summary;
  const gradeColor = { A: c.bgGreen, B: c.bgGreen, C: c.bgYellow, D: c.bgRed, F: c.bgRed }[s.grade];
  const counts = ['critical', 'high', 'medium', 'low']
    .map((k) => (s[k] ? sevColor[k](`${s[k]} ${k}`) : c.dim(`0 ${k}`)))
    .join(c.dim(' · '));
  lines.push(`${gradeColor(` ${s.grade} `)} ${c.bold(`Security score ${s.score}/100`)}   ${counts}${s.info ? c.dim(` · ${s.info} info`) : ''}`);
  if (report.findings.length && !verbose) lines.push(c.dim('Run with --verbose for remediation advice, or --format sarif for GitHub code scanning.'));
  lines.push('');
  return lines.join('\n');
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

export function formatMarkdown(report) {
  const s = report.summary;
  const emoji = { critical: '🟣', high: '🔴', medium: '🟠', low: '🔵', info: '⚪' };
  const out = [];
  out.push(`## 🛡️ mcp-warden report — grade **${s.grade}** (${s.score}/100)`);
  out.push('');
  out.push(`| Critical | High | Medium | Low | Info |\n|---:|---:|---:|---:|---:|\n| ${s.critical} | ${s.high} | ${s.medium} | ${s.low} | ${s.info} |`);
  out.push('');
  if (!report.findings.length) {
    out.push('✅ No issues found.');
    return out.join('\n');
  }
  out.push('| Severity | Rule | Server | Finding | Location |');
  out.push('|---|---|---|---|---|');
  const esc = (x) => String(x ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  for (const f of report.findings) {
    out.push(`| ${emoji[f.severity]} ${f.severity} | \`${f.ruleId}\` ${f.rule} | ${esc(f.server || '—')} | ${esc(f.message)}${f.evidence ? `<br><sub>\`${esc(f.evidence)}\`</sub>` : ''} | \`${esc(displayPath(f.file))}:${f.line || 1}\` |`);
  }
  out.push('');
  out.push('<details><summary>How to fix</summary>\n');
  const seen = new Set();
  for (const f of report.findings) {
    if (seen.has(f.ruleId) || !f.fix) continue;
    seen.add(f.ruleId);
    out.push(`- **${f.ruleId} ${f.rule}** — ${f.fix}`);
  }
  out.push('\n</details>');
  return out.join('\n');
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

export function formatSarif(report, { cwd = process.cwd() } = {}) {
  const rules = [...ALL_RULES, ...ALL_TOOL_RULES, ...LOCK_RULES];
  const used = [...new Set(report.findings.map((f) => f.ruleId))];
  const ruleIndex = new Map(used.map((id, i) => [id, i]));
  const toUri = (file) => {
    if (!file || file.startsWith('<')) return 'stdin';
    const rel = path.relative(cwd, file);
    return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : `file://${file.split(path.sep).join('/')}`;
  };
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'mcp-warden',
              version: report.version,
              informationUri: 'https://github.com/kirtanbhatt10/mcp-warden',
              rules: used.map((id) => {
                const r = rules.find((x) => x.id === id) || { id, name: id, title: id, severity: 'medium' };
                return {
                  id,
                  name: r.name,
                  shortDescription: { text: r.title },
                  fullDescription: { text: r.description || r.title },
                  help: { text: r.fix || r.title, markdown: `**${r.title}**\n\n${r.description || ''}\n\n**Fix:** ${r.fix || ''}` },
                  helpUri: `https://github.com/kirtanbhatt10/mcp-warden/blob/main/docs/rules.md#${id.toLowerCase()}`,
                  defaultConfiguration: { level: SARIF_LEVEL[r.severity] || 'warning' },
                  properties: { tags: ['security', 'mcp'], 'security-severity': SECURITY_SEVERITY[r.severity] || '5.0' },
                };
              }),
            },
          },
          results: report.findings.map((f) => ({
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId),
            level: SARIF_LEVEL[f.severity],
            message: { text: `${f.message}${f.server ? ` (server: ${f.server})` : ''}${f.evidence ? ` — ${f.evidence}` : ''}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: toUri(f.file) },
                  region: { startLine: Math.max(1, f.line || 1) },
                },
              },
            ],
            partialFingerprints: { 'mcpWarden/v1': `${f.ruleId}:${f.server || ''}:${f.pointer}` },
            properties: { severity: f.severity, 'security-severity': SECURITY_SEVERITY[f.severity] },
          })),
        },
      ],
    },
    null,
    2,
  );
}

export function format(report, fmt, opts) {
  switch (fmt) {
    case 'json': return formatJson(report);
    case 'sarif': return formatSarif(report, opts);
    case 'markdown':
    case 'md': return formatMarkdown(report);
    default: return formatText(report, opts);
  }
}
