#!/usr/bin/env node
import fs from 'node:fs';
import { audit, auditTools, filterBySeverity, VERSION, SEVERITIES, severityRank, ALL_RULES, ALL_TOOL_RULES } from '../src/index.js';
import { knownLocations } from '../src/discover.js';
import { format, displayPath } from '../src/report.js';

const HELP = `
mcp-warden v${VERSION} — security auditor for MCP server configs

Usage
  mcp-warden [scan] [paths...]     Audit MCP configs (auto-discovers when no path is given)
  mcp-warden tools <file|->        Scan a tools/list JSON dump for tool poisoning
  mcp-warden rules                 List all rules
  mcp-warden locations             Show every config path that is checked

Options
  -f, --format <fmt>       text (default) | json | sarif | markdown
  -o, --output <file>      Write the report to a file instead of stdout
  -s, --min-severity <s>   Hide findings below: info | low (default) | medium | high | critical
      --fail-on <s>        Exit 1 if a finding is at or above this severity (default: high, "none" to disable)
  -i, --ignore <ids>       Comma-separated rule IDs or names to skip (e.g. MW002,typosquat)
      --no-discover        Only scan the paths given (skip auto-discovery)
      --discover           Also auto-discover when paths are given
  -v, --verbose            Show remediation advice for each finding
      --no-color           Disable colours (NO_COLOR is honoured too)
  -h, --help               Show help
      --version            Print version

Examples
  npx github:kirtanbhatt10/mcp-warden
  npx github:kirtanbhatt10/mcp-warden scan .cursor/mcp.json --verbose
  npx github:kirtanbhatt10/mcp-warden scan . --format sarif -o mcp-warden.sarif
  npx github:kirtanbhatt10/mcp-warden tools tools.json
`;

function parseArgs(argv) {
  const opts = { _: [], format: 'text', minSeverity: 'low', failOn: 'high', ignore: [], discover: undefined, verbose: false, color: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const [flag, inline] = a.startsWith('--') && a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
    const val = () => {
      if (inline !== undefined) return inline;
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`${flag} needs a value`);
      return v;
    };
    switch (flag) {
      case '-f': case '--format': opts.format = val(); break;
      case '-o': case '--output': opts.output = val(); break;
      case '-s': case '--min-severity': opts.minSeverity = val(); break;
      case '--fail-on': opts.failOn = val(); break;
      case '-i': case '--ignore': opts.ignore.push(...val().split(',').map((x) => x.trim()).filter(Boolean)); break;
      case '--no-discover': opts.discover = false; break;
      case '--discover': opts.discover = true; break;
      case '-v': case '--verbose': opts.verbose = true; break;
      case '--no-color': opts.color = false; break;
      case '--color': opts.color = true; break;
      case '-h': case '--help': opts.help = true; break;
      case '--version': case '-V': opts.version = true; break;
      default:
        if (a.startsWith('-') && a !== '-') throw new UsageError(`unknown option ${a}`);
        opts._.push(a);
    }
  }
  if (!['text', 'json', 'sarif', 'markdown', 'md'].includes(opts.format)) throw new UsageError(`unknown format "${opts.format}"`);
  if (!SEVERITIES.includes(opts.minSeverity)) throw new UsageError(`unknown severity "${opts.minSeverity}"`);
  if (opts.failOn !== 'none' && !SEVERITIES.includes(opts.failOn)) throw new UsageError(`unknown severity "${opts.failOn}"`);
  return opts;
}

class UsageError extends Error {}

function emit(text, opts) {
  if (opts.output) {
    fs.writeFileSync(opts.output, text.endsWith('\n') ? text : `${text}\n`);
    process.stderr.write(`mcp-warden: report written to ${opts.output}\n`);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  }
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`mcp-warden: ${e.message}\nRun "mcp-warden --help" for usage.\n`);
      return 2;
    }
    throw e;
  }
  if (opts.version) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (opts.help) { process.stdout.write(HELP); return 0; }

  const commands = ['scan', 'tools', 'rules', 'locations', 'help'];
  const cmd = commands.includes(opts._[0]) ? opts._.shift() : 'scan';

  if (cmd === 'help') { process.stdout.write(HELP); return 0; }

  if (cmd === 'rules') {
    const all = [...ALL_RULES, ...ALL_TOOL_RULES];
    if (opts.format === 'json') {
      emit(JSON.stringify(all.map(({ id, name, severity, title, description, fix }) => ({ id, name, severity, title, description, fix })), null, 2), opts);
    } else {
      emit(all.map((r) => `${r.id}  ${r.severity.padEnd(8)}  ${r.name.padEnd(28)}  ${r.title}`).join('\n'), opts);
    }
    return 0;
  }

  if (cmd === 'locations') {
    emit(knownLocations().map((l) => `${fs.existsSync(l.file) ? '✔' : ' '} ${l.client.padEnd(28)} ${displayPath(l.file)}`).join('\n'), opts);
    return 0;
  }

  let report;
  try {
    if (cmd === 'tools') {
      if (!opts._[0]) throw new UsageError('tools needs a file (or - for stdin)');
      report = auditTools(opts._[0], { ignore: opts.ignore });
    } else {
      report = audit({ paths: opts._, discover: opts.discover, ignore: opts.ignore });
    }
  } catch (e) {
    process.stderr.write(`mcp-warden: ${e.message}\n`);
    return 2;
  }

  const filtered = filterBySeverity(report, opts.minSeverity);
  const colorOn = opts.output ? false : opts.color;
  emit(format(filtered, opts.format, { color: colorOn, verbose: opts.verbose }), opts);

  if (opts.failOn === 'none') return 0;
  const threshold = severityRank(opts.failOn);
  return report.findings.some((f) => severityRank(f.severity) >= threshold) ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
