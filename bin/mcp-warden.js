#!/usr/bin/env node
import fs from 'node:fs';
import {
  audit, auditTools, auditToolData, filterBySeverity, summarize, VERSION, SEVERITIES, severityRank,
  ALL_RULES, ALL_TOOL_RULES, inspectStdio, inspectHttp, writeBaseline, applyBaseline, loadSettings,
  expandPaths, discover, loadConfigFile,
} from '../src/index.js';
import { safeMultiline } from '../src/sanitize.js';
import { writeFileAtomic } from '../src/fsutil.js';
import { knownLocations } from '../src/discover.js';
import { format, displayPath } from '../src/report.js';

const HELP = `
mcp-warden v${VERSION} — security auditor for MCP servers and configs

Usage
  mcp-warden [scan] [paths...]          Audit MCP configs (auto-discovers when no path is given)
  mcp-warden tools <file|->             Scan a tools/list JSON dump for tool poisoning
  mcp-warden inspect -- <cmd> [args]    Launch a stdio server, fetch its tools and scan them
  mcp-warden inspect --url <url>        Fetch tools from a remote (Streamable HTTP) server
  mcp-warden inspect --server <name>    Inspect a server from your configs (--all for every one)
  mcp-warden rules                      List all rules
  mcp-warden locations                  Show every config path that is checked

Output
  -f, --format <fmt>       text (default) | json | sarif | markdown
  -o, --output <file>      Write the report to a file instead of stdout
  -s, --min-severity <s>   Hide findings below: info | low (default) | medium | high | critical
      --fail-on <s>        Exit 1 at or above this severity (default: high, "none" to disable)
  -i, --ignore <ids>       Comma-separated rule IDs or names to skip (e.g. MW002,typosquat)
  -v, --verbose            Show remediation advice for each finding
      --no-color           Disable colours (NO_COLOR is honoured too)

Config scanning
      --no-discover        Only scan the paths given (skip auto-discovery)
      --discover           Also auto-discover when paths are given
      --baseline <file>    Suppress findings recorded in a baseline file
      --write-baseline <f> Record all current findings as accepted, then exit 0
      --settings <file>    Project settings (default: nearest .mcp-warden.json)

Tool scanning / inspect
      --lock <file>        Pin tool definitions; later runs flag changes (rug pulls)
      --update-lock        Accept the current tool definitions into the lock file
      --save <file>        Save the fetched tools/list JSON (inspect)
  -H, --header <h>         Extra HTTP header for --url, e.g. -H "Authorization: Bearer $TOKEN"
      --timeout <ms>       Inspect timeout per server (default 30000)
  -e, --env KEY=VALUE      Environment variable for launched servers (repeatable)
      --inherit-env        Pass your whole environment to launched servers (default: minimal env)
  -y, --yes                Confirm launching stdio servers taken from your configs

      --debug              Print stack traces for unexpected errors
  -h, --help               Show help
      --version            Print version

Examples
  npx github:kirtanbhatt10/mcp-warden
  npx github:kirtanbhatt10/mcp-warden scan . --format sarif -o mcp-warden.sarif
  npx github:kirtanbhatt10/mcp-warden inspect --lock mcp-tools.lock.json -- npx -y @playwright/mcp@0.0.41
  npx github:kirtanbhatt10/mcp-warden inspect --all --yes --lock mcp-tools.lock.json
`;

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = { _: [], cmdline: null, env: {}, format: undefined, minSeverity: undefined, failOn: undefined, ignore: [], headers: {}, discover: undefined, verbose: false, color: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { opts.cmdline = argv.slice(i + 1); break; }
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
      case '--baseline': opts.baseline = val(); break;
      case '--write-baseline': opts.writeBaseline = val(); break;
      case '--settings': opts.settings = val(); break;
      case '--lock': opts.lock = val(); break;
      case '--update-lock': opts.updateLock = true; break;
      case '--save': opts.save = val(); break;
      case '--url': opts.url = val(); break;
      case '--server': opts.server = val(); break;
      case '--all': opts.all = true; break;
      case '-H': case '--header': {
        const h = val();
        const idx = h.indexOf(':');
        if (idx < 1) throw new UsageError(`invalid header "${h}" (expected "Name: value")`);
        opts.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
        break;
      }
      case '--timeout': opts.timeout = Number(val()); break;
      case '-e': case '--env': {
        const kv = val();
        const idx = kv.indexOf('=');
        if (idx < 1) throw new UsageError(`invalid --env "${kv}" (expected KEY=VALUE)`);
        opts.env[kv.slice(0, idx)] = kv.slice(idx + 1);
        break;
      }
      case '--inherit-env': opts.inheritEnv = true; break;
      case '-y': case '--yes': opts.yes = true; break;
      case '-v': case '--verbose': opts.verbose = true; break;
      case '--no-color': opts.color = false; break;
      case '--color': opts.color = true; break;
      case '-h': case '--help': opts.help = true; break;
      case '--version': case '-V': opts.version = true; break;
      case '--debug': opts.debug = true; break;
      default:
        if (a.startsWith('-') && a !== '-') throw new UsageError(`unknown option ${a}`);
        opts._.push(a);
    }
  }
  return opts;
}

function applySettings(opts) {
  const { settings } = loadSettings(opts.settings);
  opts.format ??= settings.format ?? 'text';
  opts.minSeverity ??= settings.minSeverity ?? 'low';
  opts.failOn ??= settings.failOn ?? 'high';
  opts.baseline ??= settings.baseline;
  if (Array.isArray(settings.ignore)) opts.ignore.push(...settings.ignore);
  if (Array.isArray(settings.paths)) opts.settingsPaths = settings.paths;
  if (!['text', 'json', 'sarif', 'markdown', 'md'].includes(opts.format)) throw new UsageError(`unknown format "${opts.format}"`);
  if (!SEVERITIES.includes(opts.minSeverity)) throw new UsageError(`unknown severity "${opts.minSeverity}"`);
  if (opts.failOn !== 'none' && !SEVERITIES.includes(opts.failOn)) throw new UsageError(`unknown severity "${opts.failOn}"`);
  if (opts.timeout !== undefined && !(opts.timeout > 0 && opts.timeout <= 3600000)) throw new UsageError('--timeout must be between 1 and 3600000 milliseconds');
  if (opts.updateLock && !opts.lock) throw new UsageError('--update-lock requires --lock <file>');
}

function emit(text, opts) {
  const out = text.endsWith('\n') ? text : `${text}\n`;
  if (opts.output) {
    writeFileAtomic(opts.output, out);
    process.stderr.write(`mcp-warden: report written to ${opts.output}\n`);
  } else {
    process.stdout.write(out);
  }
}

const note = (msg) => process.stderr.write(`mcp-warden: ${safeMultiline(msg)}\n`);

/** Resolve which servers `inspect` should talk to. */
function inspectTargets(opts) {
  if (opts.cmdline) {
    if (!opts.cmdline.length) throw new UsageError('nothing after "--" (expected a server command)');
    return [{ name: opts._[0] || opts.cmdline.slice(0, 3).join(' '), command: opts.cmdline[0], args: opts.cmdline.slice(1), env: { ...opts.env }, explicit: true }];
  }
  if (opts.url) return [{ name: new URL(opts.url).host, url: opts.url, headers: opts.headers }];
  if (opts.server || opts.all) {
    const files = opts._.length ? expandPaths(opts._) : discover();
    const servers = files.filter((f) => !f.missing).flatMap((f) => loadConfigFile(f.file).servers);
    const chosen = opts.all ? servers : servers.filter((s) => s.name === opts.server || s.key === opts.server);
    if (!chosen.length) throw new UsageError(opts.all ? 'no MCP servers found in your configs' : `server "${opts.server}" not found (try: mcp-warden scan to list servers)`);
    const stdio = chosen.filter((s) => s.command);
    if (stdio.length && !opts.yes) {
      throw new UsageError(`inspect will launch ${stdio.length} local server process${stdio.length > 1 ? 'es' : ''} (${stdio.map((s) => s.name).join(', ')}).\nRun "mcp-warden scan" first, then re-run with --yes to confirm.`);
    }
    return chosen.map((s) => ({ name: s.name, command: s.command, args: s.args, env: { ...s.env, ...opts.env }, url: s.url, headers: { ...s.headers, ...opts.headers } }));
  }
  throw new UsageError('inspect needs a target: -- <command>, --url <url>, --server <name> or --all');
}

async function runInspect(opts) {
  const targets = inspectTargets(opts);
  const data = {};
  let failures = 0;
  for (const t of targets) {
    note(`inspecting ${t.name} …`);
    try {
      const res = t.command
        ? await inspectStdio(t.command, t.args, { env: t.env, timeoutMs: opts.timeout || 30000, inheritEnv: opts.inheritEnv })
        : await inspectHttp(t.url, { headers: t.headers, timeoutMs: opts.timeout || 30000 });
      const label = res.serverInfo?.name ? `${res.serverInfo.name}${res.serverInfo.version ? `@${res.serverInfo.version}` : ''}` : 'unknown server';
      note(`  ${label} exposed ${res.tools.length} tool${res.tools.length === 1 ? '' : 's'}`);
      const key = t.explicit && res.serverInfo?.name ? res.serverInfo.name : t.name;
      data[key] = { tools: res.tools };
    } catch (e) {
      failures++;
      note(`  failed: ${e.message.split('\n').join('\n  ')}`);
    }
  }
  if (!Object.keys(data).length) throw new Error('could not inspect any server');
  if (opts.save) {
    writeFileAtomic(opts.save, `${JSON.stringify(data, null, 2)}\n`);
    note(`tools saved to ${opts.save}`);
  }
  const report = auditToolData(data, { ignore: opts.ignore, source: opts.save || 'live inspection', lock: opts.lock, updateLock: opts.updateLock });
  report.inspected = Object.keys(data).length;
  report.failed = failures;
  return report;
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
    if (opts.version) { process.stdout.write(`${VERSION}\n`); return 0; }
    if (opts.help) { process.stdout.write(HELP); return 0; }
    applySettings(opts);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`mcp-warden: ${e.message}\nRun "mcp-warden --help" for usage.\n`);
      return 2;
    }
    process.stderr.write(`mcp-warden: ${e.message}\n`);
    return 2;
  }

  const commands = ['scan', 'tools', 'inspect', 'rules', 'locations', 'help'];
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
      report = auditTools(opts._[0], { ignore: opts.ignore, lock: opts.lock, updateLock: opts.updateLock });
    } else if (cmd === 'inspect') {
      report = await runInspect(opts);
    } else {
      const paths = opts._.length ? opts._ : opts.settingsPaths || [];
      report = audit({ paths, discover: opts.discover, ignore: opts.ignore });
      if (opts.writeBaseline) {
        const n = writeBaseline(opts.writeBaseline, report.findings);
        note(`baseline with ${n} finding${n === 1 ? '' : 's'} written to ${opts.writeBaseline}`);
        return 0;
      }
      if (opts.baseline) {
        const { findings, suppressed } = applyBaseline(opts.baseline, report.findings);
        report = { ...report, findings, summary: summarize(findings), suppressed };
      }
    }
  } catch (e) {
    note(e.message);
    if (opts.debug && !(e instanceof UsageError)) process.stderr.write(`${e.stack}\n`);
    return 2;
  }

  if (report.lock?.created) note(`lock file created at ${report.lock.file} – future runs will flag changed tools`);
  if (report.lock?.updated) note(`lock file ${report.lock.file} updated`);
  if (report.suppressed) note(`${report.suppressed} finding${report.suppressed === 1 ? '' : 's'} suppressed by baseline`);

  const filtered = filterBySeverity(report, opts.minSeverity);
  const colorOn = opts.output ? false : opts.color;
  emit(format(filtered, opts.format, { color: colorOn, verbose: opts.verbose }), opts);

  if (opts.failOn === 'none') return 0;
  const threshold = severityRank(opts.failOn);
  return report.findings.some((f) => severityRank(f.severity) >= threshold) ? 1 : 0;
}

// Piping into `head` & co. closes stdout early: exit quietly instead of crashing.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (e) => {
    if (e.code === 'EPIPE') process.exit(process.exitCode ?? 0);
    throw e;
  });
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (e) => {
    process.stderr.write(`mcp-warden: internal error: ${safeMultiline(e?.message || e)}\n`);
    if (process.argv.includes('--debug') || process.env.MCP_WARDEN_DEBUG) process.stderr.write(`${e?.stack}\n`);
    else process.stderr.write('Re-run with --debug for a stack trace and please report it: https://github.com/kirtanbhatt10/mcp-warden/issues\n');
    process.exitCode = 2;
  },
);
