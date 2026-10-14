import os from 'node:os';
import { detectSecret, redact, SENSITIVE_KEY, isPlaceholder } from './secrets.js';
import { analyzeLaunch, baseCommand, effectiveCommand, isShell } from './packages.js';
import { POPULAR_PACKAGES, ARCHIVED_PACKAGES, TRUSTED_SCOPES, KNOWN_VULNERABLE } from './data.js';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const severityRank = (s) => SEVERITIES.indexOf(s);

/**
 * @typedef {Object} Finding
 * @property {string} ruleId
 * @property {string} rule
 * @property {'info'|'low'|'medium'|'high'|'critical'} severity
 * @property {string} message
 * @property {string} [evidence]
 * @property {string} [fix]
 * @property {string} [server]
 * @property {string} file
 * @property {string} pointer
 */

const LOOPBACK = /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i;

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** Every string in a server definition with its location. */
function* stringsOf(server) {
  if (server.command) yield { value: server.command, pointer: `${server.pointer}/command`, where: 'command' };
  for (let i = 0; i < server.args.length; i++) {
    const prev = server.args[i - 1] || '';
    let key = '';
    const eq = /^--?([A-Za-z0-9_.-]+)=(.*)$/s.exec(server.args[i]);
    if (eq) key = eq[1];
    else if (/^--?[A-Za-z]/.test(prev)) key = prev.replace(/^-+/, '');
    yield { value: eq ? eq[2] : server.args[i], pointer: `${server.pointer}/args/${i}`, where: `args[${i}]`, key };
  }
  for (const [k, v] of Object.entries(server.env)) yield { value: v, pointer: `${server.pointer}/env/${k}`, where: `env.${k}`, key: k };
  for (const [k, v] of Object.entries(server.headers)) yield { value: v, pointer: `${server.pointer}/headers/${k}`, where: `headers.${k}`, key: k };
  if (server.url) yield { value: server.url, pointer: `${server.pointer}/url`, where: 'url' };
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

/** Rules that run once per server. */
export const SERVER_RULES = [
  {
    id: 'MW001',
    name: 'hardcoded-secret',
    severity: 'critical',
    title: 'Hard-coded secret in MCP config',
    description: 'API keys, tokens or passwords are stored in plain text in the config. Anything that can read the file (other apps, backups, dotfile repos, malicious MCP servers with filesystem access) can steal them.',
    fix: 'Move the value to your OS keychain or a shell environment variable and reference it (e.g. "${env:GITHUB_TOKEN}" in VS Code, or export it before launching the client). Rotate the leaked credential.',
    check(server) {
      const out = [];
      const seen = new Set();
      for (const s of stringsOf(server)) {
        if (s.where === 'command') continue;
        const hit = detectSecret(s.value, s.key);
        if (!hit || seen.has(hit.match)) continue;
        seen.add(hit.match);
        out.push({
          severity: hit.severity,
          message: `${hit.name} found in ${s.where}`,
          evidence: redact(hit.match),
          pointer: s.pointer,
        });
      }
      return out;
    },
  },
  {
    id: 'MW002',
    name: 'unpinned-package',
    severity: 'medium',
    title: 'Server package is not pinned to an exact version',
    description: 'Runners like npx, uvx and docker fetch whatever the registry serves at launch time. A compromised maintainer account or a malicious update is executed automatically, with your user privileges, the next time your AI client starts.',
    fix: 'Pin an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3) or an image digest (image@sha256:…), and review changes before bumping.',
    check(server) {
      if (!server.command) return [];
      const l = analyzeLaunch(server.command, server.args);
      if (!l || l.pinned) return [];
      const yes = l.ecosystem === 'npm' && l.autoYes ? ' and installs without confirmation (-y)' : '';
      return [{ message: `${l.runner} launches "${l.spec}" – ${l.reason}${yes}`, evidence: l.spec, pointer: `${server.pointer}/args` }];
    },
  },
  {
    id: 'MW003',
    name: 'typosquat',
    severity: 'high',
    title: 'Package name looks like a typosquat of a popular MCP server',
    description: 'The package name is one or two characters away from a well-known MCP server or impersonates a trusted npm scope. Typosquatted MCP servers have been used to exfiltrate credentials and inject instructions into AI agents.',
    fix: 'Double-check the exact package name against the vendor\'s official documentation before running it.',
    check(server) {
      if (!server.command) return [];
      const l = analyzeLaunch(server.command, server.args);
      if (!l || l.ecosystem === 'docker') return [];
      const name = l.name.toLowerCase();
      if (POPULAR_PACKAGES.includes(name) || name in ARCHIVED_PACKAGES) return [];
      for (const known of [...POPULAR_PACKAGES, ...Object.keys(ARCHIVED_PACKAGES)]) {
        const d = levenshtein(name, known);
        if (d > 0 && d <= 2 && known.length >= 8) {
          return [{ message: `"${l.name}" is ${d} edit${d > 1 ? 's' : ''} away from the well-known package "${known}"`, evidence: l.name, pointer: `${server.pointer}/args` }];
        }
      }
      const scope = name.startsWith('@') ? name.split('/')[0] : null;
      if (scope && !TRUSTED_SCOPES.includes(scope)) {
        for (const t of TRUSTED_SCOPES) {
          const d = levenshtein(scope, t);
          if (d > 0 && d <= 2) {
            return [{ message: `npm scope "${scope}" imitates the trusted scope "${t}"`, evidence: l.name, pointer: `${server.pointer}/args` }];
          }
        }
      }
      return [];
    },
  },
  {
    id: 'MW004',
    name: 'archived-server',
    severity: 'medium',
    title: 'Server package is archived and unmaintained',
    description: 'This reference server was moved to modelcontextprotocol/servers-archived and no longer receives security fixes.',
    fix: 'Switch to the vendor-maintained replacement and remove the archived package.',
    check(server) {
      if (!server.command) return [];
      const l = analyzeLaunch(server.command, server.args);
      if (!l) return [];
      const key = l.name.toLowerCase();
      if (!(key in ARCHIVED_PACKAGES)) return [];
      const alt = ARCHIVED_PACKAGES[key];
      return [{ message: `"${l.name}" is archived and unmaintained${alt ? ` – consider ${alt}` : ''}`, evidence: l.name, pointer: `${server.pointer}/args` }];
    },
  },
  {
    id: 'MW005',
    name: 'insecure-transport',
    severity: 'high',
    title: 'Remote MCP server over unencrypted HTTP',
    description: 'Traffic (including tool calls, results and any auth headers) to a non-local server is sent in clear text and can be read or modified by anyone on the network path.',
    fix: 'Use an https:// endpoint. Plain http is only acceptable for localhost.',
    check(server) {
      const out = [];
      const urls = [];
      if (server.url) urls.push({ u: server.url, pointer: `${server.pointer}/url` });
      // mcp-remote / supergateway style proxies carry the URL in args
      server.args.forEach((a, i) => {
        if (/^(https?|wss?):\/\//i.test(a)) urls.push({ u: a, pointer: `${server.pointer}/args/${i}` });
      });
      for (const { u, pointer } of urls) {
        if (!/^(http|ws):\/\//i.test(u)) continue;
        const h = hostOf(u);
        if (!h || LOOPBACK.test(h)) continue;
        out.push({ message: `Connects to ${u.split('?')[0]} without TLS`, evidence: u.split('?')[0], pointer });
      }
      return out;
    },
  },
  {
    id: 'MW006',
    name: 'shell-execution',
    severity: 'high',
    title: 'Server is launched through a shell command string',
    description: 'Launching via "sh -c" / "cmd /c" with a command string hides what actually runs, enables injection through environment variables and makes the config hard to review.',
    fix: 'Invoke the server binary directly with an explicit "command" and "args" array.',
    check(server) {
      if (!server.command || !isShell(server.command)) return [];
      const cmd = baseCommand(server.command);
      const flagIdx = server.args.findIndex((a) => /^(-c|\/c|\/k|-command|-encodedcommand|-e)$/i.test(a));
      if (flagIdx === -1) return [];
      const script = server.args.slice(flagIdx + 1).join(' ');
      // `cmd /c npx -y pkg` is the documented Windows pattern – only flag real scripts
      if (cmd === 'cmd' && !/[|&;<>`$%]/.test(script)) return [];
      const encoded = /^-encodedcommand$/i.test(server.args[flagIdx]);
      return [{
        severity: encoded ? 'critical' : 'high',
        message: encoded ? 'PowerShell -EncodedCommand hides the real command being executed' : `Runs a shell script via ${cmd} ${server.args[flagIdx]}`,
        evidence: script.length > 120 ? `${script.slice(0, 117)}...` : script,
        pointer: `${server.pointer}/args`,
      }];
    },
  },
  {
    id: 'MW007',
    name: 'remote-code-download',
    severity: 'critical',
    title: 'Downloads and executes remote code at launch',
    description: 'The server pipes a script from the internet into an interpreter (curl | sh, iwr | iex …). Whoever controls that URL controls your machine every time the AI client starts.',
    fix: 'Install the server once from a reviewed, pinned release and launch the local binary.',
    check(server) {
      const all = [server.command || '', ...server.args].join(' ');
      if (/\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|invoke-expression|perl|ruby)\b/i.test(all) ||
          /\b(iex|invoke-expression)\b.*\b(downloadstring|iwr|irm|invoke-webrequest)\b/i.test(all) ||
          /(bash|sh)\s+<\(\s*(curl|wget)/i.test(all)) {
        return [{ message: 'Pipes a remotely downloaded script into an interpreter', evidence: all.length > 120 ? `${all.slice(0, 117)}...` : all, pointer: `${server.pointer}/args` }];
      }
      return [];
    },
  },
  {
    id: 'MW008',
    name: 'dangerous-container',
    severity: 'high',
    title: 'Container runs with dangerous privileges',
    description: 'Docker flags such as --privileged, a mounted Docker socket or host namespaces let a compromised MCP server escape the container and take over the host.',
    fix: 'Drop --privileged, never mount /var/run/docker.sock, avoid --network/--pid host, and mount only the directories the server needs (read-only where possible).',
    check(server) {
      if (!server.command) return [];
      const { cmd, args } = effectiveCommand(server.command, server.args);
      if (!['docker', 'podman', 'nerdctl'].includes(cmd) || args[0] !== 'run') return [];
      const out = [];
      const p = `${server.pointer}/args`;
      const joined = args.join(' ');
      if (args.includes('--privileged')) out.push({ severity: 'critical', message: 'Container runs with --privileged (full host access)', evidence: '--privileged', pointer: p });
      if (/docker\.sock|podman\.sock|containerd\.sock/.test(joined)) out.push({ severity: 'critical', message: 'Container engine socket is mounted (trivial host takeover)', evidence: (joined.match(/\S*\.sock\S*/) || [''])[0], pointer: p });
      args.forEach((a, i) => {
        const v = a.includes('=') ? a.split('=').slice(1).join('=') : args[i + 1];
        const flag = a.split('=')[0];
        if ((flag === '--network' || flag === '--net') && v === 'host') out.push({ severity: 'medium', message: 'Container shares the host network namespace', evidence: `${flag} host`, pointer: p });
        if ((flag === '--pid' || flag === '--ipc' || flag === '--uts' || flag === '--userns') && v === 'host') out.push({ severity: 'high', message: `Container shares the host ${flag.slice(2).toUpperCase()} namespace`, evidence: `${flag} host`, pointer: p });
        if (flag === '--cap-add' && v && /^(ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|NET_ADMIN|DAC_READ_SEARCH)$/i.test(v)) out.push({ severity: 'high', message: `Container is granted the ${v.toUpperCase()} capability`, evidence: `--cap-add ${v}`, pointer: p });
        if (flag === '--security-opt' && v && /(apparmor|seccomp|label)[=:]unconfined|label[=:]disable/i.test(v)) out.push({ severity: 'high', message: 'Container security profile disabled', evidence: `--security-opt ${v}`, pointer: p });
        if ((flag === '-v' || flag === '--volume') && v) {
          const src = v.split(':')[0];
          if (isBroadPath(src) && !/:ro\b/.test(v)) out.push({ severity: 'high', message: `Host path "${src}" is mounted read-write into the container`, evidence: `${flag} ${v}`, pointer: p });
        }
        if (flag === '--device' && v) out.push({ severity: 'medium', message: `Host device ${v} exposed to the container`, evidence: `--device ${v}`, pointer: p });
      });
      return out;
    },
  },
  {
    id: 'MW009',
    name: 'broad-filesystem-access',
    severity: 'high',
    title: 'Server is granted access to the entire disk or home directory',
    description: 'Giving an MCP server "/" or your whole home directory exposes SSH keys, cloud credentials, browser profiles and other AI-client configs to any prompt-injected tool call.',
    fix: 'Grant only the specific project directories the server needs.',
    check(server) {
      if (!server.command) return [];
      const { cmd, args } = effectiveCommand(server.command, server.args);
      if (['docker', 'podman', 'nerdctl'].includes(cmd)) return []; // handled by MW008
      const out = [];
      args.forEach((a, i) => {
        const val = a.includes('=') && a.startsWith('-') ? a.split('=').slice(1).join('=') : a;
        if (isBroadPath(val)) out.push({ message: `Grants access to "${val}"`, evidence: val, pointer: `${server.pointer}/args/${i}` });
      });
      return out;
    },
  },
  {
    id: 'MW010',
    name: 'secret-in-url',
    severity: 'high',
    title: 'Credential embedded in a URL',
    description: 'Tokens in URLs leak through logs, proxies, browser history and error messages.',
    fix: 'Send credentials in an Authorization header sourced from an environment variable.',
    check(server) {
      const out = [];
      const urls = [];
      if (server.url) urls.push([server.url, `${server.pointer}/url`]);
      server.args.forEach((a, i) => { if (/^[a-z]+:\/\//i.test(a)) urls.push([a, `${server.pointer}/args/${i}`]); });
      for (const [u, pointer] of urls) {
        let parsed;
        try { parsed = new URL(u); } catch { continue; }
        for (const [k, v] of parsed.searchParams) {
          if (SENSITIVE_KEY.test(k) && v && !isPlaceholder(v) && v.length >= 8) {
            out.push({ message: `Query parameter "${k}" carries a credential`, evidence: `${k}=${redact(v)}`, pointer });
          }
        }
      }
      return out;
    },
  },
  {
    id: 'MW011',
    name: 'auto-approve',
    severity: 'medium',
    title: 'Tool calls are auto-approved',
    description: 'Auto-approving tools removes the human confirmation step that protects you from prompt injection. A malicious web page or document can then make the agent call these tools silently.',
    fix: 'Remove alwaysAllow/autoApprove entries (or "trust": true) for tools that write, delete, send or execute.',
    check(server) {
      const out = [];
      const raw = server.raw || {};
      for (const key of ['alwaysAllow', 'autoApprove', 'auto_approve', 'autoapprove']) {
        const v = raw[key];
        if (Array.isArray(v) && v.length) {
          const risky = v.filter((t) => /(write|delete|remove|exec|run|shell|command|send|post|push|create|update|edit|move|kill|deploy|transfer|pay)/i.test(String(t)));
          out.push({
            severity: risky.length ? 'high' : 'medium',
            message: `${v.length} tool${v.length > 1 ? 's' : ''} auto-approved${risky.length ? ` including side-effecting ${risky.slice(0, 4).join(', ')}` : ''}`,
            evidence: v.slice(0, 6).join(', '),
            pointer: `${server.pointer}/${key}`,
          });
        } else if (v === true || v === '*') {
          out.push({ severity: 'high', message: 'All tools are auto-approved', evidence: `${key}: ${JSON.stringify(v)}`, pointer: `${server.pointer}/${key}` });
        }
      }
      if (raw.trust === true) out.push({ severity: 'high', message: '"trust": true bypasses every tool-call confirmation for this server', evidence: '"trust": true', pointer: `${server.pointer}/trust` });
      return out;
    },
  },
  {
    id: 'MW012',
    name: 'privilege-escalation',
    severity: 'high',
    title: 'Server runs with elevated privileges',
    description: 'Running an MCP server as root/administrator means a single prompt-injected tool call can modify the whole system.',
    fix: 'Run the server as your normal user; grant narrowly-scoped permissions instead.',
    check(server) {
      if (!server.command) return [];
      const b = baseCommand(server.command);
      const viaArgs = server.args.some((a) => /^(sudo|doas|runas|gsudo)$/i.test(a));
      if (['sudo', 'doas', 'runas', 'gsudo', 'pkexec'].includes(b) || viaArgs) {
        return [{ message: `Launched through ${viaArgs ? 'an elevation wrapper in args' : b}`, evidence: [server.command, ...server.args].join(' ').slice(0, 120), pointer: `${server.pointer}/command` }];
      }
      const { cmd, args } = effectiveCommand(server.command, server.args);
      if (['docker', 'podman'].includes(cmd) && args.some((a, i) => (a === '-u' || a === '--user') && /^(0|root)(:|$)/.test(args[i + 1] || ''))) {
        return [{ severity: 'medium', message: 'Container explicitly runs as root', evidence: '--user root', pointer: `${server.pointer}/args` }];
      }
      return [];
    },
  },
  {
    id: 'MW013',
    name: 'inline-code',
    severity: 'medium',
    title: 'Server launches inline interpreter code',
    description: 'Inline code (node -e, python -c, deno eval) is hard to audit and is a common way to smuggle loaders into configs.',
    fix: 'Put the code in a reviewed file in your repository and launch that file.',
    check(server) {
      if (!server.command) return [];
      const { cmd, args } = effectiveCommand(server.command, server.args);
      const map = { node: ['-e', '--eval', '-p', '--print'], python: ['-c'], python3: ['-c'], deno: ['eval'], bun: ['-e', '--eval'], ruby: ['-e'], perl: ['-e'], php: ['-r'] };
      const flags = map[cmd];
      if (!flags) return [];
      const i = args.findIndex((a) => flags.includes(a));
      if (i === -1) return [];
      const code = args[i + 1] || '';
      const sus = /(child_process|exec\(|spawn|eval\(|atob|base64|Buffer\.from|fromCharCode|subprocess|os\.system|__import__|https?:\/\/)/i.test(code);
      return [{ severity: sus ? 'high' : 'medium', message: `${cmd} ${args[i]} runs inline code${sus ? ' that spawns processes, decodes payloads or reaches the network' : ''}`, evidence: code.length > 100 ? `${code.slice(0, 97)}...` : code, pointer: `${server.pointer}/args` }];
    },
  },
  {
    id: 'MW014',
    name: 'tls-verification-disabled',
    severity: 'high',
    title: 'TLS certificate verification is disabled',
    description: 'Disabling certificate checks lets anyone on the network impersonate the API the server talks to and capture its credentials.',
    fix: 'Remove the override. If you need a corporate CA, point NODE_EXTRA_CA_CERTS / SSL_CERT_FILE at it instead.',
    check(server) {
      const out = [];
      const envBad = { NODE_TLS_REJECT_UNAUTHORIZED: /^0$/, PYTHONHTTPSVERIFY: /^0$/, CURL_INSECURE: /^(1|true)$/i, GIT_SSL_NO_VERIFY: /^(1|true)$/i, REQUESTS_CA_BUNDLE: /^$/ };
      for (const [k, v] of Object.entries(server.env)) {
        if (envBad[k] && envBad[k].test(v.trim())) out.push({ message: `${k}=${v} disables certificate verification`, evidence: `${k}=${v}`, pointer: `${server.pointer}/env/${k}` });
      }
      server.args.forEach((a, i) => {
        if (/^(--insecure|--no-verify-ssl|--no-tls-verify|--ignore-certificate-errors|--tls-skip-verify|--skip-tls-verify|--disable-ssl-verification|--allow-insecure)$/i.test(a)) {
          out.push({ message: `${a} disables certificate verification`, evidence: a, pointer: `${server.pointer}/args/${i}` });
        }
      });
      return out;
    },
  },
  {
    id: 'MW015',
    name: 'untrusted-registry',
    severity: 'medium',
    title: 'Packages are installed from a non-default registry',
    description: 'A custom or plain-HTTP package index can serve modified packages. Make sure the registry is one you control and trust.',
    fix: 'Use the default registry or a verified internal mirror over HTTPS.',
    check(server) {
      const out = [];
      const official = /^(https:\/\/registry\.npmjs\.org|https:\/\/registry\.yarnpkg\.com|https:\/\/pypi\.org|https:\/\/files\.pythonhosted\.org)/i;
      const check = (val, pointer, where) => {
        if (!val || official.test(val) || /^(\$|%|\{\{)/.test(val)) return;
        const insecure = /^http:\/\//i.test(val);
        out.push({ severity: insecure ? 'high' : 'low', message: `${where} points to ${insecure ? 'an unencrypted' : 'a custom'} registry ${val}`, evidence: val, pointer });
      };
      server.args.forEach((a, i) => {
        const m = /^--(registry|index-url|extra-index-url|index|default-index)(?:=(.+))?$/.exec(a);
        if (m) check(m[2] ?? server.args[i + 1], `${server.pointer}/args/${i}`, `--${m[1]}`);
      });
      for (const [k, v] of Object.entries(server.env)) {
        if (/^(npm_config_registry|NPM_CONFIG_REGISTRY|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|UV_EXTRA_INDEX_URL|UV_DEFAULT_INDEX|UV_INDEX)$/.test(k)) check(v, `${server.pointer}/env/${k}`, k);
      }
      return out;
    },
  },
  {
    id: 'MW016',
    name: 'remote-without-auth',
    severity: 'info',
    title: 'Remote MCP server configured without credentials',
    description: 'No Authorization header is configured. That is fine for servers that use OAuth (the client will prompt), but double-check the endpoint is the vendor\'s official one.',
    fix: 'Verify the server URL against the vendor documentation.',
    check(server) {
      if (!server.url) return [];
      const h = hostOf(server.url);
      if (!h || LOOPBACK.test(h)) return [];
      const hasAuth = Object.keys(server.headers).some((k) => /^authorization$/i.test(k) || SENSITIVE_KEY.test(k));
      if (hasAuth) return [];
      return [{ message: `Remote server ${h} has no static auth header (OAuth or unauthenticated)`, evidence: h, pointer: `${server.pointer}/url` }];
    },
  },
  {
    id: 'MW019',
    name: 'known-vulnerable-package',
    severity: 'critical',
    title: 'Server package has a known vulnerability or is malicious',
    description: 'The configured package (or version) is affected by a published vulnerability or was identified as malicious.',
    fix: 'Upgrade to the fixed version and pin it, or remove the package entirely if it is marked malicious.',
    check(server) {
      if (!server.command) return [];
      const l = analyzeLaunch(server.command, server.args);
      if (!l) return [];
      const v = KNOWN_VULNERABLE.find((k) => k.name === l.name.toLowerCase());
      if (!v) return [];
      if (v.malicious) return [{ severity: v.severity, message: `"${l.name}" is a known malicious package (${v.id}): ${v.summary}`, evidence: l.spec, pointer: `${server.pointer}/args` }];
      if (l.version && /^v?\d+\.\d+\.\d+/.test(l.version)) {
        if (compareVersions(l.version, v.fixed) < 0) {
          return [{ severity: v.severity, message: `${l.name}@${l.version} is vulnerable to ${v.id} (${v.summary}); fixed in ${v.fixed}`, evidence: l.spec, pointer: `${server.pointer}/args` }];
        }
        return [];
      }
      return [{ severity: 'medium', message: `${l.name} had ${v.id} (${v.summary}); version is not pinned, so make sure ≥ ${v.fixed} runs`, evidence: l.spec, pointer: `${server.pointer}/args` }];
    },
  },
];

export function compareVersions(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

function isBroadPath(p) {
  if (!p) return false;
  const v = String(p).trim().replace(/\\/g, '/').replace(/\/+$/, '') || '/';
  const home = os.homedir().replace(/\\/g, '/').replace(/\/+$/, '');
  return (
    v === '/' ||
    v === '~' ||
    v === '$HOME' ||
    v === '${HOME}' ||
    v === '${env:HOME}' ||
    v === '${userHome}' ||
    v === '%USERPROFILE%' ||
    /^[A-Za-z]:\/?$/.test(v) ||
    /^\/(Users|home)\/[^/]+$/.test(v) ||
    v === '/root' ||
    /^[A-Za-z]:\/Users\/[^/]+$/i.test(v) ||
    (home.length > 1 && v === home)
  );
}

/** Rules that run once per config file. */
export const FILE_RULES = [
  {
    id: 'MW017',
    name: 'config-permissions',
    severity: 'medium',
    title: 'Config containing secrets is readable by other users',
    description: 'The file holds credentials but is group- or world-readable.',
    fix: 'chmod 600 the file (and better: move the secrets out of it).',
    check({ stat, findings }) {
      if (process.platform === 'win32' || !stat) return [];
      const hasSecret = findings.some((f) => f.ruleId === 'MW001');
      if (!hasSecret) return [];
      const mode = stat.mode & 0o777;
      if ((mode & 0o044) === 0) return [];
      return [{ message: `File mode is ${mode.toString(8).padStart(3, '0')}; secrets are readable by ${mode & 0o004 ? 'every user on this machine' : 'your group'}`, evidence: mode.toString(8), pointer: '' }];
    },
  },
  {
    id: 'MW018',
    name: 'duplicate-server-name',
    severity: 'low',
    title: 'Same server name defined more than once',
    description: 'Duplicate names make it ambiguous which definition (and which tools) the client actually loads, a known vector for tool shadowing.',
    fix: 'Give every server a unique name.',
    check({ servers }) {
      const counts = new Map();
      for (const s of servers) counts.set(s.name, (counts.get(s.name) || 0) + 1);
      return [...counts].filter(([, c]) => c > 1).map(([k, c]) => ({ message: `"${k}" is defined ${c} times in this file`, evidence: k, pointer: '' }));
    },
  },
];

export const ALL_RULES = [...SERVER_RULES, ...FILE_RULES];
