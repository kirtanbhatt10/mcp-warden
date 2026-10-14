/**
 * Safe process spawning for `inspect`.
 *
 * - Never uses `shell: true`: arguments taken from config files could
 *   otherwise inject shell commands (`&`, `|`, `;`).
 * - On Windows, `.cmd`/`.bat` shims (npx, uvx, …) cannot be spawned without a
 *   shell, so the command line is built with cmd.exe-safe escaping (the same
 *   approach as the widely used cross-spawn package) and passed verbatim.
 * - Launched servers get a minimal environment instead of every secret in the
 *   user's shell.
 * - Whole process trees are terminated (npx → node → server).
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const DEFAULT_ENV_POSIX = ['HOME', 'LOGNAME', 'PATH', 'SHELL', 'TERM', 'USER', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'NVM_DIR', 'NVM_BIN', 'VOLTA_HOME', 'npm_config_cache', 'npm_config_prefix', 'UV_CACHE_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR'];
const DEFAULT_ENV_WIN = ['APPDATA', 'HOMEDRIVE', 'HOMEPATH', 'LOCALAPPDATA', 'PATH', 'PATHEXT', 'PROCESSOR_ARCHITECTURE', 'SYSTEMDRIVE', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERNAME', 'USERPROFILE', 'COMSPEC', 'WINDIR', 'PROGRAMFILES', 'PROGRAMDATA', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'NODE_EXTRA_CA_CERTS'];

/**
 * Build the environment for a launched server: a small allow-list of
 * variables needed to locate runtimes, plus the server's own configured env.
 */
export function minimalEnv(extra = {}, { platform = process.platform, source = process.env, inherit = false } = {}) {
  if (inherit) return { ...source, ...extra };
  const allow = platform === 'win32' ? DEFAULT_ENV_WIN : DEFAULT_ENV_POSIX;
  const out = {};
  const keys = Object.keys(source);
  for (const name of allow) {
    // Windows env names are case-insensitive (Path vs PATH)
    const key = platform === 'win32' ? keys.find((k) => k.toUpperCase() === name) : name;
    const v = key !== undefined ? source[key] : undefined;
    if (v !== undefined && !v.startsWith('()')) out[key] = v; // skip exported bash functions
  }
  return { ...out, ...extra };
}

const META = /([()\][%!^"`<>&|;, *?])/g;

function escapeCommand(cmd) {
  return cmd.replace(META, '^$1');
}

export function escapeArgument(arg, doubleEscapeMetaChars = false) {
  let a = String(arg);
  // Sequence of backslashes followed by a double quote: double the backslashes and escape the quote
  a = a.replace(/(\\*)"/g, '$1$1\\"');
  // Sequence of backslashes at the end: double them (they precede the closing quote)
  a = a.replace(/(\\*)$/, '$1$1');
  a = `"${a}"`;
  a = a.replace(META, '^$1');
  if (doubleEscapeMetaChars) a = a.replace(META, '^$1');
  return a;
}

/** Resolve a bare command against PATH/PATHEXT (Windows) so we know whether it is a .cmd shim. */
export function resolveWindowsCommand(command, env = process.env) {
  const exts = (env.PATHEXT || env.Pathext || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasExt = path.extname(command) !== '';
  const candidates = hasExt ? [command] : exts.map((e) => command + e.toLowerCase());
  const isPath = /[\\/]/.test(command);
  const dirs = isPath ? [''] : (env.PATH || env.Path || '').split(';').filter(Boolean);
  for (const dir of dirs) {
    for (const c of candidates) {
      const full = dir ? path.join(dir, c) : c;
      try {
        if (fs.statSync(full).isFile()) return full;
      } catch { /* keep looking */ }
    }
  }
  return null;
}

/**
 * Spawn a command without a shell, safely on every platform.
 * @returns {import('node:child_process').ChildProcess}
 */
export function safeSpawn(command, args = [], { env, cwd, platform = process.platform } = {}) {
  const base = { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false };
  if (platform !== 'win32') {
    // own process group so the whole tree can be killed
    return spawn(command, args, { ...base, detached: true });
  }
  const resolved = resolveWindowsCommand(command, env || process.env) || command;
  if (!/\.(cmd|bat)$/i.test(resolved)) return spawn(resolved, args, base);
  const shim = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(resolved);
  const line = [escapeCommand(path.normalize(resolved)), ...args.map((a) => escapeArgument(a, shim))].join(' ');
  const comspec = (env && (env.COMSPEC || env.ComSpec)) || process.env.ComSpec || 'cmd.exe';
  return spawn(comspec, ['/d', '/s', '/c', `"${line}"`], { ...base, windowsVerbatimArguments: true });
}

/** Terminate a child and everything it spawned. */
export function killTree(child) {
  if (!child || !child.pid) return;
  try {
    if (process.platform === 'win32') {
      if (child.exitCode !== null) return;
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    } else {
      try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
      const t = setTimeout(() => {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
      }, 1500);
      t.unref();
    }
  } catch { /* already gone */ }
}
