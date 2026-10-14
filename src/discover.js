import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Known MCP config locations for popular clients.
 * Each entry: { client, file } with absolute paths.
 */
export function knownLocations({ home = os.homedir(), cwd = process.cwd(), platform = process.platform, env = process.env } = {}) {
  const j = path.join;
  const appData = env.APPDATA || j(home, 'AppData', 'Roaming');
  const xdg = env.XDG_CONFIG_HOME || j(home, '.config');

  // Per-OS "application support" directory used by Electron apps (Claude, VS Code, Cursor)
  const appSupport = platform === 'darwin' ? j(home, 'Library', 'Application Support') : platform === 'win32' ? appData : xdg;

  const vscodeFlavours = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];
  const list = [
    { client: 'Claude Desktop', file: j(appSupport, 'Claude', 'claude_desktop_config.json') },
    { client: 'Claude Code', file: j(home, '.claude.json') },
    { client: 'Claude Code', file: j(home, '.claude', 'settings.json') },
    { client: 'Claude Code (project)', file: j(cwd, '.mcp.json') },
    { client: 'Cursor', file: j(home, '.cursor', 'mcp.json') },
    { client: 'Cursor (project)', file: j(cwd, '.cursor', 'mcp.json') },
    { client: 'Windsurf', file: j(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { client: 'Gemini CLI', file: j(home, '.gemini', 'settings.json') },
    { client: 'Gemini CLI (project)', file: j(cwd, '.gemini', 'settings.json') },
    { client: 'Codex CLI', file: j(env.CODEX_HOME || j(home, '.codex'), 'config.toml') },
    { client: 'Zed', file: j(xdg, 'zed', 'settings.json') },
    { client: 'Zed', file: j(home, '.config', 'zed', 'settings.json') },
    { client: 'VS Code (workspace)', file: j(cwd, '.vscode', 'mcp.json') },
    { client: 'VS Code (workspace)', file: j(cwd, '.vscode', 'settings.json') },
    { client: 'Roo Code (project)', file: j(cwd, '.roo', 'mcp.json') },
    { client: 'Amazon Q', file: j(home, '.aws', 'amazonq', 'mcp.json') },
    { client: 'Amazon Q (project)', file: j(cwd, '.amazonq', 'mcp.json') },
    { client: 'LM Studio', file: j(home, '.lmstudio', 'mcp.json') },
  ];

  for (const flavour of vscodeFlavours) {
    const user = j(appSupport, flavour, 'User');
    list.push({ client: `${flavour} (user)`, file: j(user, 'mcp.json') });
    list.push({ client: `${flavour} (user)`, file: j(user, 'settings.json') });
    list.push({ client: `Cline (${flavour})`, file: j(user, 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json') });
    list.push({ client: `Roo Code (${flavour})`, file: j(user, 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json') });
  }

  // de-duplicate by path
  const seen = new Set();
  return list.filter((l) => (seen.has(l.file) ? false : (seen.add(l.file), true)));
}

/** Return known locations that actually exist on disk. */
export function discover(opts = {}) {
  return knownLocations(opts).filter((l) => isFile(l.file));
}

/** Filenames that are recognised when scanning a directory tree. */
const CANDIDATE_NAMES = new Set([
  'mcp.json',
  '.mcp.json',
  'mcp_config.json',
  'mcp_settings.json',
  'cline_mcp_settings.json',
  'claude_desktop_config.json',
  '.claude.json',
  'settings.json',
  'config.toml',
]);

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '.venv', 'venv', '__pycache__', 'target']);

/**
 * Expand user-supplied paths: files are returned as-is, directories are
 * walked (depth-limited) for MCP config candidates.
 */
export function expandPaths(paths, { maxDepth = 6 } = {}) {
  const files = [];
  for (const p of paths) {
    const abs = path.resolve(p);
    let st;
    try {
      st = fs.statSync(abs);
    } catch {
      files.push({ client: 'missing', file: abs, missing: true });
      continue;
    }
    if (st.isFile()) files.push({ client: guessClient(abs), file: abs });
    else if (st.isDirectory()) walk(abs, 0, maxDepth, files);
  }
  return files;
}

function walk(dir, depth, maxDepth, acc) {
  if (depth > maxDepth) return;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walk(full, depth + 1, maxDepth, acc);
    } else if (e.isFile() && isCandidate(full)) {
      acc.push({ client: guessClient(full), file: full });
    }
  }
}

function isCandidate(file) {
  const base = path.basename(file);
  if (!CANDIDATE_NAMES.has(base)) {
    return /mcp.*\.json$/i.test(base);
  }
  // generic names: only when they live in a known client directory or mention MCP
  if (base === 'settings.json' || base === 'config.toml') {
    try {
      const text = fs.readFileSync(file, 'utf8');
      return /mcpServers|mcp_servers|context_servers|"mcp"\s*:/.test(text);
    } catch {
      return false;
    }
  }
  return true;
}

export function guessClient(file) {
  const f = file.replace(/\\/g, '/');
  if (f.endsWith('claude_desktop_config.json')) return 'Claude Desktop';
  if (f.endsWith('/.claude.json') || f.endsWith('/.mcp.json') || f.includes('/.claude/')) return 'Claude Code';
  if (f.includes('/.cursor/')) return 'Cursor';
  if (f.includes('windsurf')) return 'Windsurf';
  if (f.includes('/.gemini/')) return 'Gemini CLI';
  if (f.includes('/.codex/') || f.endsWith('.toml')) return 'Codex CLI';
  if (f.includes('/zed/')) return 'Zed';
  if (f.includes('claude-dev') || f.endsWith('cline_mcp_settings.json')) return 'Cline';
  if (f.includes('/.roo/') || f.includes('roo-cline')) return 'Roo Code';
  if (f.includes('/.vscode/') || f.includes('/Code/')) return 'VS Code';
  return 'MCP config';
}

function isFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}
