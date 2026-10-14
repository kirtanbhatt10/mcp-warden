import fs from 'node:fs';
import path from 'node:path';
import { parseJsonc } from './parsers/jsonc.js';
import { parseToml } from './parsers/toml.js';

/**
 * @typedef {Object} McpServer
 * @property {string} name          Display name (may include a project prefix)
 * @property {string} key           Raw key of the server inside its container
 * @property {string} file          Absolute path of the config file
 * @property {string} pointer       JSON-pointer-like location of the server
 * @property {'stdio'|'remote'} transport
 * @property {string} [command]
 * @property {string[]} args
 * @property {Record<string,string>} env
 * @property {string} [url]
 * @property {Record<string,string>} headers
 * @property {object} raw           The original server object
 */

/**
 * Read and parse a config file and return its MCP servers.
 * @returns {{servers: McpServer[], text: string, error?: string, client?: string}}
 */
export function loadConfigFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    return { servers: [], text: '', error: `cannot read: ${e.code || e.message}` };
  }
  let data;
  try {
    data = file.toLowerCase().endsWith('.toml') ? parseToml(text) : parseJsonc(text);
  } catch (e) {
    return { servers: [], text, error: `cannot parse: ${e.message}` };
  }
  return { servers: extractServers(data, file), text };
}

/** Extract every MCP server definition from a parsed config object. */
export function extractServers(data, file = '<inline>') {
  /** @type {McpServer[]} */
  const out = [];
  if (!data || typeof data !== 'object') return out;

  const add = (container, pointerBase, prefix = '') => {
    if (!container || typeof container !== 'object' || Array.isArray(container)) return;
    for (const [key, raw] of Object.entries(container)) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
      const s = normalizeServer(raw);
      if (!s) continue;
      out.push({
        name: prefix ? `${prefix} › ${key}` : key,
        key,
        file,
        pointer: `${pointerBase}/${escapePointer(key)}`,
        ...s,
        raw,
      });
    }
  };

  // Claude Desktop, Claude Code, Cursor, Windsurf, Gemini CLI, Cline, Roo
  add(data.mcpServers, '/mcpServers');
  // VS Code .vscode/mcp.json and User/mcp.json
  add(data.servers, '/servers');
  // VS Code settings.json  ("mcp": { "servers": {...} })
  if (data.mcp && typeof data.mcp === 'object') add(data.mcp.servers, '/mcp/servers');
  // Zed settings.json
  add(data.context_servers, '/context_servers');
  // Codex CLI config.toml  ([mcp_servers.<name>])
  add(data.mcp_servers, '/mcp_servers');
  // Claude Code ~/.claude.json per-project servers
  if (data.projects && typeof data.projects === 'object') {
    for (const [proj, cfg] of Object.entries(data.projects)) {
      if (cfg && typeof cfg === 'object') {
        add(cfg.mcpServers, `/projects/${escapePointer(proj)}/mcpServers`, shortProject(proj));
      }
    }
  }
  return out;
}

function shortProject(p) {
  const base = p.split(/[\\/]/).filter(Boolean).pop();
  return base || p;
}

function escapePointer(k) {
  return String(k).replace(/~/g, '~0').replace(/\//g, '~1');
}

function asStringRecord(obj) {
  const out = {};
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return out;
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    out[k] = typeof v === 'string' ? v : String(v);
  }
  return out;
}

/** Normalize the many server shapes used by different MCP clients. */
export function normalizeServer(raw) {
  let command = raw.command;
  let args = raw.args;
  let env = raw.env;

  // Zed (legacy): { command: { path, args, env } }
  if (command && typeof command === 'object' && !Array.isArray(command)) {
    args = command.args ?? args;
    env = command.env ?? env;
    command = command.path ?? command.command;
  }
  // Some clients accept command as an array
  if (Array.isArray(command)) {
    args = [...command.slice(1), ...(Array.isArray(args) ? args : [])];
    command = command[0];
  }

  const url = raw.url ?? raw.serverUrl ?? raw.httpUrl ?? raw.uri;
  const type = String(raw.type ?? raw.transport ?? '').toLowerCase();
  const isRemote = typeof url === 'string' || ['http', 'sse', 'streamable-http', 'streamablehttp', 'ws', 'websocket'].includes(type);

  if (typeof command !== 'string' && !isRemote) return null;

  return {
    transport: typeof command === 'string' ? 'stdio' : 'remote',
    command: typeof command === 'string' ? command : undefined,
    args: Array.isArray(args) ? args.map((a) => String(a)) : [],
    env: asStringRecord(env),
    url: typeof url === 'string' ? url : undefined,
    headers: asStringRecord(raw.headers ?? raw.http_headers ?? raw.requestInit?.headers),
  };
}

/**
 * Best-effort line lookup for a pointer inside the original text, used for
 * SARIF and editor-friendly output. Returns 1 when nothing better is found.
 */
export function locateLine(text, pointer) {
  if (!text || !pointer) return 1;
  const parts = pointer.split('/').filter(Boolean).map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'));
  let idx = 0;
  for (const part of parts) {
    const candidates = [`"${part}"`, `'${part}'`, `.${part}]`, `.${part}.`, `.${part}"]`, `\n${part} =`, `\n${part}=`, ` ${part} =`];
    let found = -1;
    for (const c of candidates) {
      const at = text.indexOf(c, idx);
      if (at !== -1 && (found === -1 || at < found)) found = at;
    }
    if (found === -1) continue;
    idx = found + (text[found] === '\n' ? 1 : 0);
  }
  return text.slice(0, idx).split('\n').length;
}

export function relativeTo(file, cwd = process.cwd()) {
  const rel = path.relative(cwd, file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : file;
}
