/**
 * Live inspection: connect to an MCP server (stdio or Streamable HTTP / SSE
 * response), perform the initialize handshake and fetch tools/list.
 *
 * WARNING: stdio inspection *runs* the server command. Only inspect servers
 * you would run anyway, ideally inside a container or VM.
 */
import { spawn } from 'node:child_process';

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'mcp-warden', version: '1' };

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{env?: Record<string,string>, timeoutMs?: number, cwd?: string}} [opts]
 * @returns {Promise<{serverInfo: object, protocolVersion: string, tools: object[], stderr: string}>}
 */
export function inspectStdio(command, args = [], { env = {}, timeoutMs = 30000, cwd } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        env: { ...process.env, ...env },
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: process.platform === 'win32' && !/\.(exe|com)$/i.test(command),
        windowsHide: true,
      });
    } catch (e) {
      reject(e);
      return;
    }

    let buf = '';
    let stderr = '';
    let nextId = 1;
    const pending = new Map();
    let finished = false;

    const finish = (err, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { child.stdin.end(); } catch { /* ignore */ }
      try { child.kill(); } catch { /* ignore */ }
      if (err) {
        if (stderr.trim()) err.message += `\n--- server stderr ---\n${stderr.trim().split('\n').slice(-15).join('\n')}`;
        reject(err);
      } else resolve({ ...value, stderr });
    };

    const timer = setTimeout(() => finish(new Error(`timed out after ${timeoutMs} ms waiting for the server`)), timeoutMs);

    const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);
    const request = (method, params) => new Promise((res, rej) => {
      const id = nextId++;
      pending.set(id, { res, rej });
      send({ jsonrpc: '2.0', id, method, params });
    });

    child.on('error', (e) => finish(new Error(`failed to start "${command}": ${e.message}`)));
    child.on('exit', (code, signal) => {
      if (!finished) finish(new Error(`server exited early (${signal || `code ${code}`})`));
    });
    child.stderr.on('data', (d) => { stderr += d.toString(); if (stderr.length > 20000) stderr = stderr.slice(-20000); });
    child.stdout.on('data', (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; } // servers sometimes log to stdout
        if (msg.id !== undefined && pending.has(msg.id) && (msg.result !== undefined || msg.error)) {
          const p = pending.get(msg.id);
          pending.delete(msg.id);
          if (msg.error) p.rej(new Error(`${msg.error.message || 'JSON-RPC error'} (${msg.error.code})`));
          else p.res(msg.result);
        } else if (msg.id !== undefined && msg.method) {
          // server -> client request (e.g. roots/list, ping): answer politely
          send({ jsonrpc: '2.0', id: msg.id, result: msg.method === 'roots/list' ? { roots: [] } : {} });
        }
      }
    });

    (async () => {
      const init = await request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      const tools = await listAll((cursor) => request('tools/list', cursor ? { cursor } : {}));
      finish(null, { serverInfo: init?.serverInfo || {}, protocolVersion: init?.protocolVersion, tools });
    })().catch((e) => finish(e));
  });
}

async function listAll(fetchPage) {
  const tools = [];
  let cursor;
  for (let page = 0; page < 50; page++) {
    const res = await fetchPage(cursor);
    tools.push(...(res?.tools || []));
    cursor = res?.nextCursor;
    if (!cursor) break;
  }
  return tools;
}

/** Parse a JSON or text/event-stream response body and return the JSON-RPC message with the given id. */
export function parseRpcBody(text, contentType = '', id) {
  const msgs = [];
  if (/text\/event-stream/i.test(contentType) || /^(event|data|id):/m.test(text)) {
    for (const block of text.split(/\r?\n\r?\n/)) {
      const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
      if (!data) continue;
      try { msgs.push(JSON.parse(data)); } catch { /* ignore */ }
    }
  } else if (text.trim()) {
    const v = JSON.parse(text);
    msgs.push(...(Array.isArray(v) ? v : [v]));
  }
  return msgs.find((m) => m && m.id === id) || null;
}

/**
 * @param {string} url
 * @param {{headers?: Record<string,string>, timeoutMs?: number, fetchImpl?: typeof fetch}} [opts]
 */
export async function inspectHttp(url, { headers = {}, timeoutMs = 30000, fetchImpl = globalThis.fetch } = {}) {
  if (!fetchImpl) throw new Error('fetch is not available (Node 20+ required)');
  let session;
  let negotiated = PROTOCOL_VERSION;
  let id = 0;
  const deadline = AbortSignal.timeout(timeoutMs);

  const post = async (body, expectResponse = true) => {
    const h = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': negotiated,
      ...headers,
    };
    if (session) h['mcp-session-id'] = session;
    const res = await fetchImpl(url, { method: 'POST', headers: h, body: JSON.stringify(body), signal: deadline });
    const sid = res.headers.get('mcp-session-id');
    if (sid) session = sid;
    if (!expectResponse) return null;
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}: ${text.slice(0, 200)}`);
    const msg = parseRpcBody(text, res.headers.get('content-type') || '', body.id);
    if (!msg) throw new Error('no JSON-RPC response in server reply');
    if (msg.error) throw new Error(`${msg.error.message || 'JSON-RPC error'} (${msg.error.code})`);
    return msg.result;
  };

  const init = await post({ jsonrpc: '2.0', id: ++id, method: 'initialize', params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO } });
  if (init?.protocolVersion) negotiated = init.protocolVersion;
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, false);
  const tools = await listAll((cursor) => post({ jsonrpc: '2.0', id: ++id, method: 'tools/list', params: cursor ? { cursor } : {} }));
  if (session) {
    fetchImpl(url, { method: 'DELETE', headers: { 'mcp-session-id': session, ...headers } }).catch(() => {});
  }
  return { serverInfo: init?.serverInfo || {}, protocolVersion: init?.protocolVersion, tools };
}
