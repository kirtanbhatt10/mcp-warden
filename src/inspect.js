/**
 * Live inspection: connect to an MCP server (stdio or Streamable HTTP / SSE
 * response), perform the initialize handshake and fetch tools/list.
 *
 * WARNING: stdio inspection *runs* the server command. Only inspect servers
 * you would run anyway, ideally inside a container or VM. To limit the blast
 * radius, servers are launched without a shell, with a minimal environment
 * (no inherited secrets), bounded output and a hard timeout, and their whole
 * process tree is terminated afterwards.
 */
import { safeSpawn, minimalEnv, killTree } from './spawn.js';

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'mcp-warden', version: '1' };
export const LIMITS = {
  maxMessageBytes: 16 * 1024 * 1024, // largest single JSON-RPC message we accept
  maxStderrBytes: 64 * 1024,
  maxPages: 50,
  maxTools: 5000,
};

const active = new Set();
let signalsHooked = false;
function track(child) {
  active.add(child);
  if (!signalsHooked) {
    signalsHooked = true;
    process.once('exit', () => active.forEach(killTree));
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      process.once(sig, () => {
        active.forEach(killTree);
        process.exit(sig === 'SIGINT' ? 130 : 143);
      });
    }
  }
}

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{env?: Record<string,string>, timeoutMs?: number, cwd?: string, inheritEnv?: boolean}} [opts]
 * @returns {Promise<{serverInfo: object, protocolVersion: string, tools: object[], stderr: string}>}
 */
export function inspectStdio(command, args = [], { env = {}, timeoutMs = 30000, cwd, inheritEnv = false } = {}) {
  return new Promise((resolve, reject) => {
    if (typeof command !== 'string' || !command.trim()) {
      reject(new Error('no command to launch'));
      return;
    }
    let child;
    try {
      child = safeSpawn(command, args.map(String), { cwd, env: minimalEnv(env, { inherit: inheritEnv }) });
    } catch (e) {
      reject(new Error(`failed to start "${command}": ${e.message}`));
      return;
    }
    track(child);

    let buf = '';
    let stderr = '';
    let nextId = 1;
    const pending = new Map();
    let finished = false;

    const finish = (err, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      for (const s of [child.stdin, child.stdout, child.stderr]) {
        try { s.destroy(); } catch { /* ignore */ }
      }
      killTree(child);
      active.delete(child);
      child.unref();
      if (err) {
        if (stderr.trim()) err.message += `\n--- server stderr ---\n${stderr.trim().split('\n').slice(-15).join('\n')}`;
        reject(err);
      } else resolve({ ...value, stderr });
    };

    const timer = setTimeout(() => finish(new Error(`timed out after ${timeoutMs} ms waiting for the server`)), timeoutMs);

    const send = (msg) => {
      if (finished || !child.stdin.writable) return;
      child.stdin.write(`${JSON.stringify(msg)}\n`);
    };
    const request = (method, params) => new Promise((res, rej) => {
      const id = nextId++;
      pending.set(id, { res, rej });
      send({ jsonrpc: '2.0', id, method, params });
    });

    child.on('error', (e) => finish(new Error(`failed to start "${command}": ${e.message}`)));
    child.on('exit', (code, signal) => {
      if (!finished) finish(new Error(`server exited early (${signal || `code ${code}`})`));
    });
    child.stdin.on('error', () => { /* EPIPE when the server dies; reported via 'exit' */ });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > LIMITS.maxStderrBytes) stderr = stderr.slice(-LIMITS.maxStderrBytes);
    });
    let scanFrom = 0;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d) => {
      if (finished) return;
      buf += d;
      let nl;
      // only scan the newly received part for newlines (avoids O(n^2) on large messages)
      while ((nl = buf.indexOf('\n', scanFrom)) !== -1) {
        scanFrom = 0;
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; } // servers sometimes log to stdout
        if (!msg || typeof msg !== 'object') continue;
        if (msg.id !== undefined && pending.has(msg.id) && (msg.result !== undefined || msg.error)) {
          const p = pending.get(msg.id);
          pending.delete(msg.id);
          if (msg.error) p.rej(new Error(`${String(msg.error.message || 'JSON-RPC error')} (${msg.error.code})`));
          else p.res(msg.result);
        } else if (msg.id !== undefined && typeof msg.method === 'string') {
          // server -> client request (roots/list, ping, sampling…): answer minimally, never grant anything
          if (msg.method === 'roots/list') send({ jsonrpc: '2.0', id: msg.id, result: { roots: [] } });
          else if (msg.method === 'ping') send({ jsonrpc: '2.0', id: msg.id, result: {} });
          else send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'mcp-warden does not support this request' } });
        }
      }
      scanFrom = buf.length;
      if (buf.length > LIMITS.maxMessageBytes) finish(new Error(`server sent more than ${LIMITS.maxMessageBytes} bytes without a newline`));
    });

    (async () => {
      const init = await request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      const tools = await listAll((cursor) => request('tools/list', cursor ? { cursor } : {}));
      finish(null, { serverInfo: asObject(init?.serverInfo), protocolVersion: init?.protocolVersion, tools });
    })().catch((e) => finish(e));
  });
}

function asObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

async function listAll(fetchPage) {
  const tools = [];
  let cursor;
  const seen = new Set();
  for (let page = 0; page < LIMITS.maxPages; page++) {
    const res = await fetchPage(cursor);
    const list = Array.isArray(res?.tools) ? res.tools : [];
    tools.push(...list.filter((t) => t && typeof t === 'object'));
    if (tools.length > LIMITS.maxTools) throw new Error(`server returned more than ${LIMITS.maxTools} tools`);
    cursor = typeof res?.nextCursor === 'string' && res.nextCursor ? res.nextCursor : undefined;
    if (!cursor || seen.has(cursor)) break; // stop on missing or repeating cursors
    seen.add(cursor);
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
    let v;
    try { v = JSON.parse(text); } catch { throw new Error('server returned invalid JSON'); }
    msgs.push(...(Array.isArray(v) ? v : [v]));
  }
  return msgs.find((m) => m && m.id === id) || null;
}

async function readBodyLimited(res, limit) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      try { await reader.cancel(); } catch { /* ignore */ }
      throw new Error(`response larger than ${limit} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * @param {string} url
 * @param {{headers?: Record<string,string>, timeoutMs?: number, fetchImpl?: typeof fetch}} [opts]
 */
export async function inspectHttp(url, { headers = {}, timeoutMs = 30000, fetchImpl = globalThis.fetch } = {}) {
  if (!fetchImpl) throw new Error('fetch is not available (Node 20+ required)');
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error(`invalid URL: ${url}`); }
  if (!/^https?:$/.test(parsed.protocol)) throw new Error(`unsupported URL scheme ${parsed.protocol} (use http or https)`);
  if (parsed.username || parsed.password) throw new Error('credentials in the URL are not allowed; pass them with -H "Authorization: …"');

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
    // redirect: 'error' — never forward Authorization headers to another origin
    const res = await fetchImpl(parsed.href, { method: 'POST', headers: h, body: JSON.stringify(body), signal: deadline, redirect: 'error' });
    const sid = res.headers.get('mcp-session-id');
    if (sid && /^[\x21-\x7e]{1,256}$/.test(sid)) session = sid;
    if (!expectResponse) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      return null;
    }
    const text = await readBodyLimited(res, LIMITS.maxMessageBytes);
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}: ${text.slice(0, 200)}`);
    const msg = parseRpcBody(text, res.headers.get('content-type') || '', body.id);
    if (!msg) throw new Error('no JSON-RPC response in server reply');
    if (msg.error) throw new Error(`${String(msg.error.message || 'JSON-RPC error')} (${msg.error.code})`);
    return msg.result;
  };

  try {
    const init = await post({ jsonrpc: '2.0', id: ++id, method: 'initialize', params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO } });
    if (typeof init?.protocolVersion === 'string') negotiated = init.protocolVersion;
    await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, false);
    const tools = await listAll((cursor) => post({ jsonrpc: '2.0', id: ++id, method: 'tools/list', params: cursor ? { cursor } : {} }));
    return { serverInfo: asObject(init?.serverInfo), protocolVersion: init?.protocolVersion, tools };
  } catch (e) {
    if (e?.name === 'TimeoutError' || deadline.aborted) throw new Error(`timed out after ${timeoutMs} ms`);
    if (e?.cause?.message?.includes('redirect')) throw new Error('server tried to redirect; refusing to follow (pass the final URL explicitly)');
    throw e;
  } finally {
    if (session) {
      fetchImpl(parsed.href, { method: 'DELETE', headers: { 'mcp-session-id': session, ...headers }, redirect: 'error', signal: AbortSignal.timeout(3000) }).catch(() => {});
    }
  }
}
