/**
 * Duplicate-key detection for JSON/JSONC.
 *
 * JSON.parse silently keeps the *last* value of a duplicated key. In an MCP
 * config that lets an attacker show reviewers a harmless server definition
 * near the top of the file while the client actually loads a malicious one
 * defined later under the same name (or a second "command"/"args" inside the
 * same server). This scanner walks the raw text and reports every duplicate
 * key together with its path and line.
 *
 * @param {string} text  JSON or JSONC text
 * @returns {{path: string[], key: string, line: number, firstLine: number}[]}
 */
export function findDuplicateKeys(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  let line = 1;
  /** @type {{type: 'object'|'array', keys?: Map<string, number>, path: string[], index?: number, pendingKey?: string|null}[]} */
  const stack = [];

  const top = () => stack[stack.length - 1];
  const childPath = () => {
    const t = top();
    if (!t) return [];
    if (t.type === 'object') return [...t.path, t.pendingKey ?? ''];
    return [...t.path, String(t.index ?? 0)];
  };

  const readString = () => {
    // assumes text[i] === '"'
    let s = '';
    i++;
    while (i < n) {
      const ch = text[i];
      if (ch === '\\') {
        const nx = text[i + 1];
        if (nx === 'u') {
          s += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16) || 0);
          i += 6;
        } else {
          s += { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' }[nx] ?? nx;
          i += 2;
        }
        continue;
      }
      if (ch === '"') { i++; return s; }
      if (ch === '\n') line++;
      s += ch;
      i++;
    }
    return s;
  };

  const skipWsAndComments = () => {
    while (i < n) {
      const ch = text[i];
      if (ch === '\n') { line++; i++; continue; }
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\uFEFF') { i++; continue; }
      if (ch === '/' && text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; continue; }
      if (ch === '/' && text[i + 1] === '*') {
        const end = text.indexOf('*/', i + 2);
        const stop = end === -1 ? n : end + 2;
        for (let k = i; k < stop; k++) if (text[k] === '\n') line++;
        i = stop;
        continue;
      }
      break;
    }
  };

  while (i < n) {
    skipWsAndComments();
    if (i >= n) break;
    const ch = text[i];
    const t = top();
    if (ch === '{') {
      stack.push({ type: 'object', keys: new Map(), path: childPath(), pendingKey: null });
      i++;
      continue;
    }
    if (ch === '[') {
      stack.push({ type: 'array', path: childPath(), index: 0 });
      i++;
      continue;
    }
    if (ch === '}' || ch === ']') {
      stack.pop();
      i++;
      continue;
    }
    if (ch === ',') {
      if (t?.type === 'object') t.pendingKey = null;
      if (t?.type === 'array') t.index++;
      i++;
      continue;
    }
    if (ch === ':') { i++; continue; }
    if (ch === '"') {
      const keyLine = line;
      const s = readString();
      if (t?.type === 'object' && t.pendingKey === null) {
        // is this string a key? (next significant char is ':')
        const save = i;
        const saveLine = line;
        skipWsAndComments();
        if (text[i] === ':') {
          if (t.keys.has(s)) out.push({ path: t.path, key: s, line: keyLine, firstLine: t.keys.get(s) });
          else t.keys.set(s, keyLine);
          t.pendingKey = s;
        } else {
          i = save;
          line = saveLine;
        }
      }
      continue;
    }
    // literals: numbers, true/false/null — skip until a structural char
    while (i < n && !/[\s,:{}[\]"/]/.test(text[i])) i++;
    if (i < n && text[i] === '/' && text[i + 1] !== '/' && text[i + 1] !== '*') i++;
  }
  return out;
}
