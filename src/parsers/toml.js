/**
 * Small, dependency-free TOML parser covering the subset used by MCP client
 * configs (e.g. Codex CLI's ~/.codex/config.toml): tables, arrays of tables,
 * dotted/quoted keys, strings (basic, literal, multi-line), numbers, booleans,
 * arrays and inline tables. Dates are returned as raw strings.
 */
export function parseToml(text) {
  const p = new Parser(text);
  return p.parse();
}

class TomlError extends Error {
  constructor(msg, line) {
    super(`TOML parse error (line ${line}): ${msg}`);
  }
}

class Parser {
  constructor(src) {
    this.s = src.replace(/\r\n/g, '\n');
    this.i = 0;
    this.root = {};
    this.current = this.root;
  }

  get line() {
    return this.s.slice(0, this.i).split('\n').length;
  }

  err(msg) { throw new TomlError(msg, this.line); }

  peek(o = 0) { return this.s[this.i + o]; }

  skipWs() {
    while (this.i < this.s.length && (this.peek() === ' ' || this.peek() === '\t')) this.i++;
  }

  skipComment() {
    if (this.peek() === '#') while (this.i < this.s.length && this.peek() !== '\n') this.i++;
  }

  // skip whitespace, newlines and comments (used inside arrays)
  skipAll() {
    for (;;) {
      this.skipWs();
      if (this.peek() === '#') { this.skipComment(); continue; }
      if (this.peek() === '\n') { this.i++; continue; }
      break;
    }
  }

  expectEol() {
    this.skipWs();
    this.skipComment();
    if (this.i < this.s.length && this.peek() !== '\n') this.err(`unexpected "${this.peek()}"`);
  }

  parse() {
    while (this.i < this.s.length) {
      this.skipAll();
      if (this.i >= this.s.length) break;
      if (this.peek() === '[') {
        if (this.peek(1) === '[') {
          this.i += 2;
          const path = this.parseKey();
          this.skipWs();
          if (this.s.slice(this.i, this.i + 2) !== ']]') this.err('expected ]]');
          this.i += 2;
          const parent = this.walk(this.root, path.slice(0, -1));
          const last = path[path.length - 1];
          if (!Array.isArray(parent[last])) parent[last] = [];
          const obj = {};
          parent[last].push(obj);
          this.current = obj;
        } else {
          this.i++;
          const path = this.parseKey();
          this.skipWs();
          if (this.peek() !== ']') this.err('expected ]');
          this.i++;
          this.current = this.walk(this.root, path);
        }
        this.expectEol();
        continue;
      }
      const path = this.parseKey();
      this.skipWs();
      if (this.peek() !== '=') this.err('expected =');
      this.i++;
      this.skipWs();
      const value = this.parseValue();
      const target = this.walk(this.current, path.slice(0, -1));
      target[path[path.length - 1]] = value;
      this.expectEol();
    }
    return this.root;
  }

  walk(obj, path) {
    let cur = obj;
    for (const k of path) {
      if (Array.isArray(cur[k])) cur = cur[k][cur[k].length - 1];
      else {
        if (cur[k] === undefined || typeof cur[k] !== 'object') cur[k] = {};
        cur = cur[k];
      }
    }
    return cur;
  }

  parseKey() {
    const parts = [];
    for (;;) {
      this.skipWs();
      const c = this.peek();
      if (c === '"') parts.push(this.parseBasicString());
      else if (c === "'") parts.push(this.parseLiteralString());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(this.s.slice(this.i));
        if (!m) this.err('invalid key');
        parts.push(m[0]);
        this.i += m[0].length;
      }
      this.skipWs();
      if (this.peek() === '.') { this.i++; continue; }
      break;
    }
    return parts;
  }

  parseValue() {
    const c = this.peek();
    if (c === '"') {
      if (this.s.startsWith('"""', this.i)) return this.parseMultiBasic();
      return this.parseBasicString();
    }
    if (c === "'") {
      if (this.s.startsWith("'''", this.i)) return this.parseMultiLiteral();
      return this.parseLiteralString();
    }
    if (c === '[') return this.parseArray();
    if (c === '{') return this.parseInlineTable();
    const rest = this.s.slice(this.i);
    let m;
    if ((m = /^(true|false)(?![A-Za-z0-9_-])/.exec(rest))) {
      this.i += m[0].length;
      return m[0] === 'true';
    }
    if ((m = /^[+-]?(inf|nan)/.exec(rest))) {
      this.i += m[0].length;
      return m[1] === 'inf' ? (m[0][0] === '-' ? -Infinity : Infinity) : NaN;
    }
    if ((m = /^\d{4}-\d{2}-\d{2}([T ][0-9:.]+(Z|[+-]\d{2}:\d{2})?)?/.exec(rest))) {
      this.i += m[0].length;
      return m[0];
    }
    if ((m = /^0x[0-9A-Fa-f_]+|^0o[0-7_]+|^0b[01_]+/.exec(rest))) {
      this.i += m[0].length;
      return Number(m[0].replace(/_/g, ''));
    }
    if ((m = /^[+-]?\d[\d_]*(\.[\d_]+)?([eE][+-]?\d+)?/.exec(rest))) {
      this.i += m[0].length;
      return Number(m[0].replace(/_/g, ''));
    }
    this.err(`invalid value starting with "${c}"`);
  }

  parseBasicString() {
    this.i++; // opening "
    let out = '';
    while (this.i < this.s.length) {
      const c = this.peek();
      if (c === '"') { this.i++; return out; }
      if (c === '\n') this.err('newline in string');
      if (c === '\\') { out += this.parseEscape(); continue; }
      out += c;
      this.i++;
    }
    this.err('unterminated string');
  }

  parseEscape() {
    const e = this.s[this.i + 1];
    const map = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
    if (e in map) { this.i += 2; return map[e]; }
    if (e === 'u' || e === 'U') {
      const len = e === 'u' ? 4 : 8;
      const hex = this.s.slice(this.i + 2, this.i + 2 + len);
      if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) this.err('bad unicode escape');
      this.i += 2 + len;
      return String.fromCodePoint(parseInt(hex, 16));
    }
    this.err(`invalid escape \\${e}`);
  }

  parseLiteralString() {
    this.i++;
    const end = this.s.indexOf("'", this.i);
    const nl = this.s.indexOf('\n', this.i);
    if (end === -1 || (nl !== -1 && nl < end)) this.err('unterminated literal string');
    const v = this.s.slice(this.i, end);
    this.i = end + 1;
    return v;
  }

  parseMultiBasic() {
    this.i += 3;
    if (this.peek() === '\n') this.i++;
    let out = '';
    while (this.i < this.s.length) {
      if (this.s.startsWith('"""', this.i)) {
        this.i += 3;
        // allow up to two extra quotes inside the closing delimiter
        while (this.peek() === '"') { out += '"'; this.i++; }
        return out;
      }
      const c = this.peek();
      if (c === '\\') {
        // line-ending backslash trims whitespace
        if (/^\\[ \t]*\n/.test(this.s.slice(this.i))) {
          this.i++;
          while (/[\s]/.test(this.peek() || '')) this.i++;
          continue;
        }
        out += this.parseEscape();
        continue;
      }
      out += c;
      this.i++;
    }
    this.err('unterminated multi-line string');
  }

  parseMultiLiteral() {
    this.i += 3;
    if (this.peek() === '\n') this.i++;
    const end = this.s.indexOf("'''", this.i);
    if (end === -1) this.err('unterminated multi-line literal');
    const v = this.s.slice(this.i, end);
    this.i = end + 3;
    return v;
  }

  parseArray() {
    this.i++;
    const arr = [];
    for (;;) {
      this.skipAll();
      if (this.peek() === ']') { this.i++; return arr; }
      arr.push(this.parseValue());
      this.skipAll();
      if (this.peek() === ',') { this.i++; continue; }
      if (this.peek() === ']') { this.i++; return arr; }
      this.err('expected , or ] in array');
    }
  }

  parseInlineTable() {
    this.i++;
    const obj = {};
    this.skipWs();
    if (this.peek() === '}') { this.i++; return obj; }
    for (;;) {
      this.skipWs();
      const path = this.parseKey();
      this.skipWs();
      if (this.peek() !== '=') this.err('expected = in inline table');
      this.i++;
      this.skipWs();
      const v = this.parseValue();
      this.walk(obj, path.slice(0, -1))[path[path.length - 1]] = v;
      this.skipWs();
      if (this.peek() === ',') { this.i++; continue; }
      if (this.peek() === '}') { this.i++; return obj; }
      this.err('expected , or } in inline table');
    }
  }
}
