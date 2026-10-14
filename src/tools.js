/**
 * Tool-poisoning scanner. Inspects MCP tool definitions (the result of a
 * `tools/list` call) for hidden instructions aimed at the model.
 */
import { detectSecret, redact } from './secrets.js';

export const TOOL_RULES = [
  {
    id: 'TP001',
    name: 'hidden-instructions',
    severity: 'high',
    title: 'Tool description contains instructions aimed at the model',
    fix: 'Tool descriptions should describe behaviour, not command the assistant. Remove or replace this server.',
    test(text) {
      const re = /<\s*(important|system|instructions?|secret|hidden|admin|note to (the )?(ai|assistant|model))\s*>|\[\s*(inst|system)\s*\]|\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|other|system)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|guidelines?)|\byou (must|should) (always|first|now|also)\b|\bbefore (using|calling|you use) (this|any) tool\b|\bas an ai\b|\bnew instructions?\b/i;
      return matchOf(re, text);
    },
  },
  {
    id: 'TP002',
    name: 'concealment',
    severity: 'critical',
    title: 'Tool asks the model to hide actions from the user',
    fix: 'Treat the server as malicious. Remove it and rotate any credentials it could have seen.',
    test(text) {
      const re = /\b(do not|don't|never|must not|without)\b[^.\n]{0,30}\b(tell|inform|mention|notify|alert|show|reveal|let)\b[^.\n]{0,60}\b(the )?(user|human|operator)\b|\bwithout (the )?(user|human)('s)? (knowing|knowledge|noticing|consent)\b|\b(user|human) (must|should) not (know|see|be told)\b|\bkeep (this|it) (a )?secret\b/i;
      return matchOf(re, text);
    },
  },
  {
    id: 'TP003',
    name: 'sensitive-file-access',
    severity: 'high',
    title: 'Tool description references credential or config files',
    fix: 'A legitimate tool rarely needs to mention SSH keys or other AI-client configs in its description. Investigate before use.',
    test(text) {
      const re = /(~|\$home|%userprofile%)?[\/\\]?\.(ssh|aws|gnupg|kube|docker|npmrc|netrc|pypirc|git-credentials|env)\b|\bid_(rsa|ed25519|ecdsa)\b|\bcredentials(\.json)?\b|\bmcp\.json\b|claude_desktop_config|\.cursor[\/\\]|\bwallet\.dat\b|\bkeychain\b|\b\/etc\/(passwd|shadow)\b/i;
      return matchOf(re, text);
    },
  },
  {
    id: 'TP004',
    name: 'invisible-characters',
    severity: 'high',
    title: 'Tool metadata contains invisible or bidirectional Unicode',
    fix: 'Invisible characters can carry instructions humans cannot see in the UI. Strip them or remove the server.',
    test(text) {
      // zero-width, word joiner, BOM, bidi controls, Unicode tag characters
      const re = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/u;
      const m = re.exec(text);
      if (!m) return null;
      const cp = m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      const tags = decodeTagChars(text);
      return tags ? `U+${cp} … decoded hidden text: "${tags.slice(0, 80)}"` : `U+${cp} at position ${m.index}`;
    },
  },
  {
    id: 'TP005',
    name: 'tool-shadowing',
    severity: 'medium',
    title: 'Tool tries to influence how other tools are used',
    fix: 'A tool should not change the behaviour of other tools. This is a classic cross-server shadowing attack.',
    test(text) {
      const re = /\b(when|whenever|if)\b[^.\n]{0,40}\b(the )?[`'"]?[a-z0-9_.-]+[`'"]? tool is (used|called|invoked)\b|\binstead of (using|calling) (the )?[`'"]?[a-z0-9_.-]+[`'"]?\b|\b(all|every|any) (other )?tools? (must|should)\b|\bthis tool (replaces|overrides|supersedes)\b|\b(change|modify|redirect) the (recipient|destination|address|to field)\b/i;
      return matchOf(re, text);
    },
  },
  {
    id: 'TP006',
    name: 'exfiltration-channel',
    severity: 'medium',
    title: 'Tool description embeds URLs or encoded data',
    fix: 'Check where the URL points and why a description needs it. Long encoded blobs are a common way to hide payloads.',
    test(text) {
      const url = /\bhttps?:\/\/[^\s"'<>)]+/i.exec(text);
      if (url && /\b(send|post|upload|forward|include|append|exfil|report|leak|transmit)\b/i.test(text)) return `${url[0]} (with send/upload wording)`;
      const b64 = /[A-Za-z0-9+/]{120,}={0,2}/.exec(text);
      if (b64) return `${b64[0].slice(0, 40)}… (${b64[0].length}-char encoded blob)`;
      return null;
    },
  },
  {
    id: 'TP007',
    name: 'oversized-description',
    severity: 'low',
    title: 'Unusually long tool description',
    fix: 'Very long descriptions consume context and are often used to bury instructions. Review the full text.',
    test(text, where) {
      if (where !== 'description') return null;
      return text.length > 1500 ? `${text.length} characters` : null;
    },
  },
  {
    id: 'TP008',
    name: 'secret-in-tool',
    severity: 'high',
    title: 'Tool metadata contains a credential',
    fix: 'The server is leaking a credential to every client and model that lists its tools. Report it to the maintainer.',
    test(text) {
      const hit = detectSecret(text);
      return hit ? `${hit.name}: ${redact(hit.match)}` : null;
    },
  },
];

function matchOf(re, text) {
  const m = re.exec(text);
  if (!m) return null;
  const start = Math.max(0, m.index - 20);
  const end = Math.min(text.length, m.index + m[0].length + 30);
  return `${start > 0 ? '…' : ''}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${end < text.length ? '…' : ''}`;
}

function decodeTagChars(text) {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out || null;
}

/** Accepts many shapes: a tools/list JSON-RPC response, {tools}, an array, or {server: {tools}}. */
export function extractTools(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data.filter((t) => t && typeof t === 'object' && 'name' in t).map((t) => ({ server: undefined, tool: t }));
  if (data.result) return extractTools(data.result);
  if (Array.isArray(data.tools)) return extractTools(data.tools);
  // map of server -> tools
  const out = [];
  for (const [server, v] of Object.entries(data)) {
    const list = Array.isArray(v) ? v : v && Array.isArray(v.tools) ? v.tools : v && v.result && Array.isArray(v.result.tools) ? v.result.tools : null;
    if (list) for (const t of list) if (t && typeof t === 'object') out.push({ server, tool: t });
  }
  return out;
}

/** Collect every human-readable string from a tool definition. */
function* textsOf(tool) {
  if (tool.name) yield { where: 'name', text: String(tool.name), pointer: 'name' };
  if (tool.title) yield { where: 'title', text: String(tool.title), pointer: 'title' };
  if (tool.description) yield { where: 'description', text: String(tool.description), pointer: 'description' };
  if (tool.annotations?.title) yield { where: 'annotations.title', text: String(tool.annotations.title), pointer: 'annotations/title' };
  const visit = function* (schema, p) {
    if (!schema || typeof schema !== 'object') return;
    if (typeof schema.description === 'string') yield { where: `${p}.description`, text: schema.description, pointer: `${p}/description` };
    if (typeof schema.title === 'string') yield { where: `${p}.title`, text: schema.title, pointer: `${p}/title` };
    if (schema.default !== undefined && typeof schema.default === 'string') yield { where: `${p}.default`, text: schema.default, pointer: `${p}/default` };
    if (Array.isArray(schema.enum)) for (const e of schema.enum) if (typeof e === 'string') yield { where: `${p}.enum`, text: e, pointer: `${p}/enum` };
    if (schema.properties) {
      for (const [k, v] of Object.entries(schema.properties)) {
        yield { where: `${p}.properties.${k}`, text: k, pointer: `${p}/properties/${k}`, isKey: true };
        yield* visit(v, `${p}/properties/${k}`);
      }
    }
    if (schema.items) yield* visit(schema.items, `${p}/items`);
  };
  yield* visit(tool.inputSchema || tool.input_schema || tool.parameters, 'inputSchema');
}

/**
 * Scan tool definitions.
 * @returns {import('./rules.js').Finding[]}
 */
export function scanTools(data, file = '<stdin>') {
  const findings = [];
  const tools = extractTools(data);
  const names = new Map();
  tools.forEach(({ server, tool }, idx) => {
    const label = `${server ? `${server}/` : ''}${tool.name ?? `#${idx}`}`;
    const seen = new Set();
    for (const t of textsOf(tool)) {
      for (const rule of TOOL_RULES) {
        if (seen.has(rule.id)) continue;
        // parameter names are only checked for invisible chars and suspicious names
        if (t.isKey && !['TP004', 'TP003'].includes(rule.id)) continue;
        const ev = rule.test(t.text, t.where);
        if (!ev) continue;
        seen.add(rule.id);
        findings.push({
          ruleId: rule.id,
          rule: rule.name,
          severity: rule.severity,
          title: rule.title,
          message: `${rule.title} (in ${t.where})`,
          evidence: ev,
          fix: rule.fix,
          server: label,
          file,
          pointer: `/tools/${idx}/${t.pointer}`,
          line: 1,
        });
      }
    }
    // suspicious parameter names commonly used to smuggle context out
    const props = Object.keys((tool.inputSchema || tool.input_schema || tool.parameters || {}).properties || {});
    const smuggle = props.filter((p) => /^(sidenote|side_note|notes?_for_(ai|model)|context|conversation(_history)?|system_prompt|chat_history|previous_messages|user_secrets?|feedback_for_ai)$/i.test(p));
    if (smuggle.length) {
      findings.push({
        ruleId: 'TP009',
        rule: 'context-smuggling-parameter',
        severity: 'medium',
        title: 'Tool requests conversation or system context as a parameter',
        message: `Parameter${smuggle.length > 1 ? 's' : ''} ${smuggle.join(', ')} could be used to exfiltrate the conversation`,
        evidence: smuggle.join(', '),
        fix: 'Check why the tool needs this. Malicious tools ask the model to fill such fields with chat history or secrets.',
        server: label,
        file,
        pointer: `/tools/${idx}/inputSchema/properties`,
        line: 1,
      });
    }
    const n = String(tool.name || '');
    if (!names.has(n)) names.set(n, []);
    names.get(n).push(label);
  });
  for (const [n, labels] of names) {
    const servers = new Set(labels.map((l) => l.split('/')[0]));
    if (labels.length > 1 && servers.size > 1) {
      findings.push({
        ruleId: 'TP010',
        rule: 'tool-name-collision',
        severity: 'medium',
        title: 'Same tool name exposed by multiple servers',
        message: `Tool "${n}" is exposed by ${labels.length} servers – a later server can shadow an earlier one`,
        evidence: labels.join(', '),
        fix: 'Rename or disable one of the conflicting tools.',
        server: labels[0],
        file,
        pointer: '/tools',
        line: 1,
      });
    }
  }
  return { findings, toolCount: tools.length };
}

export const ALL_TOOL_RULES = [
  ...TOOL_RULES,
  { id: 'TP009', name: 'context-smuggling-parameter', severity: 'medium', title: 'Tool requests conversation or system context as a parameter' },
  { id: 'TP010', name: 'tool-name-collision', severity: 'medium', title: 'Same tool name exposed by multiple servers' },
];
