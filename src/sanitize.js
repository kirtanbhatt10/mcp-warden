/**
 * Output sanitization.
 *
 * Everything mcp-warden prints can originate from an attacker: tool
 * descriptions come from (possibly malicious) MCP servers, and config values
 * can come from a cloned repository. Printing them raw would let an attacker
 * inject terminal escape sequences (rewrite or hide findings, change the
 * window title, emit hyperlinks) or bidi/zero-width characters that make the
 * output lie. These helpers make untrusted text inert and visible.
 */

// C0 controls (except \t and \n, handled separately), DEL, C1 controls.
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
// Bidi controls, zero-width characters, BOM, line/paragraph separators.
const INVISIBLE = /[\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/g;
// Unicode tag characters (used for ASCII smuggling).
const TAGS = /[\u{E0000}-\u{E007F}]/gu;

const hex = (ch) => {
  const cp = ch.codePointAt(0);
  return cp > 0xffff ? `\\u{${cp.toString(16).toUpperCase()}}` : `\\u${cp.toString(16).toUpperCase().padStart(4, '0')}`;
};

/**
 * Make a string safe to print on a single terminal line.
 * Control, bidi, zero-width and tag characters are shown as \uXXXX escapes;
 * tabs and newlines become visible "\t" / "\n".
 */
export function safeInline(value, maxLength = 500) {
  if (value === undefined || value === null) return '';
  let s = String(value)
    .replace(/\r\n|\r|\n/g, '\\n')
    .replace(/\t/g, '\\t')
    .replace(CONTROL, hex)
    .replace(INVISIBLE, hex)
    .replace(TAGS, hex);
  if (s.length > maxLength) s = `${s.slice(0, maxLength - 1)}…`;
  return s;
}

/** Like safeInline but keeps real newlines (for multi-line error output). */
export function safeMultiline(value, maxLength = 4000) {
  if (value === undefined || value === null) return '';
  let s = String(value)
    .replace(/\r\n|\r/g, '\n')
    .replace(/\t/g, '  ')
    .replace(CONTROL, hex)
    .replace(INVISIBLE, hex)
    .replace(TAGS, hex);
  if (s.length > maxLength) s = `${s.slice(0, maxLength - 1)}…`;
  return s;
}

/** Escape text for a GitHub-flavoured Markdown table cell (no HTML, no table breaks). */
export function mdCell(value, maxLength = 300) {
  return safeInline(value, maxLength)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;')
    .replace(/`/g, '&#96;')
    .replace(/([*_~[\]\\])/g, '\\$1')
    .replace(/@/g, '@\u200B'); // don't ping users from untrusted content
}

/** Escape text for inline HTML <code> in Markdown. */
export function mdCode(value, maxLength = 300) {
  return safeInline(value, maxLength)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;')
    .replace(/@/g, '@\u200B');
}
