/**
 * Secret detection: provider-specific token formats plus an entropy-based
 * fallback for values stored under sensitive-looking keys.
 */

/** @type {{id: string, name: string, re: RegExp, severity: 'critical'|'high'|'medium'}[]} */
export const SECRET_PATTERNS = [
  { id: 'private-key', name: 'Private key', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/, severity: 'critical' },
  { id: 'anthropic', name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/, severity: 'critical' },
  { id: 'openai', name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/, severity: 'critical' },
  { id: 'github-pat', name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, severity: 'critical' },
  { id: 'github-fine', name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{50,}/, severity: 'critical' },
  { id: 'gitlab', name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/, severity: 'critical' },
  { id: 'aws-access-key', name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, severity: 'critical' },
  { id: 'slack', name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/, severity: 'critical' },
  { id: 'stripe-live', name: 'Stripe live key', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}/, severity: 'critical' },
  { id: 'stripe-test', name: 'Stripe test key', re: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}/, severity: 'medium' },
  { id: 'google-api', name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'critical' },
  { id: 'huggingface', name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/, severity: 'critical' },
  { id: 'npm', name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/, severity: 'critical' },
  { id: 'supabase', name: 'Supabase access token', re: /\bsbp_[a-f0-9]{40}\b/, severity: 'critical' },
  { id: 'notion', name: 'Notion integration token', re: /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}/, severity: 'critical' },
  { id: 'linear', name: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{40}\b/, severity: 'critical' },
  { id: 'groq', name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}/, severity: 'critical' },
  { id: 'xai', name: 'xAI API key', re: /\bxai-[A-Za-z0-9]{50,}/, severity: 'critical' },
  { id: 'perplexity', name: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{40,}/, severity: 'critical' },
  { id: 'sendgrid', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, severity: 'critical' },
  { id: 'twilio', name: 'Twilio API key', re: /\bSK[0-9a-f]{32}\b/, severity: 'high' },
  { id: 'digitalocean', name: 'DigitalOcean token', re: /\bdop_v1_[a-f0-9]{64}\b/, severity: 'critical' },
  { id: 'figma', name: 'Figma token', re: /\bfigd_[A-Za-z0-9_-]{40,}/, severity: 'critical' },
  { id: 'jwt', name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high' },
  { id: 'conn-string', name: 'Connection string with password', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]+)@[^\s]+/i, severity: 'high' },
];

const SENSITIVE_KEY = /(api[_-]?key|apikey|token|secret|passw(or)?d|passwd|\bpwd\b|credential|private[_-]?key|auth|access[_-]?key|client[_-]?secret|session|cookie|bearer)/i;

/** True when a value is an obvious placeholder or an environment reference. */
export function isPlaceholder(value) {
  const v = String(value).trim();
  if (!v) return true;
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_:.\-]*\}?$/.test(v)) return true; // $VAR, ${VAR}, ${env:VAR}, ${input:x}
  if (/^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true; // %VAR%
  if (/^\{\{.*\}\}$/.test(v)) return true; // {{ secret }}
  if (/^<.*>$/.test(v) || /^\[.*\]$/.test(v)) return true;
  // placeholder words only count as whole words (so random tokens that happen
  // to contain "todo" or "your" are still detected as secrets)
  if (/(^|[^a-z0-9])(your|my|xxx+|changeme|change_me|example|placeholder|replace(_?me)?|dummy|redacted|insert|todo|fixme|secret_here|key_here|token_here|here)([^a-z0-9]|$)/i.test(v)) return true;
  if (/^(your|my)[_-]?(api[_-]?)?(key|token|secret|password)/i.test(v)) return true;
  if (/\*{3,}|\.\.\./.test(v)) return true;
  if (/^(.)\1+$/.test(v)) return true;
  if (/^(true|false|null|none|yes|no|\d+)$/i.test(v)) return true;
  return false;
}

export function shannonEntropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Redact a secret for display: keep a short prefix and the length. */
export function redact(secret) {
  const s = String(secret);
  if (s.length <= 8) return '*'.repeat(s.length);
  const keep = Math.min(6, Math.floor(s.length / 4));
  return `${s.slice(0, keep)}…(${s.length} chars)`;
}

/**
 * Inspect a value for secrets.
 * @param {string} value
 * @param {string} [keyName] the env/header/flag name the value is stored under
 * @returns {{kind: string, name: string, severity: string, match: string} | null}
 */
export function detectSecret(value, keyName = '') {
  if (value === undefined || value === null) return null;
  const v = String(value);
  for (const p of SECRET_PATTERNS) {
    const m = p.re.exec(v);
    if (!m) continue;
    if (p.id === 'conn-string') {
      const pwd = m[1];
      if (isPlaceholder(pwd) || /^\$|^%/.test(pwd)) continue;
    }
    if (isPlaceholder(m[0])) continue;
    return { kind: p.id, name: p.name, severity: p.severity, match: m[0] };
  }

  // Bearer / Basic auth header values
  const auth = /^(?:bearer|basic|token)\s+(\S+)$/i.exec(v.trim());
  if (auth && !isPlaceholder(auth[1]) && auth[1].length >= 12) {
    return { kind: 'auth-header', name: 'Hard-coded authorization credential', severity: 'high', match: auth[1] };
  }

  if (keyName && SENSITIVE_KEY.test(keyName) && !/(_url|_uri|_path|_file|_dir|_endpoint|_host|_region|_id|_name|_user(name)?|_type|_mode)$/i.test(keyName)) {
    const t = v.trim();
    if (!isPlaceholder(t) && t.length >= 12 && !/\s/.test(t) && !/^(https?|file):\/\//i.test(t) && !/^[./~]/.test(t) && shannonEntropy(t) >= 3.0) {
      return { kind: 'generic', name: `Hard-coded value for sensitive key "${keyName}"`, severity: 'high', match: t };
    }
  }
  return null;
}

export { SENSITIVE_KEY };
