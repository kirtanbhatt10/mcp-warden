/**
 * Reference data for supply-chain checks. Contributions welcome — keep the
 * lists sorted and cite a source in the PR.
 */

/** Well-known, legitimate MCP server packages that attackers like to imitate. */
export const POPULAR_PACKAGES = [
  // Reference servers (github.com/modelcontextprotocol/servers)
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/inspector',
  'mcp-server-fetch',
  'mcp-server-git',
  'mcp-server-time',
  // Popular vendor / community servers
  '@playwright/mcp',
  '@upstash/context7-mcp',
  '@notionhq/notion-mcp-server',
  '@supabase/mcp-server-supabase',
  '@sentry/mcp-server',
  '@stripe/mcp',
  '@browsermcp/mcp',
  '@cloudflare/mcp-server-cloudflare',
  '@heroku/mcp-server',
  '@azure/mcp',
  '@railway/mcp-server',
  '@vercel/mcp-adapter',
  '@mongodb-js/mongodb-mcp-server',
  '@neondatabase/mcp-server-neon',
  '@shopify/dev-mcp',
  '@agentdeskai/browser-tools-mcp',
  'chrome-devtools-mcp',
  'figma-developer-mcp',
  'firecrawl-mcp',
  'exa-mcp-server',
  'tavily-mcp',
  'mcp-remote',
  'awslabs.aws-documentation-mcp-server',
  'awslabs.core-mcp-server',
];

/**
 * Reference servers that were moved to modelcontextprotocol/servers-archived
 * and no longer receive security fixes.
 */
export const ARCHIVED_PACKAGES = {
  '@modelcontextprotocol/server-aws-kb-retrieval': null,
  '@modelcontextprotocol/server-brave-search': 'Brave\'s official server (@brave/brave-search-mcp-server)',
  '@modelcontextprotocol/server-everart': null,
  '@modelcontextprotocol/server-gdrive': null,
  '@modelcontextprotocol/server-github': 'GitHub\'s official server (github/github-mcp-server)',
  '@modelcontextprotocol/server-gitlab': null,
  '@modelcontextprotocol/server-google-maps': null,
  '@modelcontextprotocol/server-postgres': 'a maintained Postgres MCP server (pin a version)',
  '@modelcontextprotocol/server-puppeteer': 'Microsoft\'s @playwright/mcp',
  '@modelcontextprotocol/server-redis': 'Redis\' official server (redis/mcp-redis)',
  '@modelcontextprotocol/server-sentry': 'Sentry\'s official server (@sentry/mcp-server)',
  '@modelcontextprotocol/server-slack': null,
  '@modelcontextprotocol/server-sqlite': null,
  'mcp-server-sqlite': null,
  'mcp-server-sentry': 'Sentry\'s official server (@sentry/mcp-server)',
};

/** Scopes that are frequently impersonated. */
export const TRUSTED_SCOPES = ['@modelcontextprotocol', '@anthropic-ai', '@playwright', '@upstash', '@notionhq', '@supabase', '@cloudflare', '@stripe', '@sentry', '@microsoft', '@azure', '@github'];

/**
 * Known-vulnerable or malicious MCP packages.
 * `fixed` = first safe version; `malicious` = never install.
 */
export const KNOWN_VULNERABLE = [
  { name: 'mcp-remote', fixed: '0.1.16', id: 'CVE-2025-6514', severity: 'critical', summary: 'OS command injection via a malicious server\'s OAuth authorization_endpoint' },
  { name: '@modelcontextprotocol/inspector', fixed: '0.14.1', id: 'CVE-2025-49596', severity: 'critical', summary: 'unauthenticated RCE via the Inspector proxy (DNS rebinding / CSRF)' },
  { name: 'postmark-mcp', malicious: true, id: 'MAL-2025-postmark-mcp', severity: 'critical', summary: 'unofficial package that silently BCC\'d every sent email to an attacker-controlled address' },
];
