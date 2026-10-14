import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { minimalEnv, escapeArgument, resolveWindowsCommand } from '../src/spawn.js';
import { inspectStdio } from '../src/inspect.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const demo = path.join(root, 'examples', 'servers', 'demo-server.js');

describe('minimal environment', () => {
  test('keeps only the allow-list plus explicit variables', () => {
    const env = minimalEnv({ API_KEY: 'given' }, { platform: 'linux', source: { PATH: '/bin', HOME: '/h', AWS_SECRET_ACCESS_KEY: 's', GITHUB_TOKEN: 't', BASH_FUNC_x: '() { :; }' } });
    assert.deepEqual(env, { PATH: '/bin', HOME: '/h', API_KEY: 'given' });
  });
  test('Windows lookup is case-insensitive', () => {
    const env = minimalEnv({}, { platform: 'win32', source: { Path: 'C:\\\\bin', SystemRoot: 'C:\\\\Windows', OPENAI_API_KEY: 'x' } });
    assert.deepEqual(Object.keys(env).sort(), ['Path', 'SystemRoot']);
  });
  test('inherit mode passes everything', () => {
    assert.equal(minimalEnv({}, { inherit: true, source: { A: '1' } }).A, '1');
  });
});

describe('cmd.exe argument escaping', () => {
  test('metacharacters are caret-escaped inside quotes', () => {
    assert.equal(escapeArgument('a&b'), '^"a^&b^"');
    assert.equal(escapeArgument('x|y>z'), '^"x^|y^>z^"');
    assert.equal(escapeArgument('say "hi"'), '^"say^ \\^"hi\\^"^"');
  });
  test('trailing backslashes are doubled', () => {
    assert.equal(escapeArgument('C:\\dir\\'), '^"C:\\dir\\\\^"');
  });
  test('shims get double escaping', () => {
    assert.equal(escapeArgument('&', true), '^^^"^^^&^^^"');
  });
  test('resolveWindowsCommand finds .cmd shims via PATHEXT', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mw-path-'));
    fs.writeFileSync(path.join(dir, 'tool.cmd'), '@echo off');
    assert.equal(resolveWindowsCommand('tool', { PATH: dir, PATHEXT: '.EXE;.CMD' }), path.join(dir, 'tool.cmd'));
    assert.equal(resolveWindowsCommand('missing', { PATH: dir, PATHEXT: '.EXE;.CMD' }), null);
  });
});

describe('no shell injection through arguments', () => {
  test('metacharacters in args reach the server verbatim and run nothing', { timeout: 30000 }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mw-inject-'));
    const marker = path.join(dir, 'pwned.txt');
    const evil = process.platform === 'win32' ? `x & echo pwned > "${marker}"` : `x; echo pwned > '${marker}'`;
    let command = process.execPath;
    let args = [demo, evil];
    if (process.platform === 'win32') {
      // exercise the .cmd code path, which is where injection used to be possible
      const shim = path.join(dir, 'server.cmd');
      fs.writeFileSync(shim, `@"${process.execPath}" "${demo}" %*\r\n`);
      command = shim;
      args = [evil];
    }
    const res = await inspectStdio(command, args, { timeoutMs: 20000 });
    assert.equal(res.serverInfo.name, 'weather-demo');
    assert.equal(fs.existsSync(marker), false, 'shell metacharacters were executed');
  });
});
