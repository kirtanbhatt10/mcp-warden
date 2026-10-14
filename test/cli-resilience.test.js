import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { writeFileAtomic } from '../src/fsutil.js';
import { checkLock } from '../src/lock.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcp-warden.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mw-cli-'));
const cli = (args, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' }, ...opts });

describe('CLI resilience', () => {
  test('closing stdout early (| head) exits cleanly', { skip: process.platform === 'win32' }, () => {
    const r = spawnSync('sh', ['-c', `"${process.execPath}" "${bin}" rules | head -n 1`], { encoding: 'utf8' });
    assert.equal(r.status, 0);
    assert.ok(!/EPIPE|Error:/.test(r.stderr), r.stderr);
  });

  test('--update-lock without --lock is a usage error', () => {
    const r = cli(['tools', path.join(root, 'examples', 'tools', 'poisoned-tools.json'), '--update-lock']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /requires --lock/);
  });

  test('a corrupt lock file is never silently replaced', () => {
    const dir = tmp();
    const lock = path.join(dir, 'tools.lock.json');
    fs.writeFileSync(lock, '{ corrupted');
    const r = cli(['tools', path.join(root, 'examples', 'tools', 'poisoned-tools.json'), '--lock', lock]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /refusing to overwrite/);
    assert.equal(fs.readFileSync(lock, 'utf8'), '{ corrupted');
    assert.throws(() => checkLock([], lock), /refusing/);
  });

  test('invalid --timeout values are rejected', () => {
    assert.equal(cli(['inspect', '--timeout', '-5', '--', 'node']).status, 2);
    assert.equal(cli(['inspect', '--timeout', 'abc', '--', 'node']).status, 2);
  });

  test('unreadable baseline is a clear runtime error (exit 2)', () => {
    const r = cli(['scan', path.join(root, 'examples', 'safe'), '--no-discover', '--baseline', path.join(tmp(), 'nope.json')]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /cannot read baseline/);
  });
});

describe('atomic writes', () => {
  test('replace content and leave no temp files behind', () => {
    const dir = tmp();
    const f = path.join(dir, 'out.json');
    writeFileAtomic(f, 'one');
    writeFileAtomic(f, 'two');
    assert.equal(fs.readFileSync(f, 'utf8'), 'two');
    assert.deepEqual(fs.readdirSync(dir), ['out.json']);
  });
  test('failures clean up and propagate', () => {
    assert.throws(() => writeFileAtomic(path.join(tmp(), 'missing-dir', 'x.json'), 'x'));
  });
});
