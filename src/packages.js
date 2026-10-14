/**
 * Package-runner analysis: works out which package an MCP server launches
 * (npx, bunx, pnpm dlx, yarn dlx, uvx, pipx run, docker run) and whether it
 * is pinned.
 */

const NODE_RUNNERS = new Set(['npx', 'bunx']);
const DLX_RUNNERS = new Set(['pnpm', 'yarn', 'bun']); // pnpm dlx, yarn dlx, bun x
const PY_RUNNERS = new Set(['uvx']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'powershell', 'pwsh']);

export function baseCommand(cmd = '') {
  const b = String(cmd).split(/[\\/]/).pop().toLowerCase();
  return b.replace(/\.(cmd|exe|bat|ps1)$/, '');
}

/**
 * Unwrap Windows `cmd /c npx ...` and `sudo`/`env` style wrappers so
 * analysis sees the real launcher.
 */
export function effectiveCommand(command, args = []) {
  let cmd = baseCommand(command);
  let rest = [...args];
  for (let guard = 0; guard < 4; guard++) {
    if (cmd === 'cmd' && rest[0] && /^\/c$/i.test(rest[0]) && rest[1]) {
      // `cmd /c npx -y pkg` – only unwrap when it's a simple command, not a shell string
      if (/[|&;<>]/.test(rest.slice(1).join(' '))) break;
      cmd = baseCommand(rest[1]);
      rest = rest.slice(2);
      continue;
    }
    if ((cmd === 'sudo' || cmd === 'doas') && rest[0]) {
      while (rest[0] && rest[0].startsWith('-')) rest = rest.slice(1);
      if (!rest[0]) break;
      cmd = baseCommand(rest[0]);
      rest = rest.slice(1);
      continue;
    }
    if (cmd === 'env' && rest.length) {
      while (rest[0] && (rest[0].includes('=') || rest[0].startsWith('-'))) rest = rest.slice(1);
      if (!rest[0]) break;
      cmd = baseCommand(rest[0]);
      rest = rest.slice(1);
      continue;
    }
    break;
  }
  return { cmd, args: rest };
}

export function isShell(cmd) {
  return SHELLS.has(baseCommand(cmd));
}

/**
 * Identify the package launched by a server.
 * @returns {null | {ecosystem: 'npm'|'pypi'|'docker', runner: string, spec: string, name: string, version: string|null, pinned: boolean, reason?: string, autoYes: boolean, dockerArgs?: string[]}}
 */
export function analyzeLaunch(command, args = []) {
  const { cmd, args: a } = effectiveCommand(command, args);

  if (NODE_RUNNERS.has(cmd) || (DLX_RUNNERS.has(cmd) && (a[0] === 'dlx' || (cmd === 'bun' && a[0] === 'x')))) {
    const list = NODE_RUNNERS.has(cmd) ? a : a.slice(1);
    const runner = NODE_RUNNERS.has(cmd) ? cmd : `${cmd} ${a[0]}`;
    let spec = null;
    let autoYes = false;
    for (let i = 0; i < list.length; i++) {
      const x = list[i];
      if (x === '-y' || x === '--yes') { autoYes = true; continue; }
      if (x === '-p' || x === '--package') { spec = list[i + 1]; i++; continue; }
      if (x.startsWith('--package=')) { spec = x.slice('--package='.length); continue; }
      if (x === '--') continue;
      if (x.startsWith('-')) continue;
      if (!spec) spec = x;
      break;
    }
    if (!spec) return null;
    return { ecosystem: 'npm', runner, autoYes, ...parseNpmSpec(spec) };
  }

  if (PY_RUNNERS.has(cmd) || (cmd === 'pipx' && a[0] === 'run') || (cmd === 'uv' && a[0] === 'tool' && a[1] === 'run')) {
    let list = a;
    let runner = cmd;
    if (cmd === 'pipx') { list = a.slice(1); runner = 'pipx run'; }
    if (cmd === 'uv') { list = a.slice(2); runner = 'uv tool run'; }
    let spec = null;
    let from = null;
    for (let i = 0; i < list.length; i++) {
      const x = list[i];
      if (x === '--from' || x === '--spec') { from = list[i + 1]; i++; continue; }
      if (x.startsWith('--from=')) { from = x.slice(7); continue; }
      if (['--with', '--python', '-p', '--index-url', '--index', '--extra-index-url', '--directory'].includes(x)) { i++; continue; }
      if (x.startsWith('-')) continue;
      spec = x;
      break;
    }
    const s = from || spec;
    if (!s) return null;
    return { ecosystem: 'pypi', runner, autoYes: true, ...parsePySpec(s) };
  }

  if ((cmd === 'docker' || cmd === 'podman') && a[0] === 'run') {
    const image = findDockerImage(a.slice(1));
    if (!image) return null;
    return { ecosystem: 'docker', runner: `${cmd} run`, autoYes: true, dockerArgs: a.slice(1, image.index + 1), ...parseImage(image.name) };
  }

  return null;
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseNpmSpec(spec) {
  if (/^(\.|\/|~|[A-Za-z]:\\|file:)/.test(spec)) {
    return { spec, name: spec, version: null, pinned: true, reason: 'local path' };
  }
  if (/^(github:|git\+|git:|https?:\/\/|[\w.-]+\/[\w.-]+#)/.test(spec) || /^[\w.-]+\/[\w.-]+$/.test(spec) && !spec.startsWith('@')) {
    const hasSha = /#[0-9a-f]{40}$/i.test(spec);
    return { spec, name: spec.replace(/#.*$/, ''), version: hasSha ? spec.split('#').pop() : null, pinned: hasSha, reason: hasSha ? undefined : 'git dependency without a commit SHA' };
  }
  let name = spec;
  let version = null;
  const at = spec.lastIndexOf('@');
  if (at > 0) {
    name = spec.slice(0, at);
    version = spec.slice(at + 1);
  }
  const pinned = version !== null && EXACT_SEMVER.test(version);
  let reason;
  if (!pinned) reason = version === null ? 'no version specified' : version === 'latest' ? 'pinned to the mutable "latest" tag' : `version range "${version}" is not exact`;
  return { spec, name, version, pinned, reason };
}

export function parsePySpec(spec) {
  if (/^(\.|\/|~|git\+|https?:\/\/|file:)/.test(spec)) {
    const hasSha = /@[0-9a-f]{40}$/i.test(spec);
    const local = /^(\.|\/|~|file:)/.test(spec);
    return { spec, name: spec, version: null, pinned: local || hasSha, reason: local || hasSha ? undefined : 'VCS/URL source without a commit SHA' };
  }
  let m = /^([A-Za-z0-9_.\-\[\],]+?)\s*==\s*([^\s;,]+)$/.exec(spec);
  if (m) return { spec, name: m[1], version: m[2], pinned: true };
  m = /^([A-Za-z0-9_.\-\[\],]+?)@([^\s]+)$/.exec(spec);
  if (m) {
    const pinned = /^\d+(\.\d+)*([abrc.post-]+\d*)?$/.test(m[2]);
    return { spec, name: m[1], version: m[2], pinned, reason: pinned ? undefined : `version "${m[2]}" is not exact` };
  }
  m = /^([A-Za-z0-9_.\-\[\],]+?)\s*([<>=~!]{1,2}.*)$/.exec(spec);
  if (m) return { spec, name: m[1], version: m[2], pinned: false, reason: `version range "${m[2]}" is not exact` };
  return { spec, name: spec, version: null, pinned: false, reason: 'no version specified' };
}

const DOCKER_VALUE_FLAGS = new Set([
  '-e', '--env', '-v', '--volume', '--name', '-p', '--publish', '--network', '--net', '--mount', '-w', '--workdir',
  '-u', '--user', '--entrypoint', '--env-file', '--platform', '--cap-add', '--cap-drop', '-l', '--label', '--pid',
  '--memory', '-m', '--cpus', '--add-host', '--device', '--security-opt', '--ulimit', '--restart', '-h', '--hostname',
  '--ipc', '--runtime', '--tmpfs', '--log-driver', '--log-opt', '--uts', '--userns', '--cgroupns', '--expose',
  '--gpus', '--shm-size', '--stop-signal', '--health-cmd', '--pull', '--dns', '--label-file', '--group-add',
]);

export function findDockerImage(args) {
  for (let i = 0; i < args.length; i++) {
    const x = args[i];
    if (x === '--') continue;
    if (x.startsWith('--') && x.includes('=')) continue;
    if (DOCKER_VALUE_FLAGS.has(x)) { i++; continue; }
    if (x.startsWith('-')) continue;
    return { name: x, index: i };
  }
  return null;
}

export function parseImage(image) {
  if (image.includes('@sha256:')) {
    return { spec: image, name: image.split('@')[0], version: image.split('@')[1], pinned: true };
  }
  const lastSlash = image.lastIndexOf('/');
  const colon = image.indexOf(':', lastSlash + 1);
  const name = colon === -1 ? image : image.slice(0, colon);
  const tag = colon === -1 ? null : image.slice(colon + 1);
  if (!tag) return { spec: image, name, version: null, pinned: false, reason: 'no tag (defaults to "latest")' };
  if (tag === 'latest' || tag === 'main' || tag === 'master' || tag === 'edge' || tag === 'nightly') {
    return { spec: image, name, version: tag, pinned: false, reason: `mutable tag "${tag}"` };
  }
  return { spec: image, name, version: tag, pinned: true, digestPinned: false };
}
