import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Write a file atomically: write to a temp file in the same directory, then
 * rename over the target. Readers never observe a half-written lock file,
 * baseline or report, even if the process is interrupted.
 */
export function writeFileAtomic(file, data, { mode } = {}) {
  const dir = path.dirname(path.resolve(file));
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, data, { mode, flag: 'wx' });
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw e;
  }
}
