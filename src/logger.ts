/**
 * Minimal structured logger.
 *
 * Writes JSON lines to stdout (info) and stderr (warn / error).
 * Each entry includes an ISO-8601 timestamp and a level tag.
 */

function fmt(level: string, msg: string, extra?: Record<string, unknown>): string {
  const entry: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...extra,
  };
  return JSON.stringify(entry);
}

export const log = {
  info(msg: string, extra?: Record<string, unknown>): void {
    process.stdout.write(fmt('info', msg, extra) + '\n');
  },
  warn(msg: string, extra?: Record<string, unknown>): void {
    process.stderr.write(fmt('warn', msg, extra) + '\n');
  },
  error(msg: string, extra?: Record<string, unknown>): void {
    process.stderr.write(fmt('error', msg, extra) + '\n');
  },
};
