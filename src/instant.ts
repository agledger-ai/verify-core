/** RFC 3339 date-time: a `T`, a numeric offset or `Z`, any fraction. */
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$/;

/**
 * Milliseconds of an RFC 3339 instant, truncating any finer fraction the way
 * the engine reads a microsecond instant (its `instantToDate`). Key statements
 * sign microsecond instants; entry write times, dump columns and key documents
 * carry milliseconds, so every comparison between them is made here. NaN when
 * the string does not parse. A string that is not RFC 3339 falls back to
 * `Date.parse`, for key windows a caller supplies; a write time the walk
 * places goes through {@link rfc3339Ms}, which does not.
 */
export function instantMs(instant: string): number {
  const strict = rfc3339Ms(instant);
  return Number.isNaN(strict) ? Date.parse(instant) : strict;
}

/**
 * Milliseconds of a strict RFC 3339 instant (an offset or `Z`, a real calendar
 * date and time of day), truncating any finer fraction. NaN for anything
 * else, so a write time is never placed by how the host reads a date with no
 * offset, a space separator or an impossible day.
 */
export function rfc3339Ms(instant: string): number {
  return parse(instant)?.ms ?? Number.NaN;
}

function parse(instant: unknown): { ms: number; frac: string } | null {
  if (typeof instant !== 'string') return null;
  const m = RFC3339.exec(instant);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac = '', zone, sign, oh, om] = m;
  if (Number(h) > 23 || Number(mi) > 59 || Number(s) > 59) return null;
  if (sign !== undefined && (Number(oh) > 23 || Number(om) > 59)) return null;
  const fields = `${y}-${mo}-${d}T${h}:${mi}:${s}`;
  const local = Date.parse(`${fields}Z`);
  // Date.parse rolls an impossible date over (February 30 reads as March 2).
  if (Number.isNaN(local) || !new Date(local).toISOString().startsWith(fields)) return null;
  const offset = zone === 'Z' || zone === 'z' ? 0 : (sign === '-' ? -1 : 1) * (Number(oh) * 60 + Number(om)) * 60_000;
  return { ms: local + Number(frac.slice(0, 3).padEnd(3, '0')) - offset, frac };
}

/**
 * Microseconds of a strict RFC 3339 instant, and whether it carries a full
 * microsecond fraction. The key surfaces publish a statement's write time at
 * microsecond precision and a dump at milliseconds, so two dump rows in one
 * millisecond tie here without being simultaneous. NaN when the string is not
 * strict RFC 3339 (see {@link rfc3339Ms}).
 */
export function instantUs(instant: string): { us: number; micro: boolean } {
  const p = parse(instant);
  if (p === null) return { us: Number.NaN, micro: false };
  return { us: p.ms * 1000 + Number(p.frac.slice(3, 6).padEnd(3, '0')), micro: p.frac.length >= 6 };
}
