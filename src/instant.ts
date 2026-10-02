/**
 * Milliseconds of an RFC 3339 instant, truncating any finer fraction the way
 * the engine reads a microsecond instant (its `instantToDate`). Key statements
 * sign microsecond instants; entry write times, dump columns and key documents
 * carry milliseconds, so every comparison between them is made here. NaN when
 * the string does not parse.
 */
export function instantMs(instant: string): number {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(instant);
  if (!m) return Date.parse(instant);
  const frac = (m[2] ?? '').slice(0, 3).padEnd(3, '0');
  return Date.parse(`${m[1]}.${frac}${m[3]}`);
}

/**
 * Microseconds of an RFC 3339 instant, and whether it carries a full
 * microsecond fraction. The key surfaces publish a statement's write time at
 * microsecond precision and a dump at milliseconds, so two dump rows in one
 * millisecond tie here without being simultaneous. NaN when the string does
 * not parse.
 */
export function instantUs(instant: string): { us: number; micro: boolean } {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(instant);
  const frac = m?.[2] ?? '';
  const ms = instantMs(instant);
  const sub = m ? Number(frac.slice(3, 6).padEnd(3, '0')) : 0;
  return { us: ms * 1000 + sub, micro: frac.length >= 6 };
}
