/**
 * Options renamed in a major release, by their old name. A caller upgrading
 * with the old name would otherwise drop the check it asked for and still
 * pass.
 */
const RENAMED: Readonly<Record<string, string>> = {
  requireOutOfBandKeys: 'requireSuppliedKeys',
};

/**
 * Throw `TypeError` on an options object that is not an object, or that
 * carries a key `fn` does not read. A misspelt or renamed option that is
 * dropped without a word switches off the check it named, and the result
 * passes as if it had run.
 */
export function assertKnownOptions(fn: string, options: unknown, known: readonly string[]): void {
  if (options === undefined) return;
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError(`${fn}: options must be an object.`);
  }
  for (const key of Object.keys(options)) {
    if (known.includes(key)) continue;
    const renamed = RENAMED[key];
    throw new TypeError(
      renamed !== undefined && known.includes(renamed)
        ? `${fn}: the ${key} option is now ${renamed}; pass ${renamed} instead. It was renamed in 2.0.0, and an unknown option is refused rather than ignored.`
        : `${fn}: unknown option ${key}. It reads ${known.join(', ')}.`,
    );
  }
}
