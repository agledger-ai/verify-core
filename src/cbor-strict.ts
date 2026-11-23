import type { DecodeOptions } from 'cborg';

/**
 * Decode options for every CBOR value this package reads. The signed bytes
 * are deterministic CBOR (RFC 8949 section 4.2.1), so anything a conforming
 * encoder would not emit is refused rather than tolerated: duplicate map
 * keys (two readers could take different values), non-minimal integer and
 * length encodings, indefinite lengths, `undefined`, and invalid UTF-8.
 */
export const STRICT_CBOR_DECODE: Pick<DecodeOptions, 'strict' | 'allowIndefinite' | 'allowUndefined' | 'rejectDuplicateMapKeys' | 'rejectInvalidUtf8'> = {
  strict: true,
  allowIndefinite: false,
  allowUndefined: false,
  rejectDuplicateMapKeys: true,
  rejectInvalidUtf8: true,
};
