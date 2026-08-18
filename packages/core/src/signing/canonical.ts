/**
 * Canonical JSON for signature payloads.
 * 簽章載荷的正規化 JSON。
 *
 * Same semantics as the guard audit chain's canonicalize (deep key sort after a
 * JSON normalization pass) so "canonical" means one thing across the product:
 * first normalize through JSON (parse(stringify(value))) so values with a
 * custom toJSON (Date, Buffer, ...) and `undefined` fields are reduced to the
 * PLAIN JSON form a reader sees after JSON.parse, then rebuild with object keys
 * sorted at every depth. Array order is meaningful and preserved.
 *
 * This intentionally does NOT use `JSON.stringify(value, keysArray)`: a replacer
 * ARRAY filters keys at every depth, which silently drops nested content from
 * the serialization — a signature over that output would cover only the
 * top-level skeleton of the document.
 */
export function canonicalJson(value: unknown): string {
  const json = JSON.stringify(value);
  if (json === undefined) return JSON.stringify(null);
  const normalized: unknown = JSON.parse(json);
  return JSON.stringify(sortDeep(normalized));
}

/**
 * Recursively rebuild an already-JSON-normalized value with object keys sorted.
 * Primitives pass through. Arrays recurse element-wise (order preserved).
 */
function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortDeep(item));
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortDeep(obj[key]);
    }
    return sorted;
  }
  return value;
}
