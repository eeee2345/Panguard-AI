/**
 * String-based SKILL.md manifest parser.
 *
 * Parses YAML frontmatter from raw content string.
 * No filesystem dependencies - caller is responsible for reading the file.
 */

import yaml from 'js-yaml';
import type { SkillManifest, SkillMetadata } from './types.js';

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

/**
 * Parse SKILL.md content string and extract manifest + instructions.
 *
 * @param content - Raw SKILL.md content
 * @param fallbackName - Name to use if no name field in frontmatter (e.g. directory name)
 */
export function parseManifestFromString(
  content: string,
  fallbackName: string = 'unknown'
): SkillManifest {
  const match = FRONTMATTER_RE.exec(content);
  if (!match) {
    // No frontmatter - treat entire content as instructions
    return {
      name: fallbackName,
      description: '',
      instructions: content,
    };
  }

  const [, frontmatterRaw, instructions] = match;

  let parsed: Record<string, unknown>;
  try {
    parsed =
      (yaml.load(frontmatterRaw ?? '', { schema: yaml.JSON_SCHEMA }) as Record<string, unknown>) ??
      {};
  } catch {
    return {
      name: fallbackName,
      description: '',
      instructions: instructions ?? content,
    };
  }

  // Parse metadata - can be a JSON string or an object
  let metadataRaw: unknown;
  if (typeof parsed['metadata'] === 'string') {
    try {
      metadataRaw = JSON.parse(parsed['metadata']);
    } catch {
      metadataRaw = undefined;
    }
  } else if (typeof parsed['metadata'] === 'object' && parsed['metadata'] !== null) {
    metadataRaw = parsed['metadata'];
  }
  const degraded: string[] = [];
  const metadata = normaliseMetadata(metadataRaw, degraded);

  const str = (key: string): string | undefined => {
    const coerced = coerceString(parsed[key]);
    if (coerced !== undefined && typeof parsed[key] !== 'string') degraded.push(key);
    return coerced;
  };

  const tools = coerceStringArray(parsed['allowed-tools']);
  if (tools !== undefined && !Array.isArray(parsed['allowed-tools']))
    degraded.push('allowed-tools');

  return {
    name: str('name') ?? fallbackName,
    description: str('description') ?? '',
    license: str('license'),
    homepage: str('homepage'),
    userInvocable: parsed['user-invocable'] as boolean | undefined,
    disableModelInvocation: parsed['disable-model-invocation'] as boolean | undefined,
    commandDispatch: str('command-dispatch'),
    commandTool: str('command-tool'),
    metadata,
    'allowed-tools': tools,
    instructions: instructions ?? '',
    ...(degraded.length > 0 ? { parseDegraded: degraded } : {}),
  };
}

/**
 * Normalise the metadata block's list-typed fields.
 *
 * Same lying-cast problem as the top-level fields, one level deeper and with a
 * nastier failure mode: `requires.env` is declared `readonly string[]`, so a
 * guard such as `requires.env.length > 0` passes for a plain string as well —
 * the throw only lands on the `.join()` after it. Real skills write
 * `env: SOME_TOKEN` and `env: A,B`, so both are accepted here.
 *
 * `metadata.openclaw` and a bare `metadata.requires` are both seen in the wild;
 * the bare form is lifted under `openclaw` so consumers have one path to read.
 */
function normaliseMetadata(value: unknown, degraded: string[]): SkillMetadata | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const raw = value as Record<string, unknown>;
  const openclawRaw = (raw['openclaw'] ?? raw['clawdbot']) as Record<string, unknown> | undefined;
  const nest =
    typeof openclawRaw === 'object' && openclawRaw !== null
      ? openclawRaw
      : ({} as Record<string, unknown>);
  const requiresRaw = (nest['requires'] ?? raw['requires']) as Record<string, unknown> | undefined;

  const listField = (source: Record<string, unknown>, key: string, label: string) => {
    const coerced = coerceStringArray(source[key]);
    if (coerced === undefined) return {};
    if (!Array.isArray(source[key])) degraded.push(label);
    return { [key]: coerced };
  };

  const requires =
    typeof requiresRaw === 'object' && requiresRaw !== null
      ? {
          ...listField(requiresRaw, 'bins', 'metadata.requires.bins'),
          ...listField(requiresRaw, 'env', 'metadata.requires.env'),
          ...listField(requiresRaw, 'config', 'metadata.requires.config'),
        }
      : undefined;

  const openclaw = {
    ...nest,
    ...(requires !== undefined ? { requires } : {}),
    ...listField(nest, 'os', 'metadata.os'),
  };

  return {
    ...raw,
    ...listField(raw, 'triggers', 'metadata.triggers'),
    ...(Object.keys(openclaw).length > 0 ? { openclaw } : {}),
  } as SkillMetadata;
}

/**
 * Coerce an arbitrary YAML value into the string the manifest interface promises.
 *
 * The interface says these fields are strings; YAML does not enforce that, and the
 * casts that used to sit here made the type a lie. The crash then surfaced far from
 * its cause, inside whichever check called `.trim()` on the value — and because an
 * audit that throws produces no findings at all, a malformed manifest was a way to
 * not get scanned. Every field is coerced rather than dropped so the text still
 * reaches the detection layer: a placeholder someone wrote as `[TODO: ...]` is
 * exactly the sort of thing worth flagging, and it cannot be flagged if parsing it
 * kills the run.
 *
 * Returns undefined only for shapes with no meaningful textual rendering, so the
 * caller can fall back rather than emit a non-string.
 */
function coerceString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    const parts = value.map(renderScalar).filter((part): part is string => part.length > 0);
    return parts.length > 0 ? parts.join(', ') : undefined;
  }
  return undefined;
}

/** Render one element of a coerced sequence, preserving text for the scanner. */
function renderScalar(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return '';
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/**
 * Coerce `allowed-tools` into an array.
 *
 * `allowed-tools: Read, Write, Bash` is valid YAML and parses to a single string,
 * which is how real skills write it. Splitting on commas matches that intent;
 * a lone value such as `Bash(agent-browser:*)` stays a one-element array.
 */
function coerceStringArray(value: unknown): readonly string[] | undefined {
  if (Array.isArray(value)) {
    const items = value.map(renderScalar).filter((item) => item.length > 0);
    return items.length > 0 ? items : undefined;
  }
  if (typeof value === 'string') {
    const items = value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
    return items.length > 0 ? items : undefined;
  }
  return undefined;
}

/**
 * Quick skill name extraction from raw content (no full parse).
 */
export function parseSkillName(content: string): string | null {
  const match = content.match(/^---\n[\s\S]*?^name:\s*(.+)$/m);
  return match?.[1]?.trim() ?? null;
}
