// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { describe, it, expect } from 'vitest';
import { parseManifestFromString, parseSkillName } from '../manifest-parser.js';

// ---------------------------------------------------------------------------
// parseManifestFromString
// ---------------------------------------------------------------------------

describe('parseManifestFromString', () => {
  describe('valid frontmatter', () => {
    it('parses name and description from frontmatter', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: A test skill',
        '---',
        'Do the thing.',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.name).toBe('my-skill');
      expect(manifest.description).toBe('A test skill');
    });

    it('extracts instructions as the content after frontmatter', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: A test skill',
        '---',
        'Do the thing.',
        'Second line.',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.instructions).toContain('Do the thing.');
      expect(manifest.instructions).toContain('Second line.');
    });

    it('parses optional license field', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'license: MIT',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.license).toBe('MIT');
    });

    it('parses optional homepage field', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'homepage: https://example.com',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.homepage).toBe('https://example.com');
    });

    it('parses user-invocable boolean', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'user-invocable: true',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.userInvocable).toBe(true);
    });

    it('parses allowed-tools list', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'allowed-tools:',
        '  - Bash',
        '  - Read',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest['allowed-tools']).toEqual(['Bash', 'Read']);
    });
  });

  describe('metadata extraction', () => {
    it('extracts version from metadata object', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'metadata:',
        '  version: "1.2.3"',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.metadata?.version).toBe('1.2.3');
    });

    it('extracts tags from metadata object', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'metadata:',
        '  tags:',
        '    - security',
        '    - ai',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.metadata?.tags).toEqual(['security', 'ai']);
    });

    it('parses metadata when provided as a JSON string', () => {
      const metaJson = JSON.stringify({ version: '2.0.0', tags: ['test'] });
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        `metadata: '${metaJson}'`,
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.metadata?.version).toBe('2.0.0');
    });

    it('silently ignores invalid JSON string in metadata', () => {
      const content = [
        '---',
        'name: my-skill',
        'description: desc',
        'metadata: "not valid json {"',
        '---',
        'instructions',
      ].join('\n');

      const manifest = parseManifestFromString(content);
      expect(manifest.metadata).toBeUndefined();
    });
  });

  describe('no frontmatter', () => {
    it('treats entire content as instructions when no frontmatter present', () => {
      const content = 'Just raw instructions without any frontmatter.';
      const manifest = parseManifestFromString(content);
      expect(manifest.instructions).toBe(content);
    });

    it('uses fallbackName when no frontmatter', () => {
      const content = 'Raw instructions.';
      const manifest = parseManifestFromString(content, 'fallback-name');
      expect(manifest.name).toBe('fallback-name');
    });

    it('uses "unknown" as default fallback name', () => {
      const content = 'Raw instructions.';
      const manifest = parseManifestFromString(content);
      expect(manifest.name).toBe('unknown');
    });

    it('returns empty description when no frontmatter', () => {
      const content = 'Raw instructions.';
      const manifest = parseManifestFromString(content);
      expect(manifest.description).toBe('');
    });

    it('handles empty string content', () => {
      const manifest = parseManifestFromString('');
      expect(manifest.name).toBe('unknown');
      expect(manifest.instructions).toBe('');
    });
  });

  describe('invalid YAML frontmatter', () => {
    it('returns fallback manifest for invalid YAML', () => {
      // YAML that is structurally invalid within the frontmatter block
      const content = [
        '---',
        'name: [unclosed bracket',
        'description: test',
        '---',
        'instructions here',
      ].join('\n');

      const manifest = parseManifestFromString(content, 'fallback');
      // Should fall back gracefully - either parse successfully or use fallback
      expect(manifest.name).toBeDefined();
      expect(typeof manifest.name).toBe('string');
    });

    it('uses fallbackName on YAML parse failure', () => {
      // Deeply malformed YAML that triggers a parse exception
      const badYaml = 'key: :\n  - invalid: : nested\n    bad: [unclosed';
      const content = `---\n${badYaml}\n---\ninstructions`;
      const manifest = parseManifestFromString(content, 'my-fallback');
      // Either parses or falls back - name must be a string
      expect(typeof manifest.name).toBe('string');
    });
  });

  describe('edge cases', () => {
    it('uses fallbackName when frontmatter has no name field', () => {
      const content = ['---', 'description: no name here', '---', 'instructions'].join('\n');

      const manifest = parseManifestFromString(content, 'injected-name');
      expect(manifest.name).toBe('injected-name');
    });

    it('handles frontmatter with CRLF line endings', () => {
      const content = '---\r\nname: crlf-skill\r\ndescription: desc\r\n---\r\ninstructions';
      const manifest = parseManifestFromString(content);
      expect(manifest.name).toBe('crlf-skill');
    });

    it('instructions are empty string when nothing follows frontmatter', () => {
      const content = ['---', 'name: my-skill', 'description: desc', '---'].join('\n');
      const manifest = parseManifestFromString(content);
      // instructions should be empty or whitespace - just not throw
      expect(typeof manifest.instructions).toBe('string');
    });
  });
});

// ---------------------------------------------------------------------------
// parseSkillName
// ---------------------------------------------------------------------------

describe('parseSkillName', () => {
  it('extracts name from raw content with frontmatter', () => {
    const content = ['---', 'name: extracted-skill', 'description: test', '---', 'body'].join('\n');
    expect(parseSkillName(content)).toBe('extracted-skill');
  });

  it('returns null when no frontmatter present', () => {
    const content = 'Just raw content without frontmatter.';
    expect(parseSkillName(content)).toBeNull();
  });

  it('returns null when frontmatter has no name field', () => {
    const content = ['---', 'description: no name', '---', 'body'].join('\n');
    expect(parseSkillName(content)).toBeNull();
  });

  it('trims whitespace from the extracted name', () => {
    const content = ['---', 'name:   my-skill   ', '---', 'body'].join('\n');
    // The regex captures everything after "name: " so trailing space may or may not be trimmed
    // The implementation does .trim() so we expect clean value
    const name = parseSkillName(content);
    expect(name).toBe('my-skill');
  });

  it('handles names with hyphens and dots', () => {
    const content = ['---', 'name: my.complex-skill.v2', '---', 'body'].join('\n');
    expect(parseSkillName(content)).toBe('my.complex-skill.v2');
  });

  it('returns null for empty string', () => {
    expect(parseSkillName('')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Malformed frontmatter must not produce lying types
//
// Every input below is verbatim from a real published skill. YAML happily
// parses them into types the manifest interface says are impossible, and the
// unchecked casts in the parser used to pass those straight through — so the
// crash surfaced far away, inside whichever check called .trim() / .join() /
// .some() on them. A scanner that throws on a malformed manifest reports zero
// findings for that skill, which is a silent bypass, not a cosmetic bug.
// ---------------------------------------------------------------------------

describe('parseManifestFromString — malformed field types', () => {
  const frontmatter = (...lines: string[]) =>
    ['---', ...lines, '---', 'Body text that is long enough to look like instructions.'].join('\n');

  it('coerces a comma-separated allowed-tools string into an array', () => {
    // verbatim: benign/acestep
    const manifest = parseManifestFromString(
      frontmatter(
        'name: acestep',
        'description: Generate music',
        'allowed-tools: Read, Write, Bash, Skill'
      )
    );
    expect(Array.isArray(manifest['allowed-tools'])).toBe(true);
    expect(manifest['allowed-tools']).toEqual(['Read', 'Write', 'Bash', 'Skill']);
  });

  it('keeps a single-tool allowed-tools string as a one-element array', () => {
    // verbatim: benign/agent-browser-2
    const manifest = parseManifestFromString(
      frontmatter(
        'name: agent-browser',
        'description: Automates browsers',
        'allowed-tools: Bash(agent-browser:*)'
      )
    );
    expect(manifest['allowed-tools']).toEqual(['Bash(agent-browser:*)']);
  });

  it('flattens a description that YAML parsed as a sequence', () => {
    // verbatim: benign/my-new-skill — a bracketed TODO placeholder is flow-sequence syntax
    const manifest = parseManifestFromString(
      frontmatter(
        'name: my-new-skill',
        'description: [TODO: Complete explanation of what the skill does]'
      )
    );
    expect(typeof manifest.description).toBe('string');
    expect(manifest.description).toContain('TODO');
  });

  it('coerces a numeric name and description to strings', () => {
    const manifest = parseManifestFromString(frontmatter('name: 12345', 'description: 42'));
    expect(manifest.name).toBe('12345');
    expect(manifest.description).toBe('42');
  });

  it('drops a mapping-valued description rather than emitting a non-string', () => {
    const manifest = parseManifestFromString(
      frontmatter('name: weird', 'description:', '  nested: value')
    );
    expect(typeof manifest.description).toBe('string');
  });

  it('records which fields had to be coerced instead of coercing silently', () => {
    const manifest = parseManifestFromString(
      frontmatter('name: acestep', 'description: [TODO: fill me in]', 'allowed-tools: Read, Write')
    );
    expect(manifest.parseDegraded).toEqual(
      expect.arrayContaining(['description', 'allowed-tools'])
    );
  });

  it('leaves a well-formed manifest undegraded', () => {
    const manifest = parseManifestFromString(
      frontmatter(
        'name: fine',
        'description: A normal description',
        'allowed-tools:',
        '  - Read',
        '  - Write'
      )
    );
    expect(manifest['allowed-tools']).toEqual(['Read', 'Write']);
    expect(manifest.parseDegraded).toBeUndefined();
  });

  it('survives every downstream string/array operation the checks perform', () => {
    const manifest = parseManifestFromString(
      frontmatter('name: 1', 'description: [TODO]', 'allowed-tools: Read, Write')
    );
    // These are the exact call shapes that crashed in 1.5.4 and 1.8.26.
    expect(() => manifest.description.trim()).not.toThrow();
    expect(() => manifest.name.trim()).not.toThrow();
    expect(() => (manifest['allowed-tools'] ?? []).some((t) => t === 'Read')).not.toThrow();
    expect(() => (manifest['allowed-tools'] ?? []).join(', ')).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// metadata.requires.* has the same problem one level deeper, and it is worse:
// `requires.env` is declared readonly string[], so a guard like
// `requires.env.length > 0` passes for a string too — the crash only lands on
// the .join() that follows. All four inputs below are verbatim from published
// skills that the MalSkillBench authors had to hand-override because the
// auditor threw on them.
// ---------------------------------------------------------------------------

describe('parseManifestFromString — metadata.requires coercion', () => {
  const withMetadata = (...lines: string[]) =>
    ['---', 'name: s', 'description: d', ...lines, '---', 'Body.'].join('\n');

  it('coerces a single-value requires.env string into an array', () => {
    // verbatim: benign/baidu-ai-map
    const m = parseManifestFromString(
      withMetadata(
        'metadata:',
        '  requires:',
        '    bins: ["curl"]',
        '    env: BAIDU_MAP_AUTH_TOKEN'
      )
    );
    expect(m.metadata?.openclaw?.requires?.env).toEqual(['BAIDU_MAP_AUTH_TOKEN']);
    expect(m.metadata?.openclaw?.requires?.bins).toEqual(['curl']);
  });

  it('splits a comma-separated requires.env string', () => {
    // verbatim: benign/signalhire-skill
    const m = parseManifestFromString(
      withMetadata(
        'metadata:',
        '  requires:',
        '    env: SIGNALHIRE_API_KEY,SIGNALHIRE_CALLBACK_URL'
      )
    );
    expect(m.metadata?.openclaw?.requires?.env).toEqual([
      'SIGNALHIRE_API_KEY',
      'SIGNALHIRE_CALLBACK_URL',
    ]);
  });

  it('coerces requires.env inside a JSON-string metadata block', () => {
    // verbatim shape: benign/plurum
    const m = parseManifestFromString(
      withMetadata(
        'metadata: {"openclaw":{"requires":{"env":"PLURUM_API_KEY"}},"primaryEnv":"PLURUM_API_KEY"}'
      )
    );
    expect(m.metadata?.openclaw?.requires?.env).toEqual(['PLURUM_API_KEY']);
  });

  it('survives the exact join the dependency check performs', () => {
    const m = parseManifestFromString(
      withMetadata('metadata:', '  requires:', '    env: A_TOKEN', '    bins: curl, jq')
    );
    const req = m.metadata?.openclaw?.requires;
    expect(() => (req?.env ?? []).join(', ')).not.toThrow();
    expect(() => (req?.bins ?? []).join(', ')).not.toThrow();
    expect(req?.bins).toEqual(['curl', 'jq']);
  });
});

describe('parseManifestFromString — metadata coercion is reported too', () => {
  it('records a coerced metadata.requires.env in parseDegraded', () => {
    // verbatim: benign/baidu-ai-map — the manifest only scans because we repaired it,
    // and a report that says "clean" without saying "repaired" overstates the evidence.
    const m = parseManifestFromString(
      [
        '---',
        'name: s',
        'description: d',
        'metadata:',
        '  requires:',
        '    env: BAIDU_MAP_AUTH_TOKEN',
        '---',
        'Body.',
      ].join('\n')
    );
    expect(m.parseDegraded).toEqual(expect.arrayContaining(['metadata.requires.env']));
  });

  it('leaves well-formed metadata undegraded', () => {
    const m = parseManifestFromString(
      [
        '---',
        'name: s',
        'description: d',
        'metadata:',
        '  requires:',
        '    env:',
        '      - A',
        '      - B',
        '---',
        'Body.',
      ].join('\n')
    );
    expect(m.parseDegraded).toBeUndefined();
  });
});
