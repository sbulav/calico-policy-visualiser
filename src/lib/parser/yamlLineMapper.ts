/**
 * YAML line-range mapper for Calico policy rules.
 *
 * Scans the raw YAML string and determines the 1-based line ranges
 * for each rule under the `ingress:` and `egress:` sections.
 *
 * This avoids adding a heavier YAML AST library — it relies on the
 * well-defined structure of Calico policy YAML where rules are list
 * items (starting with `- `) under `ingress:` or `egress:` keys.
 */

interface LineRange {
  startLine: number; // 1-based, inclusive
  endLine: number;   // 1-based, inclusive
}

export interface RuleLineRanges {
  ingress: LineRange[];
  egress: LineRange[];
}

/**
 * Find the line ranges of each rule in the `ingress:` and `egress:` sections
 * of a Calico policy YAML string.
 *
 * Strategy:
 * 1. Find `ingress:` and `egress:` top-level keys under `spec:`.
 * 2. Within each section, detect list items by looking for lines that start
 *    with the expected indentation + `- `. Each such line starts a new rule.
 * 3. A rule extends from its `- ` line until the line before the next `- `
 *    at the same indentation, or until the section ends (next top-level key
 *    or a line at lesser/equal indentation to the section key).
 */
export function mapRuleLineRanges(yamlStr: string): RuleLineRanges {
  const lines = yamlStr.split('\n');
  const result: RuleLineRanges = { ingress: [], egress: [] };

  // Find `spec:` indentation level
  let specIndent = -1;
  let specLine = -1;
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^(\s*)spec\s*:/);
    if (match) {
      specIndent = match[1].length;
      specLine = i;
      break;
    }
  }
  if (specLine === -1) return result;

  // Expected indentation for keys directly under spec (e.g. `  ingress:`)
  // In standard YAML, children of spec are indented by 2 spaces relative to spec.
  // But we detect it dynamically: find the first key under spec.
  const specChildIndent = findChildIndent(lines, specLine, specIndent);
  if (specChildIndent === -1) return result;

  // Scan for `ingress:` and `egress:` keys at specChildIndent
  for (let i = specLine + 1; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();

    // If we hit a line at spec-level or less indentation (and it has content),
    // we've left the spec block entirely.
    if (trimmed.length > 0 && !trimmed.startsWith('#')) {
      const indent = line.length - trimmed.length;
      if (indent <= specIndent) break;
    }

    // Check for ingress: or egress: at the expected child indent
    const keyMatch = line.match(/^(\s*)(ingress|egress)\s*:/);
    if (keyMatch && keyMatch[1].length === specChildIndent) {
      const direction = keyMatch[2] as 'ingress' | 'egress';
      const sectionStart = i;
      const ranges = extractRuleRanges(lines, sectionStart, specChildIndent);
      result[direction] = ranges;
    }
  }

  return result;
}

/**
 * Find the indentation of the first non-comment child key after `parentLine`.
 * Returns -1 if no child found.
 */
function findChildIndent(lines: string[], parentLine: number, parentIndent: number): number {
  for (let i = parentLine + 1; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    const indent = line.length - trimmed.length;
    // Must be deeper than parent
    if (indent <= parentIndent) break;

    // This is the first content line under the parent — its indent is the child level
    return indent;
  }
  return -1;
}

/**
 * Extract rule line ranges from a section (ingress: or egress:).
 *
 * `sectionLine` is the 0-based index of the `ingress:` / `egress:` line.
 * `sectionIndent` is the indentation of that key.
 *
 * Rules are YAML list items, so their `- ` marker is at `sectionIndent + 2`
 * (the standard YAML convention for list items under a key).
 * But we detect the list-item indentation dynamically from the first `- ` line.
 */
function extractRuleRanges(lines: string[], sectionLine: number, sectionIndent: number): LineRange[] {
  const ranges: LineRange[] = [];

  // Find the first `- ` line after sectionLine to determine list-item indent
  let listItemIndent = -1;
  let firstListLine = -1;

  for (let i = sectionLine + 1; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    const indent = line.length - trimmed.length;
    // If we're before the section key's indent, we've left the section.
    // If we're at the same indent but NOT a list item, it's a sibling key.
    if (indent < sectionIndent) break;
    if (indent === sectionIndent && !trimmed.startsWith('- ')) break;

    if (trimmed.startsWith('- ')) {
      listItemIndent = indent;
      firstListLine = i;
      break;
    }
  }

  if (firstListLine === -1) return ranges;

  // Now scan all lines from firstListLine, collecting rule boundaries
  let currentRuleStart = -1;

  for (let i = firstListLine; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();

    // Blank lines and comments: include in current rule, but don't start new sections
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    const indent = line.length - trimmed.length;

    // Section is over when we hit a line that's:
    //   - shallower than the section key, OR
    //   - at the same indent as the section key but NOT a list item (i.e. a sibling key)
    // Note: `- ` at sectionIndent is valid YAML for list items under the section.
    if (indent < sectionIndent || (indent === sectionIndent && !trimmed.startsWith('- '))) {
      // Close current rule
      if (currentRuleStart !== -1) {
        ranges.push({
          startLine: currentRuleStart + 1, // convert to 1-based
          endLine: findLastContentLine(lines, currentRuleStart, i - 1) + 1,
        });
      }
      break;
    }

    // A new list item at the expected indent starts a new rule
    if (indent === listItemIndent && trimmed.startsWith('- ')) {
      // Close previous rule
      if (currentRuleStart !== -1) {
        ranges.push({
          startLine: currentRuleStart + 1,
          endLine: findLastContentLine(lines, currentRuleStart, i - 1) + 1,
        });
      }
      currentRuleStart = i;
    }
  }

  // Handle the last rule (if the file ends without a lower-indent line)
  if (currentRuleStart !== -1) {
    // Check if we already pushed this range
    const lastPushed = ranges.length > 0 ? ranges[ranges.length - 1] : null;
    if (!lastPushed || lastPushed.startLine !== currentRuleStart + 1) {
      ranges.push({
        startLine: currentRuleStart + 1,
        endLine: findLastContentLine(lines, currentRuleStart, lines.length - 1) + 1,
      });
    }
  }

  return ranges;
}

/**
 * Find the last non-blank, non-comment line in a range (0-based indices).
 * Returns 0-based line index.
 */
function findLastContentLine(lines: string[], from: number, to: number): number {
  let last = from;
  for (let i = to; i >= from; i--) {
    const trimmed = lines[i].trim();
    if (trimmed.length > 0 && !trimmed.startsWith('#')) {
      last = i;
      break;
    }
  }
  return last;
}
