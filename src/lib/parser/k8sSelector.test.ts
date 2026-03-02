import { describe, it, expect } from 'vitest';
import { labelSelectorToExpression } from './k8sSelector';

describe('labelSelectorToExpression', () => {
  it('returns undefined for undefined input', () => {
    expect(labelSelectorToExpression(undefined)).toBeUndefined();
  });

  it('returns all() for empty selector object', () => {
    expect(labelSelectorToExpression({})).toBe('all()');
  });

  it('returns all() for empty matchLabels object', () => {
    expect(labelSelectorToExpression({ matchLabels: {} })).toBe('all()');
  });

  it('converts matchLabels', () => {
    expect(labelSelectorToExpression({ matchLabels: { app: 'web' } })).toBe("app == 'web'");
  });

  it('converts multiple matchLabels joined with &&', () => {
    const result = labelSelectorToExpression({ matchLabels: { app: 'web', env: 'prod' } });
    expect(result).toContain("app == 'web'");
    expect(result).toContain("env == 'prod'");
    expect(result).toContain('&&');
  });

  it('converts matchExpressions operators', () => {
    const expression = labelSelectorToExpression({
      matchExpressions: [
        { key: 'env', operator: 'In', values: ['prod', 'staging'] },
        { key: 'tier', operator: 'NotIn', values: ['dev'] },
        { key: 'team', operator: 'Exists' },
        { key: 'debug', operator: 'DoesNotExist' },
      ],
    });

    expect(expression).toContain("env in {'prod', 'staging'}");
    expect(expression).toContain("tier not in {'dev'}");
    expect(expression).toContain('has(team)');
    expect(expression).toContain('!has(debug)');
  });

  it('In operator with empty values produces an always-false expression', () => {
    const result = labelSelectorToExpression({
      matchExpressions: [{ key: 'app', operator: 'In', values: [] }],
    });
    // Must not match anything; uses sentinel key contradiction.
    expect(result).toContain('has(__k8s_invalid__)');
    expect(result).toContain('!has(__k8s_invalid__)');
  });

  it('NotIn operator with empty values is silently omitted (vacuously true)', () => {
    const result = labelSelectorToExpression({
      matchExpressions: [{ key: 'app', operator: 'NotIn', values: [] }],
    });
    expect(result).toBe('all()');
  });

  it('combines matchLabels and matchExpressions with &&', () => {
    const result = labelSelectorToExpression({
      matchLabels: { app: 'web' },
      matchExpressions: [{ key: 'env', operator: 'Exists' }],
    });
    expect(result).toContain("app == 'web'");
    expect(result).toContain('has(env)');
    expect(result).toContain('&&');
  });

  it('escapes single quotes in label values', () => {
    const result = labelSelectorToExpression({ matchLabels: { app: "it's-fine" } });
    expect(result).toBe("app == 'it\\'s-fine'");
  });
});
