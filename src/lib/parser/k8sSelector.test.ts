import { describe, it, expect } from 'vitest';
import { labelSelectorToExpression } from './k8sSelector';

describe('labelSelectorToExpression', () => {
  it('returns all() for empty selector object', () => {
    expect(labelSelectorToExpression({})).toBe('all()');
  });

  it('converts matchLabels', () => {
    expect(labelSelectorToExpression({ matchLabels: { app: 'web' } })).toBe("app == 'web'");
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
});
