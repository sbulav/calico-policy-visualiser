import { describe, it, expect } from 'vitest';
import { evaluateSelector, parseSelectorExpression } from './selectorParser';

// ---- Parser unit tests ----

describe('parseSelectorExpression', () => {
  it('parses all()', () => {
    const ast = parseSelectorExpression('all()');
    expect(ast).toEqual({ kind: 'all' });
  });

  it('treats empty string as all()', () => {
    const ast = parseSelectorExpression('');
    expect(ast).toEqual({ kind: 'all' });
  });

  it('parses global()', () => {
    const ast = parseSelectorExpression('global()');
    expect(ast).toEqual({ kind: 'global' });
  });

  it('parses has(label)', () => {
    const ast = parseSelectorExpression('has(app)');
    expect(ast).toEqual({ kind: 'has', label: 'app' });
  });

  it('parses has() with dotted label', () => {
    const ast = parseSelectorExpression('has(node-role.kubernetes.io/control-plane)');
    expect(ast).toEqual({ kind: 'has', label: 'node-role.kubernetes.io/control-plane' });
  });

  it('parses == expression', () => {
    const ast = parseSelectorExpression("app == 'web'");
    expect(ast).toEqual({ kind: 'eq', label: 'app', value: 'web' });
  });

  it('parses != expression', () => {
    const ast = parseSelectorExpression("env != 'test'");
    expect(ast).toEqual({ kind: 'neq', label: 'env', value: 'test' });
  });

  it('parses in expression', () => {
    const ast = parseSelectorExpression("env in { 'prod', 'staging' }");
    expect(ast).toEqual({ kind: 'in', label: 'env', values: ['prod', 'staging'] });
  });

  it('parses not in expression', () => {
    const ast = parseSelectorExpression("env not in { 'dev', 'test' }");
    expect(ast).toEqual({ kind: 'notIn', label: 'env', values: ['dev', 'test'] });
  });

  it('parses starts with expression', () => {
    const ast = parseSelectorExpression("app starts with 'web'");
    expect(ast).toEqual({ kind: 'startsWith', label: 'app', value: 'web' });
  });

  it('parses ends with expression', () => {
    const ast = parseSelectorExpression("app ends with '-api'");
    expect(ast).toEqual({ kind: 'endsWith', label: 'app', value: '-api' });
  });

  it('parses && (AND) expression', () => {
    const ast = parseSelectorExpression("app == 'web' && env == 'prod'");
    expect(ast).toEqual({
      kind: 'and',
      left: { kind: 'eq', label: 'app', value: 'web' },
      right: { kind: 'eq', label: 'env', value: 'prod' },
    });
  });

  it('parses || (OR) expression', () => {
    const ast = parseSelectorExpression("app == 'web' || app == 'api'");
    expect(ast).toEqual({
      kind: 'or',
      left: { kind: 'eq', label: 'app', value: 'web' },
      right: { kind: 'eq', label: 'app', value: 'api' },
    });
  });

  it('parses ! (NOT) expression', () => {
    const ast = parseSelectorExpression("!has(internal)");
    expect(ast).toEqual({
      kind: 'not',
      operand: { kind: 'has', label: 'internal' },
    });
  });

  it('respects operator precedence: && binds tighter than ||', () => {
    // a || b && c should be parsed as a || (b && c)
    const ast = parseSelectorExpression("app == 'a' || app == 'b' && env == 'prod'");
    expect(ast).toEqual({
      kind: 'or',
      left: { kind: 'eq', label: 'app', value: 'a' },
      right: {
        kind: 'and',
        left: { kind: 'eq', label: 'app', value: 'b' },
        right: { kind: 'eq', label: 'env', value: 'prod' },
      },
    });
  });

  it('handles parenthesized grouping', () => {
    const ast = parseSelectorExpression("(app == 'a' || app == 'b') && env == 'prod'");
    expect(ast).toEqual({
      kind: 'and',
      left: {
        kind: 'or',
        left: { kind: 'eq', label: 'app', value: 'a' },
        right: { kind: 'eq', label: 'app', value: 'b' },
      },
      right: { kind: 'eq', label: 'env', value: 'prod' },
    });
  });

  it('parses double-quoted strings', () => {
    const ast = parseSelectorExpression('app == "web"');
    expect(ast).toEqual({ kind: 'eq', label: 'app', value: 'web' });
  });

  it('handles Calico-style label keys with slashes and dots', () => {
    const ast = parseSelectorExpression("projectcalico.org/name == 'default'");
    expect(ast).toEqual({ kind: 'eq', label: 'projectcalico.org/name', value: 'default' });
  });

  it('handles in with trailing comma', () => {
    const ast = parseSelectorExpression("env in { 'a', 'b', }");
    expect(ast).toEqual({ kind: 'in', label: 'env', values: ['a', 'b'] });
  });

  it('throws on invalid syntax', () => {
    expect(() => parseSelectorExpression('===')).toThrow();
    expect(() => parseSelectorExpression('app ==')).toThrow();
    expect(() => parseSelectorExpression('has(')).toThrow();
  });
});

// ---- Evaluator tests ----

describe('evaluateSelector', () => {
  const labels = {
    app: 'web',
    env: 'production',
    version: 'v2.1',
    'tier': 'frontend',
    'projectcalico.org/name': 'my-namespace',
  };

  it('all() matches anything', () => {
    expect(evaluateSelector('all()', labels)).toBe(true);
    expect(evaluateSelector('all()', {})).toBe(true);
  });

  it('empty string matches anything', () => {
    expect(evaluateSelector('', labels)).toBe(true);
    expect(evaluateSelector('  ', {})).toBe(true);
  });

  it('global() always returns false (pod context)', () => {
    expect(evaluateSelector('global()', labels)).toBe(false);
  });

  it('has() checks label existence', () => {
    expect(evaluateSelector('has(app)', labels)).toBe(true);
    expect(evaluateSelector('has(missing)', labels)).toBe(false);
  });

  it('== checks exact value', () => {
    expect(evaluateSelector("app == 'web'", labels)).toBe(true);
    expect(evaluateSelector("app == 'api'", labels)).toBe(false);
  });

  it('!= checks inequality', () => {
    expect(evaluateSelector("app != 'api'", labels)).toBe(true);
    expect(evaluateSelector("app != 'web'", labels)).toBe(false);
  });

  it('!= returns false for missing labels', () => {
    // Calico semantics: != requires label to exist and have different value
    expect(evaluateSelector("missing != 'value'", labels)).toBe(false);
  });

  it('in checks set membership', () => {
    expect(evaluateSelector("app in { 'web', 'api', 'worker' }", labels)).toBe(true);
    expect(evaluateSelector("app in { 'api', 'worker' }", labels)).toBe(false);
  });

  it('not in checks exclusion', () => {
    expect(evaluateSelector("app not in { 'api', 'worker' }", labels)).toBe(true);
    expect(evaluateSelector("app not in { 'web', 'api' }", labels)).toBe(false);
  });

  it('not in returns true for missing labels', () => {
    expect(evaluateSelector("missing not in { 'a', 'b' }", labels)).toBe(true);
  });

  it('starts with checks prefix', () => {
    expect(evaluateSelector("version starts with 'v2'", labels)).toBe(true);
    expect(evaluateSelector("version starts with 'v3'", labels)).toBe(false);
  });

  it('ends with checks suffix', () => {
    expect(evaluateSelector("version ends with '.1'", labels)).toBe(true);
    expect(evaluateSelector("version ends with '.0'", labels)).toBe(false);
  });

  it('&& requires both sides', () => {
    expect(evaluateSelector("app == 'web' && env == 'production'", labels)).toBe(true);
    expect(evaluateSelector("app == 'web' && env == 'staging'", labels)).toBe(false);
  });

  it('|| requires at least one side', () => {
    expect(evaluateSelector("app == 'api' || env == 'production'", labels)).toBe(true);
    expect(evaluateSelector("app == 'api' || env == 'staging'", labels)).toBe(false);
  });

  it('! negates', () => {
    expect(evaluateSelector('!has(missing)', labels)).toBe(true);
    expect(evaluateSelector('!has(app)', labels)).toBe(false);
  });

  it('complex expression with Calico-style labels', () => {
    expect(evaluateSelector(
      "projectcalico.org/name == 'my-namespace' && has(app)",
      labels,
    )).toBe(true);
  });

  it('complex nested expression', () => {
    expect(evaluateSelector(
      "(app == 'web' || app == 'api') && env == 'production'",
      labels,
    )).toBe(true);
    expect(evaluateSelector(
      "(app == 'web' || app == 'api') && env == 'staging'",
      labels,
    )).toBe(false);
  });
});
