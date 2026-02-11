import { describe, it, expect } from 'vitest';
import { mapRuleLineRanges } from './yamlLineMapper';

// ---------------------------------------------------------------------------
// Basic structure
// ---------------------------------------------------------------------------

describe('mapRuleLineRanges — basic', () => {
  it('returns empty arrays for YAML without spec', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toEqual([]);
    expect(result.egress).toEqual([]);
  });

  it('returns empty arrays for spec without ingress/egress', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
spec:
  selector: all()
  types:
  - Ingress`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toEqual([]);
    expect(result.egress).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Ingress rules
// ---------------------------------------------------------------------------

describe('mapRuleLineRanges — ingress', () => {
  it('maps a single ingress rule', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toHaveLength(1);
    expect(result.ingress[0].startLine).toBe(9); // `- action: Allow`
    expect(result.ingress[0].endLine).toBe(10);  // `  protocol: TCP`
  });

  it('maps multiple ingress rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: app == 'api'
  - action: Deny
  - action: Log`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toHaveLength(3);
    // Rule 1: lines 9-12
    expect(result.ingress[0].startLine).toBe(9);
    expect(result.ingress[0].endLine).toBe(12);
    // Rule 2: line 13
    expect(result.ingress[1].startLine).toBe(13);
    expect(result.ingress[1].endLine).toBe(13);
    // Rule 3: line 14
    expect(result.ingress[2].startLine).toBe(14);
    expect(result.ingress[2].endLine).toBe(14);
  });
});

// ---------------------------------------------------------------------------
// Egress rules
// ---------------------------------------------------------------------------

describe('mapRuleLineRanges — egress', () => {
  it('maps egress rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      nets:
      - 10.0.0.0/8
  - action: Deny`;

    const result = mapRuleLineRanges(yaml);
    expect(result.egress).toHaveLength(2);
    expect(result.egress[0].startLine).toBe(11);
    expect(result.egress[0].endLine).toBe(14);
    expect(result.egress[1].startLine).toBe(15);
    expect(result.egress[1].endLine).toBe(15);
  });
});

// ---------------------------------------------------------------------------
// Both directions
// ---------------------------------------------------------------------------

describe('mapRuleLineRanges — both directions', () => {
  it('maps ingress and egress in the same policy', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    source:
      selector: app == 'api'
  - action: Deny
  egress:
  - action: Allow
    destination:
      nets:
      - 10.0.0.0/8`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toHaveLength(2);
    expect(result.egress).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('mapRuleLineRanges — edge cases', () => {
  it('handles indented YAML-style (ingress with 4-space indent)', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: color == 'blue'
      destination:
        ports:
          - 6379`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toHaveLength(1);
    // Should capture the full rule including nested keys
    expect(result.ingress[0].startLine).toBe(9);
  });

  it('handles empty YAML string', () => {
    const result = mapRuleLineRanges('');
    expect(result.ingress).toEqual([]);
    expect(result.egress).toEqual([]);
  });

  it('handles YAML with comments between rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test
  namespace: default
spec:
  selector: all()
  ingress:
  # Allow API traffic
  - action: Allow
    protocol: TCP
  # Deny everything else
  - action: Deny`;

    const result = mapRuleLineRanges(yaml);
    expect(result.ingress).toHaveLength(2);
  });
});
