import { describe, it, expect } from 'vitest';
import { testAccess } from './accessTester';
import type { ResolvedPolicy } from '../../types/calico';
import type { TrafficSpec } from '../../types/matcher';

// Helper to create a minimal ResolvedPolicy for testing
function makePolicy(overrides: Partial<ResolvedPolicy> = {}): ResolvedPolicy {
  return {
    raw: {
      apiVersion: 'projectcalico.org/v3',
      kind: 'NetworkPolicy',
      metadata: { name: 'test-policy', namespace: 'default' },
      spec: {},
    },
    name: 'test-policy',
    namespace: 'default',
    kind: 'NetworkPolicy',
    tier: 'default',
    selector: 'all()',
    types: ['Ingress', 'Egress'],
    ingressRules: [],
    egressRules: [],
    ingressDefault: 'deny',
    egressDefault: 'deny',
    ...overrides,
  };
}

describe('testAccess', () => {
  // --- Default behavior ---
  describe('default behavior', () => {
    it('denies by default when no rules and direction is managed', () => {
      const policy = makePolicy();
      const result = testAccess(policy, 'ingress', {});
      expect(result.verdict).toBe('denied');
      expect(result.appliedDefault).toBe(true);
      expect(result.decisiveRuleIndex).toBeNull();
    });

    it('allows when direction is not managed by policy', () => {
      const policy = makePolicy({ types: ['Ingress'] });
      const result = testAccess(policy, 'egress', {});
      expect(result.verdict).toBe('allowed');
      expect(result.appliedDefault).toBe(true);
    });

    it('allows when default is allow', () => {
      const policy = makePolicy({ egressDefault: 'allow', types: ['Egress'] });
      const result = testAccess(policy, 'egress', {});
      expect(result.verdict).toBe('allowed');
    });
  });

  // --- Simple allow rule ---
  describe('allow rules', () => {
    it('allows traffic matching an Allow rule', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
        ],
      });
      const spec: TrafficSpec = { ip: '10.1.2.3' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('allowed');
      expect(result.decisiveRuleIndex).toBe(0);
      expect(result.appliedDefault).toBe(false);
    });

    it('denies traffic not matching any Allow rule (falls to default)', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
        ],
      });
      const spec: TrafficSpec = { ip: '192.168.1.1' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.appliedDefault).toBe(true);
    });
  });

  // --- Deny rules ---
  describe('deny rules', () => {
    it('denies traffic matching a Deny rule', () => {
      const policy = makePolicy({
        egressRules: [
          { action: 'Deny', destination: { nets: ['10.0.0.0/8'] } },
          { action: 'Allow' }, // catch-all allow
        ],
      });
      const spec: TrafficSpec = { ip: '10.5.5.5' };
      const result = testAccess(policy, 'egress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.decisiveRuleIndex).toBe(0);
    });

    it('allows traffic that skips the deny and hits allow', () => {
      const policy = makePolicy({
        egressRules: [
          { action: 'Deny', destination: { nets: ['10.0.0.0/8'] } },
          { action: 'Allow' }, // catch-all allow
        ],
      });
      const spec: TrafficSpec = { ip: '8.8.8.8' };
      const result = testAccess(policy, 'egress', spec);
      expect(result.verdict).toBe('allowed');
      expect(result.decisiveRuleIndex).toBe(1);
    });
  });

  // --- Log rules (transparent) ---
  describe('log rules', () => {
    it('Log rules are transparent — continues to next rule', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Log' },
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
        ],
      });
      const spec: TrafficSpec = { ip: '10.1.2.3' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('allowed');
      expect(result.decisiveRuleIndex).toBe(1);
      // Log rule should be in the trace
      expect(result.trace.length).toBe(2);
      expect(result.trace[0].action).toBe('Log');
      expect(result.trace[0].isDecisive).toBe(false);
    });
  });

  // --- Pass rules ---
  describe('pass rules', () => {
    it('reports pass to next tier', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Pass' },
        ],
      });
      const result = testAccess(policy, 'ingress', {});
      expect(result.verdict).toBe('passed');
      expect(result.decisiveRuleIndex).toBe(0);
    });
  });

  // --- First-match-wins ordering ---
  describe('rule ordering (first-match-wins)', () => {
    it('first matching rule wins', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Deny', source: { nets: ['10.0.0.0/24'] } },
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
        ],
      });
      // IP 10.0.0.5 matches both rules, but Deny comes first
      const spec: TrafficSpec = { ip: '10.0.0.5' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.decisiveRuleIndex).toBe(0);
    });

    it('skips non-matching rules to find the first match', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { nets: ['192.168.0.0/16'] } },
          { action: 'Deny', source: { nets: ['10.0.0.0/8'] } },
          { action: 'Allow' }, // catch-all
        ],
      });
      const spec: TrafficSpec = { ip: '10.5.5.5' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.decisiveRuleIndex).toBe(1);
      // First rule should be in trace as non-matching
      expect(result.trace[0].matchResult.matches).toBe(false);
    });
  });

  // --- Full trace ---
  describe('trace', () => {
    it('includes all rules in trace even after decisive match', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
          { action: 'Deny' }, // should not be reached but shouldn't be in trace after decisive
        ],
      });
      const spec: TrafficSpec = { ip: '10.1.2.3' };
      const result = testAccess(policy, 'ingress', spec);
      // Only rules up to and including the decisive one are in the trace
      expect(result.trace.length).toBe(1);
      expect(result.trace[0].isDecisive).toBe(true);
    });

    it('includes all rules when falling through to default', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { nets: ['10.0.0.0/8'] } },
          { action: 'Allow', source: { nets: ['172.16.0.0/12'] } },
        ],
      });
      const spec: TrafficSpec = { ip: '8.8.8.8' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.trace.length).toBe(2);
      expect(result.appliedDefault).toBe(true);
    });
  });

  // --- Selector-based policies ---
  describe('selector-based rules', () => {
    it('matches pod labels against rule selectors', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { selector: "app == 'frontend'" } },
        ],
      });
      const spec: TrafficSpec = { labels: { app: 'frontend' } };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('allowed');
    });

    it('rejects non-matching labels', () => {
      const policy = makePolicy({
        ingressRules: [
          { action: 'Allow', source: { selector: "app == 'frontend'" } },
        ],
      });
      const spec: TrafficSpec = { labels: { app: 'backend' } };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.appliedDefault).toBe(true);
    });
  });

  // --- Combined CIDR + port ---
  describe('CIDR + port rules', () => {
    it('matches when both CIDR and port match', () => {
      const policy = makePolicy({
        egressRules: [
          {
            action: 'Allow',
            protocol: 'TCP',
            destination: { nets: ['8.8.8.0/24'], ports: [53] },
          },
        ],
      });
      const spec: TrafficSpec = { ip: '8.8.8.8', port: 53, protocol: 'TCP' };
      const result = testAccess(policy, 'egress', spec);
      expect(result.verdict).toBe('allowed');
    });

    it('rejects when CIDR matches but port does not', () => {
      const policy = makePolicy({
        egressRules: [
          {
            action: 'Allow',
            protocol: 'TCP',
            destination: { nets: ['8.8.8.0/24'], ports: [53] },
          },
        ],
      });
      const spec: TrafficSpec = { ip: '8.8.8.8', port: 80, protocol: 'TCP' };
      const result = testAccess(policy, 'egress', spec);
      expect(result.verdict).toBe('denied');
      expect(result.appliedDefault).toBe(true);
    });
  });

  // --- ServiceAccount-based rules ---
  describe('service account rules', () => {
    it('matches SA by name', () => {
      const policy = makePolicy({
        ingressRules: [
          {
            action: 'Allow',
            source: { serviceAccounts: { names: ['backend-api'] } },
          },
        ],
      });
      const spec: TrafficSpec = { serviceAccountName: 'backend-api' };
      const result = testAccess(policy, 'ingress', spec);
      expect(result.verdict).toBe('allowed');
    });
  });
});
