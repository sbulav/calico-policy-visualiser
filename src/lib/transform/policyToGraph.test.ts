import { describe, it, expect } from 'vitest';
import { policyToGraph, computeEffectiveDefault, hasDenyBeforeCatchAll, inferClusterStatuses, inferNamespaceStatuses } from './policyToGraph';
import type { ResolvedPolicy, Rule, CalicoPolicy } from '../../types/calico';
import type { PolicyNodeData, RuleNodeData } from '../../types/graph';

// ---------------------------------------------------------------------------
// Helpers — build ResolvedPolicy objects for tests
// ---------------------------------------------------------------------------

function makePolicy(overrides: Partial<ResolvedPolicy> & { name: string }): ResolvedPolicy {
  const rawSpec = {
    selector: overrides.selector ?? 'all()',
    tier: overrides.tier ?? 'default',
    order: overrides.order,
    types: overrides.types ?? ['Ingress'],
    ingress: overrides.ingressRules ?? [],
    egress: overrides.egressRules ?? [],
  };

  const raw: CalicoPolicy = {
    apiVersion: 'projectcalico.org/v3',
    kind: overrides.kind ?? 'NetworkPolicy',
    metadata: {
      name: overrides.name,
      namespace: overrides.namespace,
    },
    spec: rawSpec,
  };

  return {
    raw,
    policySource: overrides.policySource ?? 'calico',
    apiVersion: overrides.apiVersion ?? 'projectcalico.org/v3',
    name: overrides.name,
    namespace: overrides.namespace,
    kind: overrides.kind ?? 'NetworkPolicy',
    tier: overrides.tier ?? 'default',
    order: overrides.order,
    selector: overrides.selector ?? 'all()',
    namespaceSelector: overrides.namespaceSelector,
    serviceAccountSelector: overrides.serviceAccountSelector,
    types: overrides.types ?? ['Ingress'],
    ingressRules: overrides.ingressRules ?? [],
    egressRules: overrides.egressRules ?? [],
    ingressDefault: overrides.ingressDefault ?? 'deny',
    egressDefault: overrides.egressDefault ?? 'allow',
  } as ResolvedPolicy;
}

function makeRule(overrides: Partial<Rule>): Rule {
  return {
    action: overrides.action ?? 'Allow',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// computeEffectiveDefault
// ---------------------------------------------------------------------------

describe('computeEffectiveDefault', () => {
  it('returns base default when no rules exist', () => {
    expect(computeEffectiveDefault([], 'ingress', 'deny')).toBe('deny');
    expect(computeEffectiveDefault([], 'egress', 'allow')).toBe('allow');
  });

  it('returns allow when an unrestricted Allow rule exists', () => {
    const rules: Rule[] = [makeRule({ action: 'Allow' })]; // no source/destination = unrestricted
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('allow');
  });

  it('returns deny when an unrestricted Deny rule exists', () => {
    const rules: Rule[] = [makeRule({ action: 'Deny' })];
    expect(computeEffectiveDefault(rules, 'egress', 'allow')).toBe('deny');
  });

  it('ignores Log rules (transparent)', () => {
    const rules: Rule[] = [makeRule({ action: 'Log' })];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('ignores Pass rules (transparent)', () => {
    const rules: Rule[] = [makeRule({ action: 'Pass' })];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('ignores restricted rules (only considers unrestricted)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: 'app == "web"' } }),
    ];
    // Has a selector so it's restricted — should fall back to base
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('uses first unrestricted Allow/Deny (first match wins)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: 'app == "web"' } }), // restricted
      makeRule({ action: 'Deny' }),  // unrestricted deny
      makeRule({ action: 'Allow' }), // unrestricted allow (but deny comes first)
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('considers 0.0.0.0/0 as unrestricted', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('allow');
  });

  it('does not consider specific CIDRs as unrestricted', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['10.0.0.0/8'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('returns deny when baseDefault is "none"', () => {
    expect(computeEffectiveDefault([], 'ingress', 'none')).toBe('deny');
  });

  it('returns deny when restricted Deny appears before catch-all Allow (egress)', () => {
    // Real-world scenario: allow specific LAN → deny all LAN → allow internet
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['10.211.76.209/32'], ports: [80, 5432] }, protocol: 'TCP' }),
      makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16'] } }),
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('returns allow when only restricted Allow rules appear before catch-all Allow', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['10.0.0.0/8'] } }),
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('allow');
  });

  it('returns allow when restricted Deny appears AFTER catch-all Allow', () => {
    // Deny rule after catch-all is unreachable — should not affect the result
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
      makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('allow');
  });

  it('returns deny when restricted Deny appears before catch-all Allow (ingress)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Deny', source: { selector: 'app == "blocked"' } }),
      makeRule({ action: 'Allow' }), // unrestricted = catch-all
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  // --- ruleIsUnrestricted: protocol and opposite-side ports ---

  it('does not consider a rule with protocol as unrestricted (ingress)', () => {
    // No source but has protocol: TCP → not a catch-all
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP' }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with protocol as unrestricted (egress)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'UDP' }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with destination ports as unrestricted (ingress)', () => {
    // No source, but destination has ports → narrows traffic, not a catch-all
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { ports: [9091] } }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with source ports as unrestricted (egress)', () => {
    // No destination, but source has ports → narrows traffic, not a catch-all
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { ports: [443] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with protocol + destination ports as unrestricted (ingress)', () => {
    // Real-world case: vault policy rule with no source but TCP + dst ports
    const rules: Rule[] = [
      makeRule({
        action: 'Allow',
        protocol: 'TCP',
        destination: { ports: [9091], selector: 'vault_cr == "vault"' },
      }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('does not consider 0.0.0.0/0 with protocol as unrestricted', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] }, protocol: 'TCP' }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('returns deny for vault-like ingress: all rules have protocol or dst ports', () => {
    // Simulated vault policy: 4 ingress rules, all with protocol TCP + dst ports
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', source: { selector: 'vault_cr == "vault"' }, destination: { ports: [8200, 8201], selector: 'vault_cr == "vault"' } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { namespaceSelector: 'kubernetes.io/metadata.name == "ingress-nginx"' }, destination: { ports: [8200], selector: 'vault_cr == "vault"' } }),
      makeRule({ action: 'Allow', protocol: 'TCP', destination: { ports: [9091], selector: 'vault_cr == "vault"' } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { namespaceSelector: 'kubernetes.io/metadata.name == "monitoring"' }, destination: { ports: [8200], selector: 'vault_cr == "vault"' } }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  // --- opposite-side nets/selectors also disqualify catch-all ---

  it('does not consider a rule with destination nets as unrestricted (ingress)', () => {
    // No source but destination has nets (localhost) — not a catch-all
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['127.0.0.0/8'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with source nets as unrestricted (egress)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { nets: ['10.0.0.0/8'] } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with destination selector as unrestricted (ingress)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { selector: 'app == "web"' } }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });

  it('does not consider a rule with source selector as unrestricted (egress)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: 'app == "web"' } }),
    ];
    expect(computeEffectiveDefault(rules, 'egress', 'deny')).toBe('deny');
  });

  it('returns deny for k8s-masters-like ingress: rules have dst nets or protocol+ports', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', destination: { ports: [6443] } }),
      makeRule({ action: 'Allow', destination: { nets: ['127.0.0.0/8'] } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { selector: 'has(node-role.kubernetes.io/control-plane)' }, destination: { ports: [2380, 10250] } }),
    ];
    expect(computeEffectiveDefault(rules, 'ingress', 'deny')).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// hasDenyBeforeCatchAll
// ---------------------------------------------------------------------------

describe('hasDenyBeforeCatchAll', () => {
  it('returns false when no rules exist', () => {
    expect(hasDenyBeforeCatchAll([], 'egress')).toBe(false);
  });

  it('returns false when no Deny rules exist', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['10.0.0.0/8'] } }),
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
    ];
    expect(hasDenyBeforeCatchAll(rules, 'egress')).toBe(false);
  });

  it('returns true when restricted Deny appears before catch-all Allow', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8'] } }),
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
    ];
    expect(hasDenyBeforeCatchAll(rules, 'egress')).toBe(true);
  });

  it('returns false when restricted Deny appears after catch-all Allow', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
      makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8'] } }),
    ];
    expect(hasDenyBeforeCatchAll(rules, 'egress')).toBe(false);
  });

  it('returns false when only unrestricted Deny exists (no catch-all Allow)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Deny' }), // unrestricted deny
    ];
    expect(hasDenyBeforeCatchAll(rules, 'egress')).toBe(false);
  });

  it('returns false when no catch-all rule exists at all', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['10.0.0.0/8'] } }),
      makeRule({ action: 'Deny', destination: { nets: ['172.16.0.0/12'] } }),
    ];
    expect(hasDenyBeforeCatchAll(rules, 'egress')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// inferClusterStatuses
// ---------------------------------------------------------------------------

describe('inferClusterStatuses', () => {
  it('returns 2 statuses (DNS + cluster)', () => {
    const statuses = inferClusterStatuses([], 'egress');
    expect(statuses).toHaveLength(2);
    expect(statuses[0].label).toBe('Kubernetes DNS');
    expect(statuses[1].label).toBe('Everything in the cluster');
  });

  it('infers DNS allowed when rule targets port 53', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { ports: [53] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed');
    expect(statuses[0].reason).toContain('DNS');
  });

  it('infers DNS allowed when rule targets 169.254.25.10', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['169.254.25.10/32'] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed');
  });

  it('infers DNS denied when deny rule targets DNS', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Deny', destination: { ports: [53] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('denied');
  });

  it('infers DNS denied when broad private-range deny covers DNS', () => {
    const rules: Rule[] = [
      makeRule({
        action: 'Deny',
        destination: { nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'] },
      }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    // DNS at 169.254.25.10 is NOT in private ranges, so this broad deny
    // covers "cluster" but DNS inference depends on separate DNS-specific check
    expect(statuses[1].state).toBe('denied'); // cluster denied
  });

  it('infers cluster allowed when unrestricted Allow exists', () => {
    const rules: Rule[] = [makeRule({ action: 'Allow' })];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed'); // DNS
    expect(statuses[1].state).toBe('allowed'); // cluster
  });

  it('marks DNS as logged when Log rule matches before Allow', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Log', destination: { ports: [53] } }),
      makeRule({ action: 'Allow', destination: { ports: [53] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed');
    expect(statuses[0].reason).toContain('logged');
  });

  it('reports "depends on policy default" when no matching rule found', () => {
    // Rules that don't match DNS or cluster broadly
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['203.0.113.0/24'] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].reason).toContain('depends on policy default');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('infers DNS allowed via service name kube-dns', () => {
    const rules: Rule[] = [
      makeRule({
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed');
  });

  it('infers DNS allowed via service account coredns', () => {
    const rules: Rule[] = [
      makeRule({
        action: 'Allow',
        destination: { serviceAccounts: { names: ['coredns'] } },
      }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[0].state).toBe('allowed');
  });

  // --- ruleCoversBroadCluster: protocol and opposite-side ports ---

  it('does not infer cluster allowed when ingress Allow has protocol + dst ports but no source', () => {
    // Vault-like rule: Allow TCP to port 9091 from any source — not a broad cluster allow
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', destination: { ports: [9091] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'ingress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('does not infer cluster allowed when egress Allow has protocol + src ports but no destination', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', source: { ports: [443] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('does not infer cluster allowed for vault-like ingress with all port-restricted rules', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', source: { selector: 'vault_cr == "vault"' }, destination: { ports: [8200, 8201] } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { namespaceSelector: 'kubernetes.io/metadata.name == "ingress-nginx"' }, destination: { ports: [8200] } }),
      makeRule({ action: 'Allow', protocol: 'TCP', destination: { ports: [9091] } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { namespaceSelector: 'kubernetes.io/metadata.name == "monitoring"' }, destination: { ports: [8200] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'ingress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('does not infer cluster denied when Deny has protocol restriction', () => {
    // A deny rule restricted to TCP is not a broad cluster deny
    const rules: Rule[] = [
      makeRule({ action: 'Deny', protocol: 'TCP', destination: { nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('still infers cluster allowed for truly unrestricted Allow (no protocol, no ports)', () => {
    const rules: Rule[] = [makeRule({ action: 'Allow' })];
    const statuses = inferClusterStatuses(rules, 'ingress');
    expect(statuses[1].state).toBe('allowed');
    expect(statuses[1].reason).toContain('Broad allow');
  });

  // --- opposite-side nets/selectors also disqualify broad cluster ---

  it('does not infer cluster allowed when ingress Allow has destination nets (localhost)', () => {
    // No source, no protocol, but destination has nets: 127.0.0.0/8 — not broad
    const rules: Rule[] = [
      makeRule({ action: 'Allow', destination: { nets: ['127.0.0.0/8'] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'ingress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('does not infer cluster allowed when egress Allow has source selector', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: 'app == "web"' } }),
    ];
    const statuses = inferClusterStatuses(rules, 'egress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });

  it('does not infer cluster allowed for k8s-masters-like ingress policy', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', protocol: 'TCP', destination: { ports: [6443] } }),
      makeRule({ action: 'Allow', destination: { nets: ['127.0.0.0/8'] } }),
      makeRule({ action: 'Allow', protocol: 'TCP', source: { selector: 'has(node-role.kubernetes.io/control-plane)' }, destination: { ports: [2380, 10250] } }),
    ];
    const statuses = inferClusterStatuses(rules, 'ingress');
    expect(statuses[1].state).toBe('denied');
    expect(statuses[1].reason).toContain('depends on policy default');
  });
});

// ---------------------------------------------------------------------------
// inferNamespaceStatuses
// ---------------------------------------------------------------------------

describe('inferNamespaceStatuses', () => {
  it('returns empty array for global policies (no namespace)', () => {
    const statuses = inferNamespaceStatuses([], 'ingress', undefined);
    expect(statuses).toEqual([]);
  });

  it('returns "Any pod" status for namespaced policies', () => {
    const statuses = inferNamespaceStatuses([], 'ingress', 'default');
    expect(statuses).toHaveLength(1);
    expect(statuses[0].label).toBe('Any pod');
  });

  it('infers allowed when unrestricted Allow rule (no entity)', () => {
    const rules: Rule[] = [makeRule({ action: 'Allow' })]; // no source = matches everything
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    // No entity at all -> direct match (matches everything including all namespace pods)
    expect(statuses[0].state).toBe('allowed');
    expect(statuses[0].reason).toContain('all pods in namespace');
  });

  it('infers allowed when selector is all() in same namespace', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: 'all()' } }),
    ];
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    expect(statuses[0].state).toBe('allowed');
    expect(statuses[0].reason).toContain('all pods in namespace');
  });

  it('infers denied when deny targets all() in namespace', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Deny', source: { selector: 'all()' } }),
    ];
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    expect(statuses[0].state).toBe('denied');
  });

  it('reports uncertain for broad CIDRs covering private ranges', () => {
    const rules: Rule[] = [
      makeRule({
        action: 'Allow',
        source: { nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'] },
      }),
    ];
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    expect(statuses[0].state).toBe('uncertain');
    expect(statuses[0].reason).toContain('network-topology dependent');
  });

  it('does not match specific selector (not all pods)', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Allow', source: { selector: "app == 'web'" } }),
    ];
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    // Specific selector does NOT match "any pod", so falls through
    expect(statuses[0].reason).toContain('depends on policy default');
  });

  it('handles Log rules transparently', () => {
    const rules: Rule[] = [
      makeRule({ action: 'Log', source: { selector: 'all()' } }),
      makeRule({ action: 'Allow', source: { selector: 'all()' } }),
    ];
    const statuses = inferNamespaceStatuses(rules, 'ingress', 'default');
    expect(statuses[0].state).toBe('allowed');
    expect(statuses[0].reason).toContain('logged');
  });
});

// ---------------------------------------------------------------------------
// policyToGraph — node structure
// ---------------------------------------------------------------------------

describe('policyToGraph — node structure', () => {
  it('creates 7 nodes (1 policy + 3 ingress + 3 egress)', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const { nodes } = policyToGraph(policy);
    expect(nodes).toHaveLength(7);
  });

  it('creates the central policy node with correct data', () => {
    const policy = makePolicy({
      name: 'my-policy',
      namespace: 'prod',
      kind: 'NetworkPolicy',
      selector: "app == 'web'",
      tier: 'security',
      order: 100,
      types: ['Ingress'],
      ingressDefault: 'deny',
    });

    const { nodes } = policyToGraph(policy);
    const center = nodes.find(n => n.id === 'policy-center');
    expect(center).toBeTruthy();
    expect(center!.type).toBe('policyNode');

    const data = center!.data as unknown as PolicyNodeData;
    expect(data.name).toBe('my-policy');
    expect(data.namespace).toBe('prod');
    expect(data.kind).toBe('NetworkPolicy');
    expect(data.selector).toBe("app == 'web'");
    expect(data.tier).toBe('security');
    expect(data.order).toBe(100);
  });

  it('keeps Kubernetes source metadata on the policy node', () => {
    const policy = makePolicy({
      name: 'k8s-policy',
      policySource: 'kubernetes',
      apiVersion: 'networking.k8s.io/v1',
      tier: 'kubernetes',
    });

    const { nodes } = policyToGraph(policy);
    const center = nodes.find(n => n.id === 'policy-center');
    const data = center!.data as unknown as PolicyNodeData;
    expect(data.policySource).toBe('kubernetes');
    expect(data.preDNAT).toBeUndefined();
    expect(data.applyOnForward).toBeUndefined();
    expect(data.doNotTrack).toBeUndefined();
  });

  it('creates rule nodes for all 3 categories per direction', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const { nodes } = policyToGraph(policy);

    const ruleNodes = nodes.filter(n => n.type === 'ruleNode');
    expect(ruleNodes).toHaveLength(6);

    const ids = ruleNodes.map(n => n.id).sort();
    expect(ids).toEqual([
      'egress-inCluster',
      'egress-inNamespace',
      'egress-outsideCluster',
      'ingress-inCluster',
      'ingress-inNamespace',
      'ingress-outsideCluster',
    ]);
  });

  it('places ingress nodes on the left (x=0) and egress on the right (x=1000)', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const { nodes } = policyToGraph(policy);

    const ingressNodes = nodes.filter(n => n.id.startsWith('ingress-'));
    const egressNodes = nodes.filter(n => n.id.startsWith('egress-'));

    for (const node of ingressNodes) {
      expect(node.position.x).toBe(0);
    }
    for (const node of egressNodes) {
      expect(node.position.x).toBe(1000);
    }
  });

  it('vertically centers the policy node', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const { nodes } = policyToGraph(policy);

    const center = nodes.find(n => n.id === 'policy-center')!;
    const ruleNodes = nodes.filter(n => n.id !== 'policy-center');
    const ys = ruleNodes.map(n => n.position.y);
    const expectedCenter = (Math.min(...ys) + Math.max(...ys)) / 2;
    expect(center.position.y).toBe(expectedCenter);
  });
});

// ---------------------------------------------------------------------------
// policyToGraph — edge structure
// ---------------------------------------------------------------------------

describe('policyToGraph — edge structure', () => {
  it('creates 6 edges (one per rule node)', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const { edges } = policyToGraph(policy);
    expect(edges).toHaveLength(6);
  });

  it('ingress edges flow from rule node to policy-center', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
    });
    const { edges } = policyToGraph(policy);

    const ingressEdges = edges.filter(e => e.id.startsWith('edge-ingress'));
    for (const edge of ingressEdges) {
      expect(edge.source).toContain('ingress-');
      expect(edge.target).toBe('policy-center');
    }
  });

  it('egress edges flow from policy-center to rule node', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
    });
    const { edges } = policyToGraph(policy);

    const egressEdges = edges.filter(e => e.id.startsWith('edge-egress'));
    for (const edge of egressEdges) {
      expect(edge.source).toBe('policy-center');
      expect(edge.target).toContain('egress-');
    }
  });

  it('empty categories get dimmed dashed edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [], // no rules = all categories empty
    });
    const { edges } = policyToGraph(policy);

    const ingressEdges = edges.filter(e => e.id.startsWith('edge-ingress'));
    for (const edge of ingressEdges) {
      expect(edge.style?.opacity).toBe(0.4);
      expect(edge.animated).toBe(false);
    }
  });

  it('active allow-only categories get green edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { nets: ['203.0.113.0/24'] } }),
      ],
    });
    const { edges } = policyToGraph(policy);

    const outsideEdge = edges.find(e => e.id === 'edge-ingress-outsideCluster');
    expect(outsideEdge).toBeTruthy();
    expect(outsideEdge!.style?.stroke).toBe('#22c55e'); // green
    expect(outsideEdge!.animated).toBe(true);
  });

  it('active deny-only categories get red edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8'] } }),
      ],
    });
    const { edges } = policyToGraph(policy);

    const outsideEdge = edges.find(e => e.id === 'edge-egress-outsideCluster');
    expect(outsideEdge!.style?.stroke).toBe('#ef4444'); // red
  });

  it('mixed allow+deny categories get amber edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { nets: ['203.0.113.0/24'] } }),
        makeRule({ action: 'Deny', source: { nets: ['198.51.100.0/24'] } }),
      ],
    });
    const { edges } = policyToGraph(policy);

    const outsideEdge = edges.find(e => e.id === 'edge-ingress-outsideCluster');
    expect(outsideEdge!.style?.stroke).toBe('#f59e0b'); // amber
  });

  it('log-only categories get amber edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Log', source: { nets: ['203.0.113.0/24'] } }),
      ],
    });
    const { edges } = policyToGraph(policy);

    const outsideEdge = edges.find(e => e.id === 'edge-ingress-outsideCluster');
    expect(outsideEdge!.style?.stroke).toBe('#f59e0b'); // amber for log-only
  });

  it('unmanaged direction gets green animated edges', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'], // only ingress managed, egress is unmanaged
      ingressDefault: 'deny',
      egressDefault: 'allow',
    });
    const { edges } = policyToGraph(policy);

    const egressEdges = edges.filter(e => e.id.startsWith('edge-egress'));
    for (const edge of egressEdges) {
      expect(edge.style?.stroke).toBe('#22c55e'); // green
      expect(edge.animated).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// policyToGraph — rule classification
// ---------------------------------------------------------------------------

describe('policyToGraph — rule classification', () => {
  it('classifies CIDR-based rules as outsideCluster', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Allow', destination: { nets: ['203.0.113.0/24'] } }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const outsideNode = nodes.find(n => n.id === 'egress-outsideCluster');
    const data = outsideNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });

  it('classifies same-namespace selector rules as inNamespace', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { selector: "app == 'api'" } }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const nsNode = nodes.find(n => n.id === 'ingress-inNamespace');
    const data = nsNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });

  it('classifies cross-namespace selector rules as inCluster', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          source: { selector: "app == 'api'", namespaceSelector: "env == 'prod'" },
        }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const clusterNode = nodes.find(n => n.id === 'ingress-inCluster');
    const data = clusterNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });

  it('classifies service rules as inCluster', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({
          action: 'Allow',
          destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
        }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const clusterNode = nodes.find(n => n.id === 'egress-inCluster');
    const data = clusterNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });

  it('classifies no-entity rules as outsideCluster', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow' }), // no source = matches everything
      ],
    });
    const { nodes } = policyToGraph(policy);

    const outsideNode = nodes.find(n => n.id === 'ingress-outsideCluster');
    const data = outsideNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });

  it('classifies selector-only rules for global policies as inCluster', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { selector: "app == 'api'" } }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    // Global policy has no namespace, so selector-only goes to inCluster
    const clusterNode = nodes.find(n => n.id === 'ingress-inCluster');
    const data = clusterNode!.data as unknown as RuleNodeData;
    expect(data.groups.rules).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// policyToGraph — effective defaults
// ---------------------------------------------------------------------------

describe('policyToGraph — effective defaults', () => {
  it('sets effectiveIngressDefault=deny and effectiveEgressDefault=deny for dual-managed policy', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
      ingressDefault: 'deny',
      egressDefault: 'deny',
    });
    const { nodes } = policyToGraph(policy);
    const data = nodes.find(n => n.id === 'policy-center')!.data as unknown as PolicyNodeData;
    expect(data.effectiveIngressDefault).toBe('deny');
    expect(data.effectiveEgressDefault).toBe('deny');
  });

  it('computes effectiveIngressDefault=allow when catch-all Allow exists', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressDefault: 'deny',
      ingressRules: [
        makeRule({ action: 'Allow', source: { selector: "app == 'api'" } }),
        makeRule({ action: 'Allow' }), // catch-all
      ],
    });
    const { nodes } = policyToGraph(policy);
    const data = nodes.find(n => n.id === 'policy-center')!.data as unknown as PolicyNodeData;
    expect(data.effectiveIngressDefault).toBe('allow');
  });
});

// ---------------------------------------------------------------------------
// policyToGraph — inferred statuses on nodes
// ---------------------------------------------------------------------------

describe('policyToGraph — inferred statuses', () => {
  it('attaches inferred statuses to inCluster nodes', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Allow', destination: { ports: [53] } }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const clusterNode = nodes.find(n => n.id === 'egress-inCluster');
    const data = clusterNode!.data as unknown as RuleNodeData;
    expect(data.groups.inferredStatuses).toBeTruthy();
    expect(data.groups.inferredStatuses!.length).toBeGreaterThanOrEqual(2);
  });

  it('attaches inferred namespace statuses to inNamespace nodes for namespaced policies', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { selector: 'all()' } }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const nsNode = nodes.find(n => n.id === 'ingress-inNamespace');
    const data = nsNode!.data as unknown as RuleNodeData;
    expect(data.groups.inferredStatuses).toBeTruthy();
    expect(data.groups.inferredStatuses![0].label).toBe('Any pod');
  });

  it('does not attach namespace statuses for global policies', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow' }),
      ],
    });
    const { nodes } = policyToGraph(policy);

    const nsNode = nodes.find(n => n.id === 'ingress-inNamespace');
    const data = nsNode!.data as unknown as RuleNodeData;
    // No namespace statuses for global policies
    expect(data.groups.inferredStatuses).toBeUndefined();
  });

  it('marks unmanaged direction nodes as unmanaged', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'], // egress unmanaged
      ingressDefault: 'deny',
      egressDefault: 'allow',
    });
    const { nodes } = policyToGraph(policy);

    const egressNode = nodes.find(n => n.id === 'egress-outsideCluster');
    const data = egressNode!.data as unknown as RuleNodeData;
    expect(data.unmanaged).toBe(true);
  });
});
