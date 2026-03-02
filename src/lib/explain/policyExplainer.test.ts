import { describe, it, expect } from 'vitest';
import { explainPolicy } from './policyExplainer';
import type { ResolvedPolicy, Rule, CalicoPolicy } from '../../types/calico';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePolicy(overrides: Partial<ResolvedPolicy> & { name: string }): ResolvedPolicy {
  const rawSpec = {
    selector: overrides.selector ?? 'all()',
    tier: overrides.tier ?? 'default',
    order: overrides.order,
    types: overrides.types ?? ['Ingress'],
    ingress: overrides.ingressRules ?? [],
    egress: overrides.egressRules ?? [],
    preDNAT: (overrides as Record<string, unknown>).preDNAT as boolean | undefined,
    applyOnForward: (overrides as Record<string, unknown>).applyOnForward as boolean | undefined,
    doNotTrack: (overrides as Record<string, unknown>).doNotTrack as boolean | undefined,
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
// Section structure
// ---------------------------------------------------------------------------

describe('explainPolicy — section structure', () => {
  it('returns at least 4 sections (overview, defaults, ingress, egress)', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress', 'Egress'],
    });
    const sections = explainPolicy(policy);
    expect(sections.length).toBeGreaterThanOrEqual(4);
  });

  it('first section is Policy Overview with type "info"', () => {
    const policy = makePolicy({ name: 'test', namespace: 'default' });
    const sections = explainPolicy(policy);
    expect(sections[0].title).toBe('Policy Overview');
    expect(sections[0].type).toBe('info');
  });

  it('includes Default Behavior section with type "warning"', () => {
    const policy = makePolicy({ name: 'test', namespace: 'default' });
    const sections = explainPolicy(policy);
    const defaultSection = sections.find(s => s.title === 'Default Behavior');
    expect(defaultSection).toBeTruthy();
    expect(defaultSection!.type).toBe('warning');
  });
});

// ---------------------------------------------------------------------------
// Policy Overview
// ---------------------------------------------------------------------------

describe('explainPolicy — Policy Overview', () => {
  it('includes kind, name, namespace, tier, selector, types', () => {
    const policy = makePolicy({
      name: 'my-policy',
      namespace: 'prod',
      kind: 'NetworkPolicy',
      selector: "app == 'web'",
      tier: 'security',
      types: ['Ingress', 'Egress'],
    });
    const sections = explainPolicy(policy);
    const overview = sections[0].items;

    expect(overview).toContain('Kind: NetworkPolicy');
    expect(overview).toContain('Name: my-policy');
    expect(overview).toContain('Namespace: prod');
    expect(overview).toContain('Tier: security');
    expect(overview).toContain("Applies to: app == 'web'");
    expect(overview).toContain('Policy types: Ingress, Egress');
  });

  it('excludes namespace for global policies', () => {
    const policy = makePolicy({
      name: 'global-test',
      kind: 'GlobalNetworkPolicy',
    });
    const sections = explainPolicy(policy);
    const hasNamespace = sections[0].items.some(i => i.startsWith('Namespace:'));
    expect(hasNamespace).toBe(false);
  });

  it('includes order with priority label', () => {
    const lowPriority = makePolicy({ name: 'test', order: 10000 });
    const highPriority = makePolicy({ name: 'test2', order: 50 });
    const medPriority = makePolicy({ name: 'test3', order: 500 });

    const lowSections = explainPolicy(lowPriority);
    const highSections = explainPolicy(highPriority);
    const medSections = explainPolicy(medPriority);

    expect(lowSections[0].items.find(i => i.startsWith('Order:'))).toContain('low priority');
    expect(highSections[0].items.find(i => i.startsWith('Order:'))).toContain('high priority');
    expect(medSections[0].items.find(i => i.startsWith('Order:'))).toContain('medium priority');
  });

  it('includes namespace selector when present', () => {
    const policy = makePolicy({
      name: 'test',
      namespaceSelector: "env == 'prod'",
    });
    const sections = explainPolicy(policy);
    expect(sections[0].items).toContain("Namespace selector: env == 'prod'");
  });

  it('shows Kubernetes source details for networking.k8s.io/v1 policies', () => {
    const policy = makePolicy({
      name: 'k8s-policy',
      policySource: 'kubernetes',
      apiVersion: 'networking.k8s.io/v1',
      tier: 'kubernetes',
    });

    const sections = explainPolicy(policy);
    expect(sections[0].items).toContain('Source: Kubernetes networking.k8s.io/v1');
    const hasTier = sections[0].items.some(i => i.startsWith('Tier:'));
    expect(hasTier).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Default Behavior
// ---------------------------------------------------------------------------

describe('explainPolicy — Default Behavior', () => {
  it('shows deny for managed ingress', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressDefault: 'deny',
    });
    const sections = explainPolicy(policy);
    const defaults = sections.find(s => s.title === 'Default Behavior')!;
    expect(defaults.items.some(i => i.includes('Ingress default: DENY'))).toBe(true);
  });

  it('shows "Not managed" for unmanaged egress', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
    });
    const sections = explainPolicy(policy);
    const defaults = sections.find(s => s.title === 'Default Behavior')!;
    expect(defaults.items.some(i => i.includes('Egress: Not managed'))).toBe(true);
  });

  it('shows effective ALLOW when catch-all allow overrides deny', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressDefault: 'deny',
      ingressRules: [
        makeRule({ action: 'Allow' }), // catch-all
      ],
    });
    const sections = explainPolicy(policy);
    const defaults = sections.find(s => s.title === 'Default Behavior')!;
    expect(defaults.items.some(i => i.includes('Ingress effective default: ALLOW'))).toBe(true);
  });

  it('shows DENY with deny-rule note when restricted Deny precedes catch-all Allow (egress)', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Allow', destination: { nets: ['10.211.76.209/32'], ports: [80] }, protocol: 'TCP' }),
        makeRule({ action: 'Deny', destination: { nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] } }),
        makeRule({ action: 'Allow', destination: { nets: ['0.0.0.0/0'] } }),
      ],
    });
    const sections = explainPolicy(policy);
    const defaults = sections.find(s => s.title === 'Default Behavior')!;
    expect(defaults.items.some(i => i.includes('deny rules restrict traffic before the catch-all allow'))).toBe(true);
  });

  it('shows DENY with deny-rule note when restricted Deny precedes catch-all Allow (ingress)', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressDefault: 'deny',
      ingressRules: [
        makeRule({ action: 'Deny', source: { selector: 'app == "blocked"' } }),
        makeRule({ action: 'Allow' }), // catch-all
      ],
    });
    const sections = explainPolicy(policy);
    const defaults = sections.find(s => s.title === 'Default Behavior')!;
    expect(defaults.items.some(i => i.includes('deny rules restrict traffic before the catch-all allow'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Ingress rules
// ---------------------------------------------------------------------------

describe('explainPolicy — Ingress rules', () => {
  it('describes managed ingress rules', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          protocol: 'TCP',
          source: { selector: "app == 'api'" },
          destination: { ports: [80, 443] },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'));
    expect(ingressSection).toBeTruthy();
    expect(ingressSection!.type).toBe('ingress');
    expect(ingressSection!.items[0]).toContain('[+] Allow');
    expect(ingressSection!.items[0]).toContain('TCP');
    expect(ingressSection!.items[0]).toContain("app == 'api'");
  });

  it('describes unmanaged ingress as "All traffic allowed"', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title === 'Ingress (not managed)');
    expect(ingressSection).toBeTruthy();
    expect(ingressSection!.items[0]).toContain('All traffic allowed');
  });

  it('includes well-known port names', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          source: { ports: [443] },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    expect(ingressSection.items[0]).toContain('HTTPS');
  });

  it('includes inferred statuses after rules', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow', source: { selector: "app == 'api'" } }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    // Should contain separator and inferred statuses
    expect(ingressSection.items).toContain('---');
    const statusItems = ingressSection.items.filter(i => i.startsWith('['));
    expect(statusItems.length).toBeGreaterThanOrEqual(2); // At least namespace + cluster statuses
  });
});

// ---------------------------------------------------------------------------
// Egress rules
// ---------------------------------------------------------------------------

describe('explainPolicy — Egress rules', () => {
  it('describes managed egress rules', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({
          action: 'Allow',
          protocol: 'UDP',
          destination: { nets: ['169.254.25.10/32'], ports: [53] },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'));
    expect(egressSection).toBeTruthy();
    expect(egressSection!.type).toBe('egress');
    expect(egressSection!.items[0]).toContain('[+] Allow');
    expect(egressSection!.items[0]).toContain('UDP');
    expect(egressSection!.items[0]).toContain('53 (DNS)');
    expect(egressSection!.items[0]).toContain('169.254.25.10/32');
  });

  it('describes deny rules with [x] prefix', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Deny', destination: { nets: ['0.0.0.0/0'] } }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('[x] Deny');
  });

  it('describes log rules with [!] prefix', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Log' }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('[!] Log');
  });

  it('describes pass rules with [~] prefix', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Pass' }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('[~] Pass');
  });
});

// ---------------------------------------------------------------------------
// Policy flags
// ---------------------------------------------------------------------------

describe('explainPolicy — Policy Flags', () => {
  it('shows preDNAT section when enabled', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      preDNAT: true,
    } as Partial<ResolvedPolicy> & { name: string; preDNAT: boolean });

    const sections = explainPolicy(policy);
    const flagSection = sections.find(s => s.title === 'Policy Flags');
    expect(flagSection).toBeTruthy();
    expect(flagSection!.items.some(i => i.includes('preDNAT: ENABLED'))).toBe(true);
  });

  it('shows applyOnForward section when enabled', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      applyOnForward: true,
    } as Partial<ResolvedPolicy> & { name: string; applyOnForward: boolean });

    const sections = explainPolicy(policy);
    const flagSection = sections.find(s => s.title === 'Policy Flags');
    expect(flagSection).toBeTruthy();
    expect(flagSection!.items.some(i => i.includes('applyOnForward: ENABLED'))).toBe(true);
  });

  it('shows doNotTrack section when enabled', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      doNotTrack: true,
    } as Partial<ResolvedPolicy> & { name: string; doNotTrack: boolean });

    const sections = explainPolicy(policy);
    const flagSection = sections.find(s => s.title === 'Policy Flags');
    expect(flagSection).toBeTruthy();
    expect(flagSection!.items.some(i => i.includes('doNotTrack: ENABLED'))).toBe(true);
  });

  it('shows combined effect when preDNAT + applyOnForward', () => {
    const policy = makePolicy({
      name: 'test',
      kind: 'GlobalNetworkPolicy',
      preDNAT: true,
      applyOnForward: true,
    } as Partial<ResolvedPolicy> & { name: string; preDNAT: boolean; applyOnForward: boolean });

    const sections = explainPolicy(policy);
    const flagSection = sections.find(s => s.title === 'Policy Flags')!;
    expect(flagSection.items.some(i => i.includes('Combined effect'))).toBe(true);
  });

  it('omits Policy Flags section when no flags are set', () => {
    const policy = makePolicy({ name: 'test' });
    const sections = explainPolicy(policy);
    const flagSection = sections.find(s => s.title === 'Policy Flags');
    expect(flagSection).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Rule description details
// ---------------------------------------------------------------------------

describe('explainPolicy — rule descriptions', () => {
  it('describes rules with CIDRs', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Allow', destination: { nets: ['10.0.0.0/8', '172.16.0.0/12'] } }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('10.0.0.0/8');
    expect(egressSection.items[0]).toContain('172.16.0.0/12');
  });

  it('summarizes many CIDRs', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({
          action: 'Allow',
          destination: { nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'] },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('4 CIDR ranges');
  });

  it('describes namespace selector', () => {
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
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    expect(ingressSection.items[0]).toContain("namespaces matching: env == 'prod'");
  });

  it('describes services', () => {
    const policy = makePolicy({
      name: 'test',
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
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('service: kube-system/kube-dns');
  });

  it('describes service accounts by name', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          source: { serviceAccounts: { names: ['coredns', 'default'] } },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    expect(ingressSection.items[0]).toContain('service accounts: coredns, default');
  });

  it('describes service accounts by selector', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          source: { serviceAccounts: { selector: "role == 'dns'" } },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    expect(ingressSection.items[0]).toContain("service accounts matching: role == 'dns'");
  });

  it('describes negation fields (notNets, notPorts, notSelector)', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({
          action: 'Allow',
          destination: {
            nets: ['10.0.0.0/8'],
            notNets: ['10.0.1.0/24'],
            notPorts: [8080],
            notSelector: "app == 'internal'",
          },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('excluding 10.0.1.0/24');
    expect(egressSection.items[0]).toContain('excluding ports 8080');
    expect(egressSection.items[0]).toContain("excluding pods matching: app == 'internal'");
  });

  it('describes "from any source" for unrestricted ingress rules', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Ingress'],
      ingressRules: [
        makeRule({ action: 'Allow' }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    expect(ingressSection.items[0]).toContain('from any source');
  });

  it('describes "to any destination" for unrestricted egress rules', () => {
    const policy = makePolicy({
      name: 'test',
      types: ['Egress'],
      egressDefault: 'deny',
      ingressDefault: 'allow',
      egressRules: [
        makeRule({ action: 'Allow' }),
      ],
    });
    const sections = explainPolicy(policy);
    const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
    expect(egressSection.items[0]).toContain('to any destination');
  });

  it('describes opposite-side match criteria', () => {
    const policy = makePolicy({
      name: 'test',
      namespace: 'default',
      types: ['Ingress'],
      ingressRules: [
        makeRule({
          action: 'Allow',
          source: { selector: "app == 'api'" },
          destination: { ports: [80, 443] },
        }),
      ],
    });
    const sections = explainPolicy(policy);
    const ingressSection = sections.find(s => s.title.startsWith('Ingress Rules'))!;
    // Should describe destination ports (opposite side for ingress)
    expect(ingressSection.items[0]).toContain('dst port');
    expect(ingressSection.items[0]).toContain('80 (HTTP)');
    expect(ingressSection.items[0]).toContain('443 (HTTPS)');
  });
});

// ---------------------------------------------------------------------------
// Well-known port detection
// ---------------------------------------------------------------------------

describe('explainPolicy — well-known ports', () => {
  const portTests: Array<[number, string]> = [
    [53, 'DNS'],
    [80, 'HTTP'],
    [443, 'HTTPS'],
    [22, 'SSH'],
    [3306, 'MySQL'],
    [5432, 'PostgreSQL'],
    [6379, 'Redis'],
    [6443, 'K8s API'],
    [9090, 'Prometheus'],
    [2379, 'etcd'],
    [10250, 'Kubelet'],
  ];

  for (const [port, label] of portTests) {
    it(`recognizes port ${port} as ${label}`, () => {
      const policy = makePolicy({
        name: 'test',
        types: ['Egress'],
        egressDefault: 'deny',
        ingressDefault: 'allow',
        egressRules: [
          makeRule({ action: 'Allow', destination: { ports: [port] } }),
        ],
      });
      const sections = explainPolicy(policy);
      const egressSection = sections.find(s => s.title.startsWith('Egress Rules'))!;
      expect(egressSection.items[0]).toContain(label);
    });
  }
});
