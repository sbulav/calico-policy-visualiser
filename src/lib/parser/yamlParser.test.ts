import { describe, it, expect } from 'vitest';
import { parseYaml } from './yamlParser';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MINIMAL_NP = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress`;

const MINIMAL_GNP = `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: test-global-policy
spec:
  selector: all()
  types:
  - Ingress
  - Egress`;

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

describe('parseYaml — error cases', () => {
  it('returns error for empty input', () => {
    const result = parseYaml('');
    expect(result.policy).toBeNull();
    expect(result.error).toBe('Empty YAML input');
  });

  it('returns error for whitespace-only input', () => {
    const result = parseYaml('   \n\n  ');
    expect(result.policy).toBeNull();
    expect(result.error).toBe('Empty YAML input');
  });

  it('returns error for invalid YAML syntax', () => {
    const result = parseYaml('{{invalid: yaml::');
    expect(result.policy).toBeNull();
    expect(result.error).toBeTruthy();
  });

  it('returns error when YAML parses to a scalar', () => {
    const result = parseYaml('just a string');
    expect(result.policy).toBeNull();
    expect(result.error).toBe('YAML did not parse to an object');
  });

  it('returns error for wrong apiVersion', () => {
    const yaml = `apiVersion: v1
kind: NetworkPolicy
metadata:
  name: test
spec:
  selector: all()`;
    const result = parseYaml(yaml);
    expect(result.policy).toBeNull();
    expect(result.error).toContain('Unsupported apiVersion');
  });

  it('returns error for unsupported kind', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: ClusterNetworkPolicy
metadata:
  name: test
spec:
  selector: all()`;
    const result = parseYaml(yaml);
    expect(result.policy).toBeNull();
    expect(result.error).toContain('Unsupported kind');
  });

  it('returns error when metadata.name is missing', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  namespace: default
spec:
  selector: all()`;
    const result = parseYaml(yaml);
    expect(result.policy).toBeNull();
    expect(result.error).toBe('Missing metadata.name');
  });

  it('returns error when spec is missing', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test`;
    const result = parseYaml(yaml);
    expect(result.policy).toBeNull();
    expect(result.error).toBe('Missing spec');
  });
});

// ---------------------------------------------------------------------------
// Successful parsing — NetworkPolicy
// ---------------------------------------------------------------------------

describe('parseYaml — NetworkPolicy', () => {
  it('parses a minimal NetworkPolicy', () => {
    const result = parseYaml(MINIMAL_NP);
    expect(result.error).toBeNull();
    expect(result.policy).toBeTruthy();
    const p = result.policy!;
    expect(p.kind).toBe('NetworkPolicy');
    expect(p.name).toBe('test-policy');
    expect(p.namespace).toBe('default');
    expect(p.selector).toBe('all()');
    expect(p.tier).toBe('default');
    expect(p.types).toEqual(['Ingress']);
    expect(p.ingressRules).toEqual([]);
    expect(p.egressRules).toEqual([]);
  });

  it('resolves ingress and egress rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: multi-rule
  namespace: prod
spec:
  selector: app == 'web'
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: app == 'api'
    destination:
      ports:
      - 80
      - 443
  - action: Deny
    source:
      nets:
      - 0.0.0.0/0
  egress:
  - action: Allow
    destination:
      nets:
      - 10.0.0.0/8
      ports:
      - 53
    protocol: UDP`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const p = result.policy!;

    expect(p.types).toEqual(['Ingress', 'Egress']);
    expect(p.ingressRules).toHaveLength(2);
    expect(p.egressRules).toHaveLength(1);

    // Ingress rule details
    expect(p.ingressRules[0].action).toBe('Allow');
    expect(p.ingressRules[0].protocol).toBe('TCP');
    expect(p.ingressRules[0].source?.selector).toBe("app == 'api'");
    expect(p.ingressRules[0].destination?.ports).toEqual([80, 443]);

    expect(p.ingressRules[1].action).toBe('Deny');
    expect(p.ingressRules[1].source?.nets).toEqual(['0.0.0.0/0']);

    // Egress rule details
    expect(p.egressRules[0].action).toBe('Allow');
    expect(p.egressRules[0].protocol).toBe('UDP');
    expect(p.egressRules[0].destination?.nets).toEqual(['10.0.0.0/8']);
    expect(p.egressRules[0].destination?.ports).toEqual([53]);
  });

  it('uses custom tier and order', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: tiered-policy
  namespace: default
spec:
  tier: security
  order: 100
  selector: all()
  types:
  - Ingress`;

    const result = parseYaml(yaml);
    const p = result.policy!;
    expect(p.tier).toBe('security');
    expect(p.order).toBe(100);
  });

  it('sets namespaceSelector and serviceAccountSelector', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: ns-sa-policy
  namespace: default
spec:
  selector: all()
  namespaceSelector: env == 'prod'
  serviceAccountSelector: role == 'admin'
  types:
  - Ingress`;

    const result = parseYaml(yaml);
    const p = result.policy!;
    expect(p.namespaceSelector).toBe("env == 'prod'");
    expect(p.serviceAccountSelector).toBe("role == 'admin'");
  });
});

// ---------------------------------------------------------------------------
// Successful parsing — GlobalNetworkPolicy
// ---------------------------------------------------------------------------

describe('parseYaml — GlobalNetworkPolicy', () => {
  it('parses a minimal GlobalNetworkPolicy', () => {
    const result = parseYaml(MINIMAL_GNP);
    expect(result.error).toBeNull();
    const p = result.policy!;
    expect(p.kind).toBe('GlobalNetworkPolicy');
    expect(p.name).toBe('test-global-policy');
    expect(p.namespace).toBeUndefined();
    expect(p.types).toEqual(['Ingress', 'Egress']);
  });
});

// ---------------------------------------------------------------------------
// Type inference
// ---------------------------------------------------------------------------

describe('parseYaml — type inference', () => {
  it('infers Ingress when only ingress rules are present and types is omitted', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: infer-ingress
  namespace: default
spec:
  selector: all()
  ingress:
  - action: Allow`;

    const result = parseYaml(yaml);
    expect(result.policy!.types).toEqual(['Ingress']);
  });

  it('infers Egress when only egress rules are present and types is omitted', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: infer-egress
  namespace: default
spec:
  selector: all()
  egress:
  - action: Allow`;

    const result = parseYaml(yaml);
    expect(result.policy!.types).toEqual(['Egress']);
  });

  it('infers both types when ingress and egress rules are present', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: infer-both
  namespace: default
spec:
  selector: all()
  ingress:
  - action: Allow
  egress:
  - action: Allow`;

    const result = parseYaml(yaml);
    expect(result.policy!.types).toEqual(['Ingress', 'Egress']);
  });

  it('defaults to Ingress when no rules and no types', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: no-rules
  namespace: default
spec:
  selector: all()`;

    const result = parseYaml(yaml);
    expect(result.policy!.types).toEqual(['Ingress']);
  });
});

// ---------------------------------------------------------------------------
// Default behavior
// ---------------------------------------------------------------------------

describe('parseYaml — default behavior', () => {
  it('sets deny default for managed direction with rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: with-ingress
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      selector: app == 'api'`;

    const result = parseYaml(yaml);
    const p = result.policy!;
    expect(p.ingressDefault).toBe('deny');
    expect(p.egressDefault).toBe('allow'); // Egress not in types
  });

  it('sets deny default for managed direction without rules', () => {
    const result = parseYaml(MINIMAL_NP);
    const p = result.policy!;
    // Ingress is in types but has no rules -> deny
    expect(p.ingressDefault).toBe('deny');
  });

  it('sets allow default for unmanaged direction', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: egress-only
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow`;

    const result = parseYaml(yaml);
    const p = result.policy!;
    expect(p.ingressDefault).toBe('allow'); // Ingress not in types
    expect(p.egressDefault).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// ruleLineRanges
// ---------------------------------------------------------------------------

describe('parseYaml — ruleLineRanges', () => {
  it('returns ruleLineRanges for successful parse', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: line-test
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      selector: app == 'api'
  - action: Deny`;

    const result = parseYaml(yaml);
    expect(result.ruleLineRanges).toBeTruthy();
    expect(result.ruleLineRanges!.ingress).toHaveLength(2);
  });

  it('returns null ruleLineRanges on error', () => {
    const result = parseYaml('');
    expect(result.ruleLineRanges).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Complex policy features
// ---------------------------------------------------------------------------

describe('parseYaml — complex features', () => {
  it('parses HTTP match rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: http-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    http:
      methods:
      - GET
      - POST
      paths:
      - exact: /api/v1/health
      - prefix: /api/v2/`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.ingressRules[0];
    expect(rule.http?.methods).toEqual(['GET', 'POST']);
    expect(rule.http?.paths).toEqual([
      { exact: '/api/v1/health' },
      { prefix: '/api/v2/' },
    ]);
  });

  it('parses ICMP rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: icmp-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: ICMP
    icmp:
      type: 8
      code: 0`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.ingressRules[0];
    expect(rule.protocol).toBe('ICMP');
    expect(rule.icmp).toEqual({ type: 8, code: 0 });
  });

  it('parses notNets, notPorts, notSelector', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: negation-policy
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
      notNets:
      - 10.0.1.0/24
      ports:
      - 80
      notPorts:
      - 8080
      notSelector: app == 'db'`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.egressRules[0];
    expect(rule.destination?.nets).toEqual(['10.0.0.0/8']);
    expect(rule.destination?.notNets).toEqual(['10.0.1.0/24']);
    expect(rule.destination?.ports).toEqual([80]);
    expect(rule.destination?.notPorts).toEqual([8080]);
    expect(rule.destination?.notSelector).toBe("app == 'db'");
  });

  it('parses serviceAccounts in rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: sa-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      serviceAccounts:
        names:
        - coredns
        - default
        selector: role == 'dns'`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.ingressRules[0];
    expect(rule.source?.serviceAccounts?.names).toEqual(['coredns', 'default']);
    expect(rule.source?.serviceAccounts?.selector).toBe("role == 'dns'");
  });

  it('parses services in rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: svc-policy
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      services:
        name: kube-dns
        namespace: kube-system`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.egressRules[0];
    expect(rule.destination?.services).toEqual({ name: 'kube-dns', namespace: 'kube-system' });
  });

  it('parses doNotTrack, preDNAT, applyOnForward', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: host-policy
spec:
  selector: has(node-role.kubernetes.io/control-plane)
  doNotTrack: true
  preDNAT: true
  applyOnForward: true
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports:
      - 6443`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const p = result.policy!;
    expect(p.raw.spec.doNotTrack).toBe(true);
    expect(p.raw.spec.preDNAT).toBe(true);
    expect(p.raw.spec.applyOnForward).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sample YAML from the project
// ---------------------------------------------------------------------------

describe('parseYaml — sample YAML files', () => {
  it('parses the embedded NetworkPolicy sample', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: color == 'red'
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: color == 'blue'
        namespaceSelector: shape == 'circle'
      destination:
        ports:
          - 6379`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const p = result.policy!;
    expect(p.name).toBe('allow-tcp-6379');
    expect(p.namespace).toBe('production');
    expect(p.ingressRules).toHaveLength(1);
    expect(p.ingressRules[0].source?.selector).toBe("color == 'blue'");
    expect(p.ingressRules[0].destination?.ports).toEqual([6379]);
  });

  it('parses the embedded GlobalNetworkPolicy sample', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ingress-k8s-masters
spec:
  selector: has(node-role.kubernetes.io/control-plane)
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports:
      - 6443
  - action: Allow
    destination:
      nets:
      - 127.0.0.0/8
  - action: Allow
    protocol: TCP
    source:
      selector: has(node-role.kubernetes.io/control-plane)
    destination:
      ports:
      - 2380
      - 10250`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const p = result.policy!;
    expect(p.name).toBe('ingress-k8s-masters');
    expect(p.kind).toBe('GlobalNetworkPolicy');
    expect(p.ingressRules).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Warnings — invalid ports and CIDRs
// ---------------------------------------------------------------------------

describe('parseYaml — warnings for invalid ports', () => {
  it('returns no warnings for valid ports', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: valid-ports
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    destination:
      ports:
      - 80
      - 443
      - "8080:9090"`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.warnings).toEqual([]);
  });

  it('warns about out-of-range port numbers', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-ports
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    destination:
      ports:
      - 80
      - 99999`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('99999');
    expect(result.warnings[0]).toContain('Ingress rule 1');
    expect(result.warnings[0]).toContain('out of range');
  });

  it('warns about invalid port ranges', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-range
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      ports:
      - "443:80"`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('443:80');
    expect(result.warnings[0]).toContain('Egress rule 1');
  });

  it('warns about invalid notPorts', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-not-ports
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      notPorts:
      - 70000`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('source notPort');
    expect(result.warnings[0]).toContain('70000');
  });
});

describe('parseYaml — warnings for invalid CIDRs', () => {
  it('returns no warnings for valid CIDRs', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: valid-cidrs
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
      - 0.0.0.0/0`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.warnings).toEqual([]);
  });

  it('warns about invalid CIDR notation', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-cidr
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      nets:
      - 999.0.0.1/8`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('999.0.0.1/8');
    expect(result.warnings[0]).toContain('Egress rule 1');
    expect(result.warnings[0]).toContain('not valid CIDR');
  });

  it('warns about invalid prefix length', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-prefix
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      nets:
      - 10.0.0.0/33`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('10.0.0.0/33');
  });

  it('warns about invalid notNets', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: bad-not-nets
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      notNets:
      - 300.0.0.0/8`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('destination notNet');
    expect(result.warnings[0]).toContain('300.0.0.0/8');
  });

  it('accumulates multiple warnings across rules', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: multi-warnings
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    destination:
      ports:
      - 99999
  egress:
  - action: Allow
    destination:
      nets:
      - 999.0.0.0/8`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]).toContain('Ingress');
    expect(result.warnings[1]).toContain('Egress');
  });

  it('returns empty warnings on error', () => {
    const result = parseYaml('');
    expect(result.warnings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Sanitization — null values from incomplete YAML list items
// ---------------------------------------------------------------------------

describe('parseYaml — sanitization of null array elements', () => {
  it('filters null from nets when an incomplete list item is present', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: production
spec:
  selector: app == 'web'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      nets:
      - 0.0.0.0/0
      - `;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    const nets = result.policy!.egressRules[0].destination?.nets;
    expect(nets).toEqual(['0.0.0.0/0']);
  });

  it('filters null from notNets', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      notNets:
      - 10.0.0.0/8
      - `;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const notNets = result.policy!.egressRules[0].destination?.notNets;
    expect(notNets).toEqual(['10.0.0.0/8']);
  });

  it('filters null from ports', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    destination:
      ports:
      - 80
      - `;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const ports = result.policy!.ingressRules[0].destination?.ports;
    expect(ports).toEqual([80]);
  });

  it('filters null from serviceAccounts.names', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      serviceAccounts:
        names:
        - coredns
        - `;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const names = result.policy!.ingressRules[0].source?.serviceAccounts?.names;
    expect(names).toEqual(['coredns']);
  });

  it('does not crash policyToGraph when nets contains only a null item', () => {
    // This is the exact scenario from the bug: user types `- ` after the last net
    // and deletes the previous value, leaving nets: [null]
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: production
spec:
  selector: app == 'web'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      nets:
      - `;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const nets = result.policy!.egressRules[0].destination?.nets;
    expect(nets).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Sanitization — selector fields as objects (React error #31 fix)
// ---------------------------------------------------------------------------

describe('parseYaml — sanitization of selector fields', () => {
  it('sanitizes namespaceSelector when it is an object instead of string', () => {
    // This is the exact bug: namespaceSelector as {namespace: foo} instead of string
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      namespaceSelector:
        namespace: production`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    // namespaceSelector should be sanitized to undefined
    expect(result.policy!.ingressRules[0].source?.namespaceSelector).toBeUndefined();
    // Should have a warning about the malformed selector
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('namespaceSelector should be a string');
  });

  it('sanitizes selector when it is an object instead of string', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      selector:
        app: web`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.ingressRules[0].source?.selector).toBeUndefined();
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('selector should be a string');
  });

  it('sanitizes notSelector when it is an object', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
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
      notSelector:
        app: db`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.egressRules[0].destination?.notSelector).toBeUndefined();
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('notSelector should be a string');
  });

  it('sanitizes serviceAccounts.selector when it is an object', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      serviceAccounts:
        selector:
          role: admin`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.ingressRules[0].source?.serviceAccounts?.selector).toBeUndefined();
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('serviceAccounts.selector should be a string');
  });

  it('sanitizes policy-level selector when it is an object', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector:
    app: web
  types:
  - Ingress`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    // Should fall back to 'all()' when selector is invalid
    expect(result.policy!.selector).toBe('all()');
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('Policy selector should be a string');
  });

  it('sanitizes policy-level namespaceSelector when it is an object', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: test-policy
spec:
  selector: all()
  namespaceSelector:
    environment: production
  types:
  - Ingress`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.namespaceSelector).toBeUndefined();
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('Policy namespaceSelector should be a string');
  });

  it('sanitizes policy-level serviceAccountSelector when it is an object', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: all()
  serviceAccountSelector:
    role: admin
  types:
  - Ingress`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.serviceAccountSelector).toBeUndefined();
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('Policy serviceAccountSelector should be a string');
  });

  it('accepts valid string selectors without warnings', () => {
    const yaml = `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: test-policy
  namespace: default
spec:
  selector: app == 'web'
  namespaceSelector: env == 'prod'
  serviceAccountSelector: role == 'admin'
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      selector: app == 'api'
      namespaceSelector: "kubernetes.io/metadata.name == 'production'"
      serviceAccounts:
        selector: role == 'dns'
    destination:
      notSelector: app == 'db'`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.selector).toBe("app == 'web'");
    expect(result.policy!.namespaceSelector).toBe("env == 'prod'");
    expect(result.policy!.serviceAccountSelector).toBe("role == 'admin'");
    expect(result.policy!.ingressRules[0].source?.selector).toBe("app == 'api'");
    expect(result.policy!.ingressRules[0].source?.namespaceSelector).toBe("kubernetes.io/metadata.name == 'production'");
    expect(result.policy!.ingressRules[0].source?.serviceAccounts?.selector).toBe("role == 'dns'");
    expect(result.policy!.ingressRules[0].destination?.notSelector).toBe("app == 'db'");
    // No selector-related warnings
    const selectorWarnings = result.warnings.filter(w => w.includes('selector'));
    expect(selectorWarnings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Kubernetes NetworkPolicy support
// ---------------------------------------------------------------------------

describe('parseYaml — Kubernetes NetworkPolicy', () => {
  it('detects and parses a minimal Kubernetes NetworkPolicy', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-minimal
  namespace: default
spec:
  podSelector: {}`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy).not.toBeNull();
    expect(result.policy!.policySource).toBe('kubernetes');
    expect(result.policy!.apiVersion).toBe('networking.k8s.io/v1');
    expect(result.policy!.types).toEqual(['Ingress']);
    expect(result.policy!.selector).toBe('all()');
  });

  it('applies Kubernetes policyTypes defaulting (ingress + egress when egress section exists)', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-default-types
spec:
  podSelector:
    matchLabels:
      app: web
  egress: []`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.types).toEqual(['Ingress', 'Egress']);
  });

  it('normalizes ipBlock.except to nets/notNets', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-ipblock
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/24
            except:
              - 10.0.0.10/32`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.egressRules).toHaveLength(1);
    expect(result.policy!.egressRules[0].destination?.nets).toEqual(['10.0.0.0/24']);
    expect(result.policy!.egressRules[0].destination?.notNets).toEqual(['10.0.0.10/32']);
  });

  it('supports namespaceSelector + podSelector in the same peer', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-peer-and
spec:
  podSelector: {}
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: web
          podSelector:
            matchLabels:
              app: frontend`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    const rule = result.policy!.ingressRules[0];
    expect(rule.source?.namespaceSelector).toContain("team == 'web'");
    expect(rule.source?.selector).toContain("app == 'frontend'");
  });

  it('normalizes endPort as a range', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-endport
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: TCP
          port: 32000
          endPort: 32768`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.egressRules[0].protocol).toBe('TCP');
    expect(result.policy!.egressRules[0].destination?.ports).toEqual(['32000:32768']);
  });

  it('supports named ports', () => {
    const yaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-named-port
spec:
  podSelector: {}
  ingress:
    - ports:
        - protocol: TCP
          port: http`;

    const result = parseYaml(yaml);
    expect(result.error).toBeNull();
    expect(result.policy!.ingressRules[0].destination?.ports).toEqual(['http']);
  });
});
