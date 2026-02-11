import { describe, it, expect } from 'vitest';
import { matchRule } from './ruleMatcher';
import type { Rule } from '../../types/calico';
import type { TrafficSpec } from '../../types/matcher';

describe('matchRule', () => {
  // --- Basic rule with no constraints (catch-all) ---
  describe('catch-all rules', () => {
    it('matches a rule with no source/destination (Allow all)', () => {
      const rule: Rule = { action: 'Allow' };
      const spec: TrafficSpec = { ip: '10.0.0.1' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
      expect(result.indeterminate).toBe(false);
    });

    it('matches a Deny-all rule', () => {
      const rule: Rule = { action: 'Deny' };
      const spec: TrafficSpec = {};
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });
  });

  // --- CIDR matching ---
  describe('CIDR matching', () => {
    it('matches IP within allowed CIDR', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['10.0.0.0/8'] },
      };
      const spec: TrafficSpec = { ip: '10.1.2.3' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('does not match IP outside allowed CIDR', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['10.0.0.0/8'] },
      };
      const spec: TrafficSpec = { ip: '192.168.1.1' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });

    it('matches /32 exact IP', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { nets: ['1.2.3.4/32'] },
      };
      const spec: TrafficSpec = { ip: '1.2.3.4' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });

    it('rejects IP excluded by notNets', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['0.0.0.0/0'], notNets: ['10.0.0.0/8'] },
      };
      const spec: TrafficSpec = { ip: '10.5.5.5' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
      const notNetsDetail = result.details.find(d => d.field === 'notNets');
      expect(notNetsDetail?.matched).toBe(false);
    });

    it('allows IP not in notNets', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['0.0.0.0/0'], notNets: ['10.0.0.0/8'] },
      };
      const spec: TrafficSpec = { ip: '8.8.8.8' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('returns indeterminate when no IP is provided but rule requires nets', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['10.0.0.0/8'] },
      };
      const spec: TrafficSpec = { labels: { app: 'web' } };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(true);
    });
  });

  // --- Protocol matching ---
  describe('protocol matching', () => {
    it('matches correct protocol', () => {
      const rule: Rule = { action: 'Allow', protocol: 'TCP' };
      const spec: TrafficSpec = { protocol: 'TCP' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('is case-insensitive', () => {
      const rule: Rule = { action: 'Allow', protocol: 'TCP' };
      const spec: TrafficSpec = { protocol: 'tcp' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('rejects wrong protocol', () => {
      const rule: Rule = { action: 'Allow', protocol: 'TCP' };
      const spec: TrafficSpec = { protocol: 'UDP' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });

    it('rejects excluded protocol', () => {
      const rule: Rule = { action: 'Allow', notProtocol: 'UDP' };
      const spec: TrafficSpec = { protocol: 'UDP' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });
  });

  // --- Port matching ---
  describe('port matching', () => {
    it('matches numeric port', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { ports: [80, 443] },
      };
      const spec: TrafficSpec = { port: 80 };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });

    it('does not match wrong port', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { ports: [80, 443] },
      };
      const spec: TrafficSpec = { port: 8080 };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
    });

    it('matches port range', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { ports: ['8000:9000'] },
      };
      const spec: TrafficSpec = { port: 8080 };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('rejects port excluded by notPorts', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { notPorts: [22] },
      };
      const spec: TrafficSpec = { port: 22 };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });
  });

  // --- Selector matching ---
  describe('selector matching', () => {
    it('matches labels against selector', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { selector: "app == 'web'" },
      };
      const spec: TrafficSpec = { labels: { app: 'web' } };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('rejects non-matching labels', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { selector: "app == 'web'" },
      };
      const spec: TrafficSpec = { labels: { app: 'api' } };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });

    it('rejects when labels match notSelector', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { notSelector: "env == 'test'" },
      };
      const spec: TrafficSpec = { labels: { env: 'test' } };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });
  });

  // --- Namespace selector matching ---
  describe('namespace selector matching', () => {
    it('matches namespace labels', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { namespaceSelector: "projectcalico.org/name == 'backend'" },
      };
      const spec: TrafficSpec = {
        namespaceLabels: { 'projectcalico.org/name': 'backend' },
      };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('infers standard namespace labels from namespace name', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { namespaceSelector: "projectcalico.org/name == 'backend'" },
      };
      const spec: TrafficSpec = { namespace: 'backend' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });
  });

  // --- ServiceAccount matching ---
  describe('serviceAccount matching', () => {
    it('matches SA by name', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { serviceAccounts: { names: ['backend-api', 'worker'] } },
      };
      const spec: TrafficSpec = { serviceAccountName: 'backend-api' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('rejects SA not in name list', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { serviceAccounts: { names: ['backend-api'] } },
      };
      const spec: TrafficSpec = { serviceAccountName: 'frontend' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });

    it('SA selector is indeterminate', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { serviceAccounts: { selector: "role == 'admin'" } },
      };
      const spec: TrafficSpec = { serviceAccountName: 'admin-sa' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.indeterminate).toBe(true);
    });
  });

  // --- Multiple constraints (AND semantics) ---
  describe('combined constraints', () => {
    it('requires all constraints to match', () => {
      const rule: Rule = {
        action: 'Allow',
        protocol: 'TCP',
        source: {
          nets: ['10.0.0.0/8'],
          selector: "app == 'web'",
          ports: [8080],
        },
      };
      const spec: TrafficSpec = {
        ip: '10.1.2.3',
        labels: { app: 'web' },
        port: 8080,
        protocol: 'TCP',
      };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('fails when one constraint does not match', () => {
      const rule: Rule = {
        action: 'Allow',
        protocol: 'TCP',
        source: {
          nets: ['10.0.0.0/8'],
          selector: "app == 'web'",
        },
      };
      const spec: TrafficSpec = {
        ip: '10.1.2.3',
        labels: { app: 'api' }, // wrong label
        protocol: 'TCP',
      };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(false);
    });
  });

  // --- Direction handling ---
  describe('direction', () => {
    it('uses source entity for ingress', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { nets: ['10.0.0.0/8'] },
        destination: { ports: [80] },
      };
      // For ingress: source.nets should match the spec IP, destination.ports is opposite-side
      const spec: TrafficSpec = { ip: '10.1.2.3', port: 80 };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('uses destination entity for egress', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { nets: ['8.8.8.0/24'] },
      };
      const spec: TrafficSpec = { ip: '8.8.8.8' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });
  });

  // --- Service matching ---
  describe('service matching', () => {
    it('matches service by name and namespace', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      };
      const spec: TrafficSpec = { serviceName: 'kube-dns', serviceNamespace: 'kube-system' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
      const svcDetail = result.details.find(d => d.field === 'services');
      expect(svcDetail?.matched).toBe(true);
    });

    it('rejects when service name does not match', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      };
      const spec: TrafficSpec = { serviceName: 'other-svc', serviceNamespace: 'kube-system' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(false);
    });

    it('rejects when service namespace does not match', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      };
      const spec: TrafficSpec = { serviceName: 'kube-dns', serviceNamespace: 'default' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(false);
    });

    it('is indeterminate when only service name is provided (no namespace)', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      };
      const spec: TrafficSpec = { serviceName: 'kube-dns' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(true);
    });

    it('is indeterminate when no service info is provided but rule has services', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { services: { name: 'kube-dns', namespace: 'kube-system' } },
      };
      const spec: TrafficSpec = { ip: '10.0.0.1' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(true);
    });

    it('matches service on ingress source', () => {
      const rule: Rule = {
        action: 'Allow',
        source: { services: { name: 'frontend', namespace: 'web' } },
      };
      const spec: TrafficSpec = { serviceName: 'frontend', serviceNamespace: 'web' };
      const result = matchRule(rule, 'ingress', spec);
      expect(result.matches).toBe(true);
    });

    it('matches service combined with protocol and port', () => {
      const rule: Rule = {
        action: 'Allow',
        protocol: 'TCP',
        destination: {
          services: { name: 'kube-dns', namespace: 'kube-system' },
          ports: [53],
        },
      };
      const spec: TrafficSpec = {
        serviceName: 'kube-dns',
        serviceNamespace: 'kube-system',
        protocol: 'TCP',
        port: 53,
      };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });

    it('fails when service matches but port does not', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: {
          services: { name: 'kube-dns', namespace: 'kube-system' },
          ports: [53],
        },
      };
      const spec: TrafficSpec = {
        serviceName: 'kube-dns',
        serviceNamespace: 'kube-system',
        port: 80,
      };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(false);
      expect(result.indeterminate).toBe(false);
    });

    it('passes through when rule has no services and spec has service info', () => {
      const rule: Rule = {
        action: 'Allow',
        destination: { nets: ['0.0.0.0/0'] },
      };
      // Providing service info shouldn't cause a failure — the rule just doesn't constrain services
      const spec: TrafficSpec = { serviceName: 'kube-dns', serviceNamespace: 'kube-system', ip: '10.0.0.1' };
      const result = matchRule(rule, 'egress', spec);
      expect(result.matches).toBe(true);
    });
  });
});
