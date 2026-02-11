import yaml from 'js-yaml';
import type { CalicoPolicy, PolicyKind, ResolvedPolicy, Rule, EntityRule, Port } from '../../types/calico';
import { mapRuleLineRanges, type RuleLineRanges } from './yamlLineMapper';
import { isValidPort, isValidCidr } from '../ipUtils';

interface ParseResult {
  policy: ResolvedPolicy | null;
  error: string | null;
  warnings: string[];
  ruleLineRanges: RuleLineRanges | null;
}

const VALID_KINDS: PolicyKind[] = ['NetworkPolicy', 'GlobalNetworkPolicy'];

// Filter null/undefined values that js-yaml produces from incomplete YAML list
// items (e.g. `- ` with no value). Without this, downstream code like ipUtils
// will crash when calling string methods on null array elements.
function sanitizeEntityRule(entity: EntityRule | undefined): EntityRule | undefined {
  if (!entity) return entity;
  const result = { ...entity };
  if (result.nets) {
    result.nets = result.nets.filter((n): n is string => typeof n === 'string');
  }
  if (result.notNets) {
    result.notNets = result.notNets.filter((n): n is string => typeof n === 'string');
  }
  if (result.ports) {
    result.ports = result.ports.filter((p): p is Port => p != null);
  }
  if (result.notPorts) {
    result.notPorts = result.notPorts.filter((p): p is Port => p != null);
  }
  if (result.serviceAccounts?.names) {
    result.serviceAccounts = {
      ...result.serviceAccounts,
      names: result.serviceAccounts.names.filter((n): n is string => typeof n === 'string'),
    };
  }
  return result;
}

function sanitizeRules(rules: Rule[]): Rule[] {
  return rules.map(rule => ({
    ...rule,
    source: sanitizeEntityRule(rule.source),
    destination: sanitizeEntityRule(rule.destination),
  }));
}

/** Validate ports and CIDRs in all rules, returning human-readable warnings.
 *  This is non-blocking — the policy is still returned even if there are warnings.
 */
function collectWarnings(rules: Rule[], direction: 'Ingress' | 'Egress'): string[] {
  const warnings: string[] = [];

  rules.forEach((rule, idx) => {
    const ruleLabel = `${direction} rule ${idx + 1}`;

    const checkPorts = (ports: Port[] | undefined, fieldName: string) => {
      if (!ports) return;
      for (const port of ports) {
        if (!isValidPort(port)) {
          if (typeof port === 'number') {
            warnings.push(`${ruleLabel}: ${fieldName} ${port} is out of range (0–65535)`);
          } else {
            warnings.push(`${ruleLabel}: ${fieldName} "${port}" is not a valid port range`);
          }
        }
      }
    };

    const checkNets = (nets: string[] | undefined, fieldName: string) => {
      if (!nets) return;
      for (const net of nets) {
        if (!isValidCidr(net)) {
          warnings.push(`${ruleLabel}: ${fieldName} "${net}" is not valid CIDR notation (expected x.x.x.x/0-32)`);
        }
      }
    };

    for (const side of ['source', 'destination'] as const) {
      const entity = rule[side];
      if (!entity) continue;
      const sideLabel = side === 'source' ? 'source' : 'destination';
      checkPorts(entity.ports, `${sideLabel} port`);
      checkPorts(entity.notPorts, `${sideLabel} notPort`);
      checkNets(entity.nets, `${sideLabel} net`);
      checkNets(entity.notNets, `${sideLabel} notNet`);
    }
  });

  return warnings;
}

export function parseYaml(yamlStr: string): ParseResult {
  if (!yamlStr.trim()) {
    return { policy: null, error: 'Empty YAML input', warnings: [], ruleLineRanges: null };
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(yamlStr);
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Invalid YAML syntax';
    return { policy: null, error: msg, warnings: [], ruleLineRanges: null };
  }

  if (!parsed || typeof parsed !== 'object') {
    return { policy: null, error: 'YAML did not parse to an object', warnings: [], ruleLineRanges: null };
  }

  const doc = parsed as Record<string, unknown>;

  // Validate apiVersion
  if (doc.apiVersion !== 'projectcalico.org/v3') {
    return {
      policy: null,
      error: `Unsupported apiVersion: "${doc.apiVersion}". Expected "projectcalico.org/v3"`,
      warnings: [],
      ruleLineRanges: null,
    };
  }

  // Validate kind
  if (!VALID_KINDS.includes(doc.kind as PolicyKind)) {
    return {
      policy: null,
      error: `Unsupported kind: "${doc.kind}". Expected "NetworkPolicy" or "GlobalNetworkPolicy"`,
      warnings: [],
      ruleLineRanges: null,
    };
  }

  const raw = doc as unknown as CalicoPolicy;

  // Validate metadata
  if (!raw.metadata?.name) {
    return { policy: null, error: 'Missing metadata.name', warnings: [], ruleLineRanges: null };
  }

  // Validate spec
  if (!raw.spec) {
    return { policy: null, error: 'Missing spec', warnings: [], ruleLineRanges: null };
  }

  // Resolve types
  const hasIngress = Array.isArray(raw.spec.ingress) && raw.spec.ingress.length > 0;
  const hasEgress = Array.isArray(raw.spec.egress) && raw.spec.egress.length > 0;

  let types = raw.spec.types;
  if (!types || types.length === 0) {
    if (hasIngress && hasEgress) {
      types = ['Ingress', 'Egress'];
    } else if (hasEgress) {
      types = ['Egress'];
    } else {
      types = ['Ingress'];
    }
  }

  // Determine defaults:
  // If a direction is listed in types, the implicit default is deny (Calico semantics).
  // If a direction is not listed in types, traffic is allowed through (not restricted).
  const ingressDefault = types.includes('Ingress') ? 'deny' : 'allow';
  const egressDefault = types.includes('Egress') ? 'deny' : 'allow';

  const resolved: ResolvedPolicy = {
    raw,
    name: raw.metadata.name,
    namespace: raw.metadata.namespace,
    kind: raw.kind,
    tier: raw.spec.tier || 'default',
    order: raw.spec.order,
    selector: raw.spec.selector || 'all()',
    namespaceSelector: raw.spec.namespaceSelector,
    serviceAccountSelector: raw.spec.serviceAccountSelector,
    types,
    ingressRules: sanitizeRules(raw.spec.ingress || []),
    egressRules: sanitizeRules(raw.spec.egress || []),
    ingressDefault: ingressDefault as 'deny' | 'allow' | 'none',
    egressDefault: egressDefault as 'deny' | 'allow' | 'none',
  };

  // Validate ports and CIDRs — collect non-blocking warnings
  const warnings = [
    ...collectWarnings(resolved.ingressRules, 'Ingress'),
    ...collectWarnings(resolved.egressRules, 'Egress'),
  ];

  // Compute YAML source line ranges for each rule (for editor highlighting)
  const ruleLineRanges = mapRuleLineRanges(yamlStr);

  return { policy: resolved, error: null, warnings, ruleLineRanges };
}
