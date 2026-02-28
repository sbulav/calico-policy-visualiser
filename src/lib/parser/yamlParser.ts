import yaml from 'js-yaml';
import type {
  CalicoPolicy,
  PolicyKind,
  ResolvedPolicy,
  Rule,
  EntityRule,
  Port,
  KubernetesLabelSelector,
} from '../../types/calico';
import { mapRuleLineRanges, type RuleLineRanges } from './yamlLineMapper';
import { isValidPort, isValidCidr } from '../ipUtils';
import { labelSelectorToExpression } from './k8sSelector';

interface ParseResult {
  policy: ResolvedPolicy | null;
  error: string | null;
  warnings: string[];
  ruleLineRanges: RuleLineRanges | null;
}

const CALICO_API_VERSION = 'projectcalico.org/v3';
const K8S_API_VERSION = 'networking.k8s.io/v1';
const CALICO_KINDS: PolicyKind[] = ['NetworkPolicy', 'GlobalNetworkPolicy'];

interface K8sNetworkPolicyPort {
  protocol?: 'TCP' | 'UDP' | 'SCTP';
  port?: number | string;
  endPort?: number;
}

interface K8sIPBlock {
  cidr: string;
  except?: string[];
}

interface K8sNetworkPolicyPeer {
  podSelector?: KubernetesLabelSelector;
  namespaceSelector?: KubernetesLabelSelector;
  ipBlock?: K8sIPBlock;
}

interface K8sNetworkPolicyIngressRule {
  from?: K8sNetworkPolicyPeer[];
  ports?: K8sNetworkPolicyPort[];
}

interface K8sNetworkPolicyEgressRule {
  to?: K8sNetworkPolicyPeer[];
  ports?: K8sNetworkPolicyPort[];
}

interface K8sNetworkPolicySpec {
  podSelector?: KubernetesLabelSelector;
  policyTypes?: Array<'Ingress' | 'Egress'>;
  ingress?: K8sNetworkPolicyIngressRule[];
  egress?: K8sNetworkPolicyEgressRule[];
}

// Filter null/undefined values that js-yaml produces from incomplete YAML list
// items (e.g. `- ` with no value). Without this, downstream code like ipUtils
// will crash when calling string methods on null array elements.
// Also sanitizes selector fields to ensure they are strings (not objects).
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
  // Sanitize selector fields - must be strings, not objects
  // This prevents React errors when rendering selectors in JSX
  const selectorFields = ['selector', 'notSelector', 'namespaceSelector'] as const;
  for (const field of selectorFields) {
    if (result[field] !== undefined && typeof result[field] !== 'string') {
      // Convert to undefined - the field will be ignored
      // Warnings are collected separately in collectSelectorWarnings()
      result[field] = undefined as unknown as string;
    }
  }
  // Sanitize serviceAccounts.selector
  if (result.serviceAccounts?.selector !== undefined && typeof result.serviceAccounts.selector !== 'string') {
    result.serviceAccounts = {
      ...result.serviceAccounts,
      selector: undefined,
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

/** Check if a value is a valid selector string (not an object or other type).
 *  Returns true if the value is undefined, null, or a string.
 */
function isValidSelectorType(value: unknown): boolean {
  return value === undefined || value === null || typeof value === 'string';
}

/** Validate selector fields in all rules, returning human-readable warnings.
 *  This catches cases where users mistakenly use object syntax instead of string selectors.
 */
function collectSelectorWarnings(rules: Rule[], direction: 'Ingress' | 'Egress'): string[] {
  const warnings: string[] = [];

  rules.forEach((rule, idx) => {
    const ruleLabel = `${direction} rule ${idx + 1}`;

    for (const side of ['source', 'destination'] as const) {
      const entity = rule[side];
      if (!entity) continue;
      const sideLabel = side === 'source' ? 'source' : 'destination';

      if (!isValidSelectorType(entity.selector)) {
        warnings.push(`${ruleLabel}: ${sideLabel} selector should be a string, got object. Use selector: "app == 'foo'" syntax.`);
      }
      if (!isValidSelectorType(entity.notSelector)) {
        warnings.push(`${ruleLabel}: ${sideLabel} notSelector should be a string, got object.`);
      }
      if (!isValidSelectorType(entity.namespaceSelector)) {
        warnings.push(`${ruleLabel}: ${sideLabel} namespaceSelector should be a string, got object. Use namespaceSelector: "kubernetes.io/metadata.name == 'foo'" syntax.`);
      }
      if (entity.serviceAccounts && !isValidSelectorType(entity.serviceAccounts.selector)) {
        warnings.push(`${ruleLabel}: ${sideLabel} serviceAccounts.selector should be a string, got object.`);
      }
    }
  });

  return warnings;
}

/** Sanitize a policy-level selector field, returning undefined if not a string. */
function sanitizePolicySelector(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'string') return value;
  return undefined;
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

  let parsedResult: { policy: ResolvedPolicy; warnings: string[] };

  try {
    if (doc.apiVersion === CALICO_API_VERSION) {
      parsedResult = parseCalicoPolicy(doc);
    } else if (doc.apiVersion === K8S_API_VERSION) {
      parsedResult = parseKubernetesPolicy(doc);
    } else {
      return {
        policy: null,
        error: `Unsupported apiVersion: "${doc.apiVersion}". Expected "${CALICO_API_VERSION}" or "${K8S_API_VERSION}"`,
        warnings: [],
        ruleLineRanges: null,
      };
    }
  } catch (error) {
    return {
      policy: null,
      error: error instanceof Error ? error.message : 'Failed to parse policy',
      warnings: [],
      ruleLineRanges: null,
    };
  }

  if (!parsedResult) {
    return {
      policy: null,
      error: 'Failed to parse policy document',
      warnings: [],
      ruleLineRanges: null,
    };
  }

  const ruleLineRanges = mapRuleLineRanges(yamlStr);
  return {
    policy: parsedResult.policy,
    error: null,
    warnings: parsedResult.warnings,
    ruleLineRanges,
  };
}

function parseCalicoPolicy(doc: Record<string, unknown>): { policy: ResolvedPolicy; warnings: string[] } {
  if (!CALICO_KINDS.includes(doc.kind as PolicyKind)) {
    throw new Error('Unsupported kind for Calico policy');
  }

  const raw = doc as unknown as CalicoPolicy;

  if (!raw.metadata?.name) {
    throw new Error('Missing metadata.name');
  }
  if (!raw.spec) {
    throw new Error('Missing spec');
  }

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

  const ingressDefault = types.includes('Ingress') ? 'deny' : 'allow';
  const egressDefault = types.includes('Egress') ? 'deny' : 'allow';

  const resolved: ResolvedPolicy = {
    raw,
    policySource: 'calico',
    apiVersion: raw.apiVersion,
    name: raw.metadata.name,
    namespace: raw.metadata.namespace,
    kind: raw.kind,
    tier: raw.spec.tier || 'default',
    order: raw.spec.order,
    selector: sanitizePolicySelector(raw.spec.selector) || 'all()',
    namespaceSelector: sanitizePolicySelector(raw.spec.namespaceSelector),
    serviceAccountSelector: sanitizePolicySelector(raw.spec.serviceAccountSelector),
    types,
    ingressRules: sanitizeRules(raw.spec.ingress || []),
    egressRules: sanitizeRules(raw.spec.egress || []),
    ingressDefault,
    egressDefault,
  };

  const warnings = [
    ...collectWarnings(resolved.ingressRules, 'Ingress'),
    ...collectWarnings(resolved.egressRules, 'Egress'),
    ...collectSelectorWarnings(raw.spec.ingress || [], 'Ingress'),
    ...collectSelectorWarnings(raw.spec.egress || [], 'Egress'),
  ];

  if (!isValidSelectorType(raw.spec.selector)) {
    warnings.push('Policy selector should be a string, got object. Use selector: "app == \'foo\'" syntax.');
  }
  if (!isValidSelectorType(raw.spec.namespaceSelector)) {
    warnings.push('Policy namespaceSelector should be a string, got object. Use namespaceSelector: "kubernetes.io/metadata.name == \'foo\'" syntax.');
  }
  if (!isValidSelectorType(raw.spec.serviceAccountSelector)) {
    warnings.push('Policy serviceAccountSelector should be a string, got object.');
  }

  return { policy: resolved, warnings };
}

function parseKubernetesPolicy(doc: Record<string, unknown>): { policy: ResolvedPolicy; warnings: string[] } {
  if (doc.kind !== 'NetworkPolicy') {
    throw new Error(`Unsupported kind: "${doc.kind}". Kubernetes networking.k8s.io/v1 supports "NetworkPolicy" only`);
  }

  const rawDoc = doc as unknown as CalicoPolicy;
  if (!rawDoc.metadata?.name) {
    throw new Error('Missing metadata.name');
  }

  const spec = (doc.spec ?? {}) as K8sNetworkPolicySpec;
  const warnings: string[] = [];

  const hasEgressSection = Array.isArray(spec.egress);
  let types = spec.policyTypes;
  if (!types || types.length === 0) {
    types = hasEgressSection ? ['Ingress', 'Egress'] : ['Ingress'];
  }

  const normalizedIngress = normalizeK8sIngressRules(spec.ingress, warnings);
  const normalizedEgress = normalizeK8sEgressRules(spec.egress, warnings);

  const selector = labelSelectorToExpression(spec.podSelector) || 'all()';

  const resolved: ResolvedPolicy = {
    raw: rawDoc,
    policySource: 'kubernetes',
    apiVersion: K8S_API_VERSION,
    name: rawDoc.metadata.name,
    namespace: rawDoc.metadata.namespace,
    kind: 'NetworkPolicy',
    tier: 'kubernetes',
    order: undefined,
    selector,
    namespaceSelector: undefined,
    serviceAccountSelector: undefined,
    types,
    ingressRules: sanitizeRules(normalizedIngress),
    egressRules: sanitizeRules(normalizedEgress),
    ingressDefault: types.includes('Ingress') ? 'deny' : 'allow',
    egressDefault: types.includes('Egress') ? 'deny' : 'allow',
  };

  warnings.push(
    ...collectWarnings(resolved.ingressRules, 'Ingress'),
    ...collectWarnings(resolved.egressRules, 'Egress'),
  );

  return { policy: resolved, warnings };
}

function normalizeK8sIngressRules(
  rules: K8sNetworkPolicyIngressRule[] | undefined,
  warnings: string[],
): Rule[] {
  if (!Array.isArray(rules)) return [];

  const result: Rule[] = [];

  for (const [idx, rule] of rules.entries()) {
    const peers = !rule.from || rule.from.length === 0 ? [undefined] : rule.from;
    const ports = !rule.ports || rule.ports.length === 0 ? [undefined] : rule.ports;

    for (const peer of peers) {
      const source = normalizeK8sPeer(peer, `Ingress rule ${idx + 1}`, warnings);
      for (const portSpec of ports) {
        const normalizedPort = normalizeK8sPort(portSpec, `Ingress rule ${idx + 1}`, warnings);
        const nextRule: Rule = {
          action: 'Allow',
          source,
        };

        if (normalizedPort.protocol) {
          nextRule.protocol = normalizedPort.protocol;
        }
        if (normalizedPort.port !== undefined) {
          nextRule.destination = { ports: [normalizedPort.port] };
        }

        result.push(nextRule);
      }
    }
  }

  return result;
}

function normalizeK8sEgressRules(
  rules: K8sNetworkPolicyEgressRule[] | undefined,
  warnings: string[],
): Rule[] {
  if (!Array.isArray(rules)) return [];

  const result: Rule[] = [];

  for (const [idx, rule] of rules.entries()) {
    const peers = !rule.to || rule.to.length === 0 ? [undefined] : rule.to;
    const ports = !rule.ports || rule.ports.length === 0 ? [undefined] : rule.ports;

    for (const peer of peers) {
      const destination = normalizeK8sPeer(peer, `Egress rule ${idx + 1}`, warnings);
      for (const portSpec of ports) {
        const normalizedPort = normalizeK8sPort(portSpec, `Egress rule ${idx + 1}`, warnings);
        const nextRule: Rule = {
          action: 'Allow',
          destination,
        };

        if (normalizedPort.protocol) {
          nextRule.protocol = normalizedPort.protocol;
        }
        if (normalizedPort.port !== undefined) {
          nextRule.destination = {
            ...(nextRule.destination || {}),
            ports: [normalizedPort.port],
          };
        }

        result.push(nextRule);
      }
    }
  }

  return result;
}

function normalizeK8sPeer(peer: K8sNetworkPolicyPeer | undefined, ruleLabel: string, warnings: string[]): EntityRule | undefined {
  if (!peer) return undefined;

  const hasIpBlock = !!peer.ipBlock;
  const hasSelector = !!peer.podSelector || !!peer.namespaceSelector;
  if (hasIpBlock && hasSelector) {
    warnings.push(`${ruleLabel}: ipBlock cannot be combined with podSelector/namespaceSelector in one peer`);
  }

  const selector = labelSelectorToExpression(peer.podSelector);
  const namespaceSelector = labelSelectorToExpression(peer.namespaceSelector);

  return {
    selector,
    namespaceSelector,
    nets: peer.ipBlock?.cidr ? [peer.ipBlock.cidr] : undefined,
    notNets: peer.ipBlock?.except,
  };
}

function normalizeK8sPort(
  portSpec: K8sNetworkPolicyPort | undefined,
  ruleLabel: string,
  warnings: string[],
): { protocol?: 'TCP' | 'UDP' | 'SCTP'; port?: Port } {
  if (!portSpec) {
    return {};
  }

  const protocol = portSpec.protocol ?? (portSpec.port !== undefined ? 'TCP' : undefined);

  if (portSpec.endPort !== undefined) {
    if (typeof portSpec.port !== 'number') {
      warnings.push(`${ruleLabel}: endPort requires numeric port; ignoring endPort`);
      return {
        protocol,
        port: portSpec.port,
      };
    }

    if (portSpec.endPort < portSpec.port) {
      warnings.push(`${ruleLabel}: endPort ${portSpec.endPort} must be >= port ${portSpec.port}`);
    }

    return {
      protocol,
      port: `${portSpec.port}:${portSpec.endPort}`,
    };
  }

  return {
    protocol,
    port: portSpec.port,
  };
}
