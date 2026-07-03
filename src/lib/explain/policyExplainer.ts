import type { ResolvedPolicy, Rule } from '../../types/calico';
import { inferClusterStatuses, inferNamespaceStatuses, computeEffectiveDefault, hasDenyBeforeCatchAll } from '../transform/policyToGraph';
import { getRuleEntities, summarizeNets, formatPortWithWellKnown, type RuleDirection } from '../ruleDescription';
import { formatPort } from '../formatPort';

function describeProtocol(protocol?: string | number): string {
  if (!protocol) return 'any protocol';
  return String(protocol);
}

function describeRule(rule: Rule, direction: RuleDirection): string {
  const { entity, opposite } = getRuleEntities(rule, direction);
  const parts: string[] = [];

  // Action
  const actionEmoji = rule.action === 'Allow' ? '+' : rule.action === 'Deny' ? 'x' : rule.action === 'Log' ? '!' : '~';
  parts.push(`[${actionEmoji}] ${rule.action}`);

  // Direction context
  parts.push(direction === 'ingress' ? 'incoming' : 'outgoing');

  // Protocol
  if (rule.protocol) {
    parts.push(`${describeProtocol(rule.protocol)} traffic`);
  } else {
    parts.push('traffic');
  }

  // Ports
  if (entity?.ports && entity.ports.length > 0) {
    const portDescs = entity.ports.map(formatPortWithWellKnown);
    parts.push(`on port${entity.ports.length > 1 ? 's' : ''} ${portDescs.join(', ')}`);
  }

  // Source/Destination
  if (entity?.nets && entity.nets.length > 0) {
    const dir = direction === 'ingress' ? 'from' : 'to';
    parts.push(`${dir} ${summarizeNets(entity.nets, 'CIDR ranges')}`);
  }

  if (entity?.selector) {
    const dir = direction === 'ingress' ? 'from' : 'to';
    parts.push(`${dir} pods matching: ${entity.selector}`);
  }

  if (entity?.namespaceSelector) {
    parts.push(`in namespaces matching: ${entity.namespaceSelector}`);
  }

  if (entity?.services) {
    const dir = direction === 'ingress' ? 'from' : 'to';
    parts.push(`${dir} service: ${entity.services.namespace}/${entity.services.name}`);
  }

  if (entity?.serviceAccounts) {
    const dir = direction === 'ingress' ? 'from' : 'to';
    if (entity.serviceAccounts.names && entity.serviceAccounts.names.length > 0) {
      parts.push(`${dir} service account${entity.serviceAccounts.names.length > 1 ? 's' : ''}: ${entity.serviceAccounts.names.join(', ')}`);
    } else if (entity.serviceAccounts.selector) {
      parts.push(`${dir} service accounts matching: ${entity.serviceAccounts.selector}`);
    }
  }

  // Negative matches
  if (entity?.notNets && entity.notNets.length > 0) {
    parts.push(`(excluding ${entity.notNets.join(', ')})`);
  }

  if (entity?.notPorts && entity.notPorts.length > 0) {
    parts.push(`(excluding ports ${entity.notPorts.map(formatPort).join(', ')})`);
  }

  if (entity?.notSelector) {
    parts.push(`(excluding pods matching: ${entity.notSelector})`);
  }

  // If no source/dest specified at all
  if (!entity || (!entity.nets && !entity.selector && !entity.services && !entity.serviceAccounts)) {
    const dir = direction === 'ingress' ? 'from any source' : 'to any destination';
    parts.push(dir);
  }

  // Opposite-side match criteria (destination for ingress, source for egress)
  if (opposite) {
    const oppDir = direction === 'ingress' ? 'destined for' : 'originating from';
    if (opposite.nets && opposite.nets.length > 0) {
      parts.push(`${oppDir} ${summarizeNets(opposite.nets, 'CIDR ranges')}`);
    }
    if (opposite.selector) {
      parts.push(`${oppDir} pods matching: ${opposite.selector}`);
    }
    if (opposite.ports && opposite.ports.length > 0) {
      const portDescs = opposite.ports.map(formatPortWithWellKnown);
      const label = direction === 'ingress' ? 'dst' : 'src';
      parts.push(`(${label} port${opposite.ports.length > 1 ? 's' : ''} ${portDescs.join(', ')})`);
    }
  }

  return parts.join(' ');
}

export interface ExplanationSection {
  title: string;
  items: string[];
  type: 'info' | 'ingress' | 'egress' | 'warning';
}

export function explainPolicy(policy: ResolvedPolicy): ExplanationSection[] {
  const sections: ExplanationSection[] = [];

  // Policy overview
  const overviewItems: string[] = [];
  overviewItems.push(`Kind: ${policy.kind}`);
  overviewItems.push(`Name: ${policy.name}`);
  if (policy.namespace) {
    overviewItems.push(`Namespace: ${policy.namespace}`);
  }
  overviewItems.push(`Source: ${policy.policySource === 'calico' ? 'Calico projectcalico.org/v3' : 'Kubernetes networking.k8s.io/v1'}`);
  if (policy.policySource === 'calico') {
    overviewItems.push(`Tier: ${policy.tier}`);
  }
  if (policy.policySource === 'calico' && policy.order !== undefined) {
    overviewItems.push(`Order: ${policy.order} (${policy.order < 100 ? 'high priority' : policy.order > 5000 ? 'low priority' : 'medium priority'})`);
  }
  overviewItems.push(`Applies to: ${policy.selector}`);
  if (policy.namespaceSelector) {
    overviewItems.push(`Namespace selector: ${policy.namespaceSelector}`);
  }
  overviewItems.push(`Policy types: ${policy.types.join(', ')}`);

  sections.push({
    title: 'Policy Overview',
    items: overviewItems,
    type: 'info',
  });

  // Policy-level flags (preDNAT, applyOnForward, doNotTrack) — Calico only
  if (policy.policySource === 'calico') {
    const spec = policy.raw.spec;
    const hasFlags = spec.preDNAT || spec.applyOnForward || spec.doNotTrack;
    if (hasFlags) {
    const flagItems: string[] = [];
    if (spec.preDNAT) {
      flagItems.push(
        'preDNAT: ENABLED -- Rules are applied before DNAT (destination NAT). ' +
        'This means the policy sees the original destination IP before kube-proxy rewrites it to a pod IP. ' +
        'Required when you want to control access to Kubernetes Service ClusterIPs or NodePorts at the host level.',
      );
    }
    if (spec.applyOnForward) {
      flagItems.push(
        'applyOnForward: ENABLED -- Rules are applied to forwarded traffic (traffic that arrives on the host ' +
        'and is forwarded to a local pod or another host). Without this flag, host endpoint policies only affect ' +
        'traffic that is destined for or originates from the host itself. Required together with preDNAT for ' +
        'controlling access to services via ClusterIPs/NodePorts.',
      );
    }
    if (spec.doNotTrack) {
      flagItems.push(
        'doNotTrack: ENABLED -- Rules are applied before Linux conntrack. Traffic matching these rules is not ' +
        'tracked by conntrack, which improves performance for high-throughput, stateless traffic (e.g., memcached, ' +
        'load balancers). Both request and response traffic must be explicitly allowed since there is no connection tracking.',
      );
    }
    if (spec.preDNAT && spec.applyOnForward) {
      flagItems.push('---');
      flagItems.push(
        'Combined effect: This policy acts as a host-level firewall that controls access to ClusterIPs and ' +
        'NodePorts before NAT translation occurs. It applies to traffic arriving on the host and being forwarded ' +
        'to backend pods. This is the standard pattern for restricting external access to specific Kubernetes services.',
      );
    }
    sections.push({
      title: 'Policy Flags',
      items: flagItems,
      type: 'warning',
    });
    } // end if (hasFlags)
  } // end if (policy.policySource === 'calico')

  // Defaults — show implicit deny behavior for managed directions.
  const defaultItems: string[] = [];
  if (policy.types.includes('Ingress')) {
    const effectiveIngress = computeEffectiveDefault(policy.ingressRules, 'ingress', policy.ingressDefault);
    if (effectiveIngress === 'allow' && policy.ingressDefault === 'deny') {
      defaultItems.push(`Ingress effective default: ALLOW (catch-all allow rule overrides the implicit deny)`);
    } else if (effectiveIngress === 'deny' && hasDenyBeforeCatchAll(policy.ingressRules, 'ingress')) {
      defaultItems.push(`Ingress default: DENY (deny rules restrict traffic before the catch-all allow)`);
    } else {
      defaultItems.push(`Ingress default: DENY (all ingress traffic not matched by a rule is denied)`);
    }
  } else {
    defaultItems.push(`Ingress: Not managed by this policy`);
  }
  if (policy.types.includes('Egress')) {
    const effectiveEgress = computeEffectiveDefault(policy.egressRules, 'egress', policy.egressDefault);
    if (effectiveEgress === 'allow' && policy.egressDefault === 'deny') {
      defaultItems.push(`Egress effective default: ALLOW (catch-all allow rule overrides the implicit deny)`);
    } else if (effectiveEgress === 'deny' && hasDenyBeforeCatchAll(policy.egressRules, 'egress')) {
      defaultItems.push(`Egress default: DENY (deny rules restrict traffic before the catch-all allow)`);
    } else {
      defaultItems.push(`Egress default: DENY (all egress traffic not matched by a rule is denied)`);
    }
  } else {
    defaultItems.push(`Egress: Not managed by this policy`);
  }
  sections.push({
    title: 'Default Behavior',
    items: defaultItems,
    type: 'warning',
  });

  // Ingress rules — always shown
  if (policy.types.includes('Ingress')) {
    const ingressItems = policy.ingressRules.map((rule) => describeRule(rule, 'ingress'));

    // Append inferred statuses
    const nsStatuses = inferNamespaceStatuses(policy.ingressRules, 'ingress', policy.namespace);
    const clusterStatuses = inferClusterStatuses(policy.ingressRules, 'ingress');
    ingressItems.push('---');
    for (const status of [...nsStatuses, ...clusterStatuses]) {
      const icon = status.state === 'allowed' ? '[+]' : status.state === 'denied' ? '[x]' : '[?]';
      const label = status.state === 'allowed' ? 'Allowed' : status.state === 'denied' ? 'Denied' : 'Likely';
      ingressItems.push(`${icon} ${status.label}: ${label} — ${status.reason}`);
    }

    sections.push({
      title: `Ingress Rules (${policy.ingressRules.length})`,
      items: ingressItems,
      type: 'ingress',
    });
  } else {
    sections.push({
      title: 'Ingress (not managed)',
      items: ['[+] All traffic allowed — this policy does not restrict ingress'],
      type: 'ingress',
    });
  }

  // Egress rules — always shown
  if (policy.types.includes('Egress')) {
    const egressItems = policy.egressRules.map((rule) => describeRule(rule, 'egress'));

    // Append inferred statuses
    const nsStatuses = inferNamespaceStatuses(policy.egressRules, 'egress', policy.namespace);
    const clusterStatuses = inferClusterStatuses(policy.egressRules, 'egress');
    egressItems.push('---');
    for (const status of [...nsStatuses, ...clusterStatuses]) {
      const icon = status.state === 'allowed' ? '[+]' : status.state === 'denied' ? '[x]' : '[?]';
      const label = status.state === 'allowed' ? 'Allowed' : status.state === 'denied' ? 'Denied' : 'Likely';
      egressItems.push(`${icon} ${status.label}: ${label} — ${status.reason}`);
    }

    sections.push({
      title: `Egress Rules (${policy.egressRules.length})`,
      items: egressItems,
      type: 'egress',
    });
  } else {
    sections.push({
      title: 'Egress (not managed)',
      items: ['[+] All traffic allowed — this policy does not restrict egress'],
      type: 'egress',
    });
  }

  return sections;
}
