import { MarkerType, type Node, type Edge } from '@xyflow/react';
import type { ResolvedPolicy, Rule, EntityRule, Port } from '../../types/calico';
import type { RuleCategory, RuleDetail, SourceRange, InferredState, InferredStatus, CategoryGroup, PolicyNodeData, RuleNodeData, PolicyEdgeData } from '../../types/graph';
import type { RuleLineRanges } from '../parser/yamlLineMapper';
import { formatPort } from '../formatPort';
import { cidrContainsIp, coversAllPrivateRanges } from '../ipUtils';

// Determine the category of a rule based on its source/destination
function classifyRule(entity: EntityRule | undefined, policyNamespace?: string): RuleCategory {
  if (!entity) {
    // No source/destination specified = matches everything
    return 'outsideCluster';
  }

  // CIDRs (nets) are always network-level targets → outside cluster
  if (entity.nets && entity.nets.length > 0) {
    return 'outsideCluster';
  }

  // Services are K8s-native cluster resources → in cluster
  if (entity.services) {
    return 'inCluster';
  }

  // Service accounts: if no explicit namespace indication, target same namespace
  if (entity.serviceAccounts) {
    // If there's a namespaceSelector, it crosses namespaces → in cluster
    if (entity.namespaceSelector) {
      return 'inCluster';
    }
    // Otherwise, targets the policy's own namespace → in namespace (for namespaced policies)
    if (policyNamespace) {
      return 'inNamespace';
    }
    return 'inCluster';
  }

  // Selector with a namespace selector = cross-namespace → in cluster
  if (entity.namespaceSelector) {
    return 'inCluster';
  }

  // Selector without namespace selector in a namespaced policy → in namespace
  if (entity.selector) {
    if (policyNamespace) {
      return 'inNamespace';
    }
    return 'inCluster';
  }

  return 'outsideCluster';
}

function formatPorts(ports?: Port[]): string[] {
  if (!ports || ports.length === 0) return [];
  return ports.map(formatPort);
}

function describeRule(rule: Rule, direction: 'ingress' | 'egress', sourceRange?: SourceRange): RuleDetail {
  const entity = direction === 'ingress' ? rule.source : rule.destination;
  // The "opposite" entity carries match criteria for the other side of the rule
  // (destination for ingress, source for egress)
  const opposite = direction === 'ingress' ? rule.destination : rule.source;
  const parts: string[] = [];

  parts.push(`${rule.action}`);

  if (rule.protocol) {
    parts.push(`${rule.protocol}`);
  }

  if (entity?.ports && entity.ports.length > 0) {
    parts.push(`port${entity.ports.length > 1 ? 's' : ''} ${formatPorts(entity.ports).join(', ')}`);
  }

  if (entity?.nets && entity.nets.length > 0) {
    if (entity.nets.length <= 3) {
      parts.push(`to ${entity.nets.join(', ')}`);
    } else {
      parts.push(`to ${entity.nets.length} CIDRs`);
    }
  }

  if (entity?.selector) {
    parts.push(`selector: ${entity.selector}`);
  }

  if (entity?.namespaceSelector) {
    parts.push(`ns: ${entity.namespaceSelector}`);
  }

  if (entity?.services) {
    parts.push(`svc: ${entity.services.name}/${entity.services.namespace}`);
  }

  if (entity?.serviceAccounts) {
    if (entity.serviceAccounts.names && entity.serviceAccounts.names.length > 0) {
      parts.push(`sa: ${entity.serviceAccounts.names.join(', ')}`);
    }
    if (entity.serviceAccounts.selector) {
      parts.push(`sa selector: ${entity.serviceAccounts.selector}`);
    }
  }

  if (entity?.notNets && entity.notNets.length > 0) {
    parts.push(`NOT nets: ${entity.notNets.join(', ')}`);
  }

  if (entity?.notPorts && entity.notPorts.length > 0) {
    parts.push(`NOT ports: ${formatPorts(entity.notPorts).join(', ')}`);
  }

  // Include opposite-side info in description
  if (opposite?.ports && opposite.ports.length > 0) {
    const label = direction === 'ingress' ? 'dst' : 'src';
    parts.push(`${label} port${opposite.ports.length > 1 ? 's' : ''} ${formatPorts(opposite.ports).join(', ')}`);
  }
  if (opposite?.selector) {
    const label = direction === 'ingress' ? 'dst' : 'src';
    parts.push(`${label}: ${opposite.selector}`);
  }

  return {
    action: rule.action,
    protocol: rule.protocol ? String(rule.protocol) : undefined,
    ports: entity?.ports ? formatPorts(entity.ports) : undefined,
    nets: entity?.nets,
    notNets: entity?.notNets,
    selector: entity?.selector,
    notSelector: entity?.notSelector,
    namespaceSelector: entity?.namespaceSelector,
    notPorts: entity?.notPorts ? formatPorts(entity.notPorts) : undefined,
    services: entity?.services,
    serviceAccounts: entity?.serviceAccounts,
    description: parts.join(' '),
    // Opposite-side data
    dstPorts: direction === 'ingress' && opposite?.ports ? formatPorts(opposite.ports) : undefined,
    dstSelector: direction === 'ingress' ? opposite?.selector : undefined,
    dstNets: direction === 'ingress' ? opposite?.nets : undefined,
    srcPorts: direction === 'egress' && opposite?.ports ? formatPorts(opposite.ports) : undefined,
    srcSelector: direction === 'egress' ? opposite?.selector : undefined,
    srcNets: direction === 'egress' ? opposite?.nets : undefined,
    // YAML source line range
    sourceRange,
  };
}

// --- IP utilities imported from ../ipUtils ---

// Well-known DNS-related IPs
const DNS_IPS = ['169.254.25.10'];

// Well-known DNS service account names
const DNS_SA_NAMES = ['coredns', 'nodelocaldns', 'node-local-dns'];

// Well-known DNS service names
const DNS_SVC_NAMES = ['kube-dns'];

// Check if a rule explicitly targets DNS
function ruleMatchesDns(rule: Rule, direction: 'ingress' | 'egress'): boolean {
  const entity = direction === 'ingress' ? rule.source : rule.destination;
  if (!entity) return false;

  // Service named kube-dns
  if (entity.services) {
    if (DNS_SVC_NAMES.includes(entity.services.name)) return true;
  }

  // Service account named coredns/nodelocaldns
  if (entity.serviceAccounts?.names) {
    if (entity.serviceAccounts.names.some(n => DNS_SA_NAMES.includes(n))) return true;
  }

  // IP 169.254.25.10 in nets
  if (entity.nets) {
    if (DNS_IPS.some(dnsIp => entity.nets!.some(cidr => cidrContainsIp(cidr, dnsIp)))) return true;
  }

  // Port 53 (UDP or TCP)
  if (entity.ports) {
    if (entity.ports.some(p => p === 53 || p === '53')) return true;
  }

  return false;
}

// Check if an entity has any constraint that narrows matching traffic.
// Used to detect opposite-side restrictions (e.g. destination nets/ports/selector
// on an ingress rule) that prevent a rule from being a true catch-all.
function entityHasConstraints(entity: EntityRule | undefined): boolean {
  if (!entity) return false;
  if (entity.nets && entity.nets.length > 0) return true;
  if (entity.ports && entity.ports.length > 0) return true;
  if (entity.selector) return true;
  if (entity.namespaceSelector) return true;
  if (entity.services) return true;
  if (entity.serviceAccounts) return true;
  if (entity.notNets && entity.notNets.length > 0) return true;
  if (entity.notPorts && entity.notPorts.length > 0) return true;
  if (entity.notSelector) return true;
  return false;
}

// Check if a rule broadly allows/denies all cluster traffic.
// A rule that restricts by protocol or has any opposite-side constraint (e.g.
// destination nets/ports/selector on an ingress rule) does not broadly cover
// the cluster — it only matches a specific traffic class.
function ruleCoversBroadCluster(rule: Rule, direction: 'ingress' | 'egress'): boolean {
  // Protocol restriction narrows the traffic class
  if (rule.protocol) return false;

  // Any opposite-side constraint narrows which traffic matches
  const opposite = direction === 'ingress' ? rule.destination : rule.source;
  if (entityHasConstraints(opposite)) return false;

  const entity = direction === 'ingress' ? rule.source : rule.destination;

  // No entity = matches everything
  if (!entity) return true;

  // Nets that cover all private ranges
  if (entity.nets && coversAllPrivateRanges(entity.nets)) return true;

  return false;
}

// Check if a rule is a true catch-all (matches all traffic regardless of port/protocol).
// A rule is unrestricted only when:
//  - The same-side entity (source for ingress, destination for egress) is absent or 0.0.0.0/0
//  - No protocol restriction
//  - No opposite-side constraints (nets, ports, selectors, etc.)
function ruleIsUnrestricted(rule: Rule, direction: 'ingress' | 'egress'): boolean {
  // Protocol restriction narrows the traffic class — not a catch-all
  if (rule.protocol) return false;

  // Any opposite-side constraint narrows which traffic matches (e.g. dst nets/ports
  // on ingress, src nets/ports on egress). A rule with such constraints is not a catch-all.
  const opposite = direction === 'ingress' ? rule.destination : rule.source;
  if (entityHasConstraints(opposite)) return false;

  const entity = direction === 'ingress' ? rule.source : rule.destination;
  if (!entity) return true;
  if (entity.nets && entity.nets.length === 1 && entity.nets[0] === '0.0.0.0/0' && !entity.ports) return true;
  return false;
}

/**
 * Compute the effective default action for a direction by walking rules in order.
 *
 * Calico evaluates rules top-to-bottom. If a catch-all (unrestricted) Allow or Deny
 * rule exists, it determines what happens to traffic that isn't matched by any
 * earlier, more-specific rule. This "effective default" supersedes the Calico
 * implicit deny because no traffic can ever reach the implicit default.
 *
 * However, if a restricted Deny rule appears *before* a catch-all Allow, the policy
 * is selectively blocking traffic (e.g. deny all LAN, then allow internet). In this
 * case the effective default is reported as 'deny' because some traffic classes are
 * explicitly denied even though a catch-all Allow exists.
 *
 * Log/Pass rules are transparent — they don't resolve the verdict and are skipped.
 */
export function computeEffectiveDefault(
  rules: Rule[],
  direction: 'ingress' | 'egress',
  baseDefault: 'allow' | 'deny' | 'none',
): 'allow' | 'deny' {
  let seenRestrictedDeny = false;

  // Walk rules in Calico evaluation order
  for (const rule of rules) {
    if (!ruleIsUnrestricted(rule, direction)) {
      // Track restricted Deny rules (e.g. deny 10.0.0.0/8)
      if (rule.action === 'Deny') seenRestrictedDeny = true;
      continue;
    }

    // Log and Pass are transparent — don't resolve
    if (rule.action === 'Log' || rule.action === 'Pass') continue;

    // A catch-all Allow after a restricted Deny means the policy selectively
    // blocks traffic — report as 'deny' rather than 'allow'.
    if (rule.action === 'Allow') return seenRestrictedDeny ? 'deny' : 'allow';
    if (rule.action === 'Deny') return 'deny';
  }

  // No catch-all found — fall back to the Calico implicit default
  return baseDefault === 'allow' ? 'allow' : 'deny';
}

/**
 * Check whether a restricted Deny rule appears before a catch-all Allow rule.
 *
 * This is used by the explainer to produce a more informative message when the
 * effective default is 'deny' because of intermediate deny rules rather than the
 * Calico implicit default or a catch-all Deny.
 */
export function hasDenyBeforeCatchAll(
  rules: Rule[],
  direction: 'ingress' | 'egress',
): boolean {
  let seenRestrictedDeny = false;

  for (const rule of rules) {
    if (!ruleIsUnrestricted(rule, direction)) {
      if (rule.action === 'Deny') seenRestrictedDeny = true;
      continue;
    }
    if (rule.action === 'Log' || rule.action === 'Pass') continue;
    if (rule.action === 'Allow') return seenRestrictedDeny;
    // Unrestricted Deny — no catch-all Allow follows, so irrelevant
    return false;
  }

  return false;
}

/**
 * Infer DNS and cluster-wide access status by walking rules in order.
 * Returns inferred statuses for the "In Cluster" category block.
 */
export function inferClusterStatuses(rules: Rule[], direction: 'ingress' | 'egress'): InferredStatus[] {
  const statuses: InferredStatus[] = [];
  const loggedSuffix = ' (traffic is also logged)';

  // --- DNS inference ---
  let dnsResolved = false;
  let dnsState: InferredState = 'denied';
  let dnsReason = '';
  let dnsLogged = false;

  for (const rule of rules) {
    if (dnsResolved) break;

    // Check if this rule explicitly targets DNS
    if (ruleMatchesDns(rule, direction)) {
      // Log rules are transparent — they log but don't decide allow/deny
      if (rule.action === 'Log') {
        dnsLogged = true;
        continue;
      }
      if (rule.action === 'Allow') {
        dnsResolved = true;
        dnsState = 'allowed';
        dnsReason = 'Explicit allow rule matches DNS';
      } else if (rule.action === 'Deny') {
        dnsResolved = true;
        dnsState = 'denied';
        dnsReason = 'Explicit deny rule matches DNS';
      }
      continue;
    }

    // Check if this rule broadly covers cluster (and thus DNS)
    if (ruleCoversBroadCluster(rule, direction)) {
      if (rule.action === 'Log') {
        dnsLogged = true;
        continue;
      }
      if (rule.action === 'Deny') {
        dnsResolved = true;
        dnsState = 'denied';
        dnsReason = 'Denied by broad private-range deny rule';
      } else if (rule.action === 'Allow' && ruleIsUnrestricted(rule, direction)) {
        dnsResolved = true;
        dnsState = 'allowed';
        dnsReason = 'Allowed by unrestricted allow rule';
      }
    }
  }

  if (!dnsResolved) {
    dnsReason = 'No matching rule found; depends on policy default';
  }
  if (dnsLogged) {
    dnsReason += loggedSuffix;
  }

  statuses.push({
    label: 'Kubernetes DNS',
    state: dnsState,
    reason: dnsReason,
  });

  // --- Cluster-wide inference ---
  let clusterResolved = false;
  let clusterState: InferredState = 'denied';
  let clusterReason = '';
  let clusterLogged = false;

  for (const rule of rules) {
    if (clusterResolved) break;

    if (ruleCoversBroadCluster(rule, direction)) {
      if (rule.action === 'Log') {
        clusterLogged = true;
        continue;
      }
      if (rule.action === 'Allow') {
        clusterResolved = true;
        clusterState = 'allowed';
        clusterReason = 'Broad allow covers all cluster traffic';
      } else if (rule.action === 'Deny') {
        clusterResolved = true;
        clusterState = 'denied';
        clusterReason = 'Broad deny blocks all cluster traffic';
      }
    }

    if (!clusterResolved && ruleIsUnrestricted(rule, direction)) {
      if (rule.action === 'Log') {
        clusterLogged = true;
        continue;
      }
      if (rule.action === 'Allow') {
        clusterResolved = true;
        clusterState = 'allowed';
        clusterReason = 'Unrestricted allow rule covers everything';
      } else if (rule.action === 'Deny') {
        clusterResolved = true;
        clusterState = 'denied';
        clusterReason = 'Unrestricted deny rule blocks everything';
      }
    }
  }

  if (!clusterResolved) {
    clusterReason = 'No matching rule found; depends on policy default';
  }
  if (clusterLogged) {
    clusterReason += loggedSuffix;
  }

  statuses.push({
    label: 'Everything in the cluster',
    state: clusterState,
    reason: clusterReason,
  });

  return statuses;
}

/**
 * Check if a rule effectively targets "any pod" in the namespace.
 *
 * Returns:
 *  - 'direct'    – rule explicitly selects all pods in-namespace (selector all(),
 *                  empty selector, unrestricted serviceAccount, etc.)
 *  - 'implicit'  – rule covers namespace pods indirectly via broad CIDRs
 *                  (e.g. 10.0.0.0/8). The CIDRs *may* include pod IPs but
 *                  that is network-topology dependent, so we flag it as uncertain.
 *  - false       – rule does not match "any pod"
 */
function ruleMatchesAnyNamespacePod(
  rule: Rule,
  direction: 'ingress' | 'egress',
  policyNamespace: string,
): 'direct' | 'implicit' | false {
  const entity = direction === 'ingress' ? rule.source : rule.destination;

  // No entity at all → matches everything, including every pod in namespace
  if (!entity) return 'direct';

    const category = classifyRule(entity, policyNamespace);

  // If the rule is classified as inNamespace, check whether it narrows the target
  if (category === 'inNamespace') {
    // selector: all() means all endpoints
    if (entity.selector === 'all()') return 'direct';

    // serviceAccounts with no specific names and no selector → default SA, most pods use it
    if (entity.serviceAccounts) {
      const hasSpecificNames = entity.serviceAccounts.names && entity.serviceAccounts.names.length > 0;
      const hasSelector = !!entity.serviceAccounts.selector;
      if (!hasSpecificNames && !hasSelector) return 'direct';
    }

    // No selector, no serviceAccounts, no services, no nets → unrestricted within namespace
    if (!entity.selector && !entity.serviceAccounts && !entity.services && !entity.nets) {
      return 'direct';
    }

    // Has a specific selector or specific SA names → targets specific pods, not "any"
    return false;
  }

  // Cross-category: broad CIDRs covering all private ranges implicitly cover namespace pods
  if (entity.nets && coversAllPrivateRanges(entity.nets)) {
    return 'implicit';
  }

  // Unrestricted rule (0.0.0.0/0 no ports/protocol) covers everything including namespace pods
  if (ruleIsUnrestricted(rule, direction)) {
    return 'implicit';
  }

  return false;
}

/**
 * Infer "Any pod" access status for the "In Namespace" block.
 * Walks rules in order (first match wins).
 * Only applicable for namespaced policies; returns empty array for global policies.
 */
export function inferNamespaceStatuses(
  rules: Rule[],
  direction: 'ingress' | 'egress',
  policyNamespace?: string,
): InferredStatus[] {
  // Not meaningful for cluster-scoped policies
  if (!policyNamespace) return [];

  const statuses: InferredStatus[] = [];
  const loggedSuffix = ' (traffic is also logged)';

  let resolved = false;
  let state: InferredState = 'denied';
  let reason = '';
  let logged = false;

  for (const rule of rules) {
    if (resolved) break;

    const match = ruleMatchesAnyNamespacePod(rule, direction, policyNamespace);
    if (!match) continue;

    // Log rules are transparent — they log but don't decide allow/deny
    if (rule.action === 'Log') {
      logged = true;
      continue;
    }

    if (match === 'direct') {
      if (rule.action === 'Allow') {
        resolved = true;
        state = 'allowed';
        reason = 'Explicit allow rule targets all pods in namespace';
      } else if (rule.action === 'Deny') {
        resolved = true;
        state = 'denied';
        reason = 'Explicit deny rule targets all pods in namespace';
      }
    } else if (match === 'implicit') {
      if (rule.action === 'Allow') {
        resolved = true;
        state = 'uncertain';
        reason = 'Broad CIDR allow may cover pod IPs (network-topology dependent)';
      } else if (rule.action === 'Deny') {
        resolved = true;
        state = 'uncertain';
        reason = 'Broad CIDR deny may block pod IPs (network-topology dependent)';
      }
    }
  }

  if (!resolved) {
    reason = 'No matching rule found; depends on policy default';
  }
  if (logged) {
    reason += loggedSuffix;
  }

  statuses.push({
    label: 'Any pod',
    state,
    reason,
  });

  return statuses;
}

function getCategoryLabel(category: RuleCategory): string {
  switch (category) {
    case 'outsideCluster': return 'Outside Cluster';
    case 'inNamespace': return 'In Namespace';
    case 'inCluster': return 'In Cluster';
  }
}

export function policyToGraph(policy: ResolvedPolicy, ruleLineRanges?: RuleLineRanges | null): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Central policy node
  const effectiveIngress = computeEffectiveDefault(policy.ingressRules, 'ingress', policy.ingressDefault);
  const effectiveEgress = computeEffectiveDefault(policy.egressRules, 'egress', policy.egressDefault);

  const policyNodeData: PolicyNodeData = {
    name: policy.name,
    namespace: policy.namespace,
    kind: policy.kind,
    selector: policy.selector,
    tier: policy.tier,
    order: policy.order,
    namespaceSelector: policy.namespaceSelector,
    serviceAccountSelector: policy.serviceAccountSelector,
    ingressDefault: policy.ingressDefault,
    egressDefault: policy.egressDefault,
    effectiveIngressDefault: effectiveIngress,
    effectiveEgressDefault: effectiveEgress,
    // Policy-level flags from spec
    applyOnForward: policy.raw.spec.applyOnForward || undefined,
    preDNAT: policy.raw.spec.preDNAT || undefined,
    doNotTrack: policy.raw.spec.doNotTrack || undefined,
  };

  nodes.push({
    id: 'policy-center',
    type: 'policyNode',
    position: { x: 500, y: 200 },
    data: policyNodeData,
    draggable: true,
  });

  // Group ingress rules by category
  const ingressRanges = ruleLineRanges?.ingress ?? [];
  const ingressGroups = new Map<RuleCategory, { rules: RuleDetail[]; hasAllow: boolean; hasDeny: boolean; hasLog: boolean }>();
  for (let ruleIdx = 0; ruleIdx < policy.ingressRules.length; ruleIdx++) {
    const rule = policy.ingressRules[ruleIdx];
    const entity = rule.source;
    const category = classifyRule(entity, policy.namespace);
    const range = ruleIdx < ingressRanges.length ? ingressRanges[ruleIdx] : undefined;
    const detail = describeRule(rule, 'ingress', range);

    if (!ingressGroups.has(category)) {
      ingressGroups.set(category, { rules: [], hasAllow: false, hasDeny: false, hasLog: false });
    }
    const group = ingressGroups.get(category)!;
    group.rules.push(detail);
    if (rule.action === 'Allow') group.hasAllow = true;
    if (rule.action === 'Deny') group.hasDeny = true;
    if (rule.action === 'Log') group.hasLog = true;
  }

  // Group egress rules by category
  const egressRanges = ruleLineRanges?.egress ?? [];
  const egressGroups = new Map<RuleCategory, { rules: RuleDetail[]; hasAllow: boolean; hasDeny: boolean; hasLog: boolean }>();
  for (let ruleIdx = 0; ruleIdx < policy.egressRules.length; ruleIdx++) {
    const rule = policy.egressRules[ruleIdx];
    const entity = rule.destination;
    const category = classifyRule(entity, policy.namespace);
    const range = ruleIdx < egressRanges.length ? egressRanges[ruleIdx] : undefined;
    const detail = describeRule(rule, 'egress', range);

    if (!egressGroups.has(category)) {
      egressGroups.set(category, { rules: [], hasAllow: false, hasDeny: false, hasLog: false });
    }
    const group = egressGroups.get(category)!;
    group.rules.push(detail);
    if (rule.action === 'Allow') group.hasAllow = true;
    if (rule.action === 'Deny') group.hasDeny = true;
    if (rule.action === 'Log') group.hasLog = true;
  }

  // Helper: create nodes and edges for a direction, always showing all 3 categories
  const categoryOrder: RuleCategory[] = ['outsideCluster', 'inNamespace', 'inCluster'];
  const SPACING = 220;

  function createDirectionNodes(
    direction: 'ingress' | 'egress',
    groups: Map<RuleCategory, { rules: RuleDetail[]; hasAllow: boolean; hasDeny: boolean; hasLog: boolean }>,
    xPos: number,
    allRules: Rule[],
    policyNamespace?: string,
    isManaged?: boolean,
  ) {
    const managed = isManaged !== false;

    // Compute inferred statuses only for managed directions (unmanaged has no rules to infer from)
    const clusterInferred = managed ? inferClusterStatuses(allRules, direction) : undefined;
    const namespaceInferred = managed ? inferNamespaceStatuses(allRules, direction, policyNamespace) : undefined;

    let y = 50;

    for (const category of categoryOrder) {
      const group = groups.get(category);
      const isEmpty = !group || group.rules.length === 0;
      const nodeId = `${direction}-${category}`;

      const inferredForCategory = managed
        ? (category === 'inCluster'
            ? clusterInferred
            : category === 'inNamespace' && namespaceInferred && namespaceInferred.length > 0
              ? namespaceInferred
              : undefined)
        : undefined;

      const groupData: CategoryGroup = {
        category,
        label: getCategoryLabel(category),
        rules: group?.rules ?? [],
        hasAllow: group?.hasAllow ?? false,
        hasDeny: group?.hasDeny ?? false,
        hasLog: group?.hasLog ?? false,
        inferredStatuses: inferredForCategory,
      };

      const ruleNodeData: RuleNodeData = {
        category,
        label: getCategoryLabel(category),
        direction,
        groups: groupData,
        unmanaged: !managed || undefined,
      };

      nodes.push({
        id: nodeId,
        type: 'ruleNode',
        position: { x: xPos, y },
        data: ruleNodeData,
        draggable: true,
      });

      if (!managed) {
        // Unmanaged direction: green solid edges (traffic is allowed through)
        const edgeData: PolicyEdgeData = {
          action: 'Allow',
          rules: [],
          category,
        };

        const edgeBase = {
          id: `edge-${nodeId}`,
          type: 'policyEdge',
          data: edgeData,
          style: { stroke: '#22c55e', strokeWidth: 2 },
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e', width: 16, height: 16 },
        };

        if (direction === 'ingress') {
          edges.push({ ...edgeBase, source: nodeId, target: 'policy-center', sourceHandle: 'right', targetHandle: 'left' });
        } else {
          edges.push({ ...edgeBase, source: 'policy-center', target: nodeId, sourceHandle: 'right', targetHandle: 'left' });
        }
      } else if (isEmpty) {
        // Managed but empty category: dimmed dashed edge
        const edgeData: PolicyEdgeData = {
          action: 'Allow',
          rules: [],
          category,
        };

        const edgeBase = {
          id: `edge-${nodeId}`,
          type: 'policyEdge',
          data: edgeData,
          style: { stroke: '#475569', strokeWidth: 1, strokeDasharray: '6 4', opacity: 0.4 },
          animated: false,
          markerEnd: { type: MarkerType.ArrowClosed, color: '#475569', width: 16, height: 16 },
        };

        if (direction === 'ingress') {
          edges.push({ ...edgeBase, source: nodeId, target: 'policy-center', sourceHandle: 'right', targetHandle: 'left' });
        } else {
          edges.push({ ...edgeBase, source: 'policy-center', target: nodeId, sourceHandle: 'right', targetHandle: 'left' });
        }
      } else {
        // Active category: colored edge
        // Log rules are transparent (don't allow/deny). Edge color reflects the actual verdict:
        //   Allow only / Allow+Log → green    Deny only / Deny+Log → red
        //   Allow+Deny / All three → amber    Log only → amber (diagnostic, no verdict)
        const hasAllow = group!.hasAllow;
        const hasDeny = group!.hasDeny;
        const hasLog = group!.hasLog;
        const logOnly = hasLog && !hasAllow && !hasDeny;

        const edgeColor = logOnly
          ? '#f59e0b' // amber for log-only (no traffic decision)
          : hasDeny && hasAllow
            ? '#f59e0b' // amber for mixed allow+deny
            : hasDeny
              ? '#ef4444' // red for deny
              : '#22c55e'; // green for allow

        const edgeAction = logOnly ? 'Log' : hasDeny ? 'Deny' : 'Allow';

        const edgeData: PolicyEdgeData = {
          action: edgeAction,
          rules: group!.rules,
          category,
        };

        const edgeBase = {
          id: `edge-${nodeId}`,
          type: 'policyEdge',
          data: edgeData,
          style: { stroke: edgeColor, strokeWidth: 2 },
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor, width: 16, height: 16 },
        };

        if (direction === 'ingress') {
          edges.push({ ...edgeBase, source: nodeId, target: 'policy-center', sourceHandle: 'right', targetHandle: 'left' });
        } else {
          edges.push({ ...edgeBase, source: 'policy-center', target: nodeId, sourceHandle: 'right', targetHandle: 'left' });
        }
      }

      y += SPACING;
    }
  }

  // Create ingress nodes (left side) — always shown
  const ingressManaged = policy.types.includes('Ingress');
  createDirectionNodes('ingress', ingressGroups, 0, policy.ingressRules, policy.namespace, ingressManaged);

  // Create egress nodes (right side) — always shown
  const egressManaged = policy.types.includes('Egress');
  createDirectionNodes('egress', egressGroups, 1000, policy.egressRules, policy.namespace, egressManaged);

  // Vertically center the policy node between all rule nodes
  const allYPositions = nodes.filter(n => n.id !== 'policy-center').map(n => n.position.y);
  if (allYPositions.length > 0) {
    const minY = Math.min(...allYPositions);
    const maxY = Math.max(...allYPositions);
    const centerY = (minY + maxY) / 2;
    const policyNode = nodes.find(n => n.id === 'policy-center');
    if (policyNode) {
      policyNode.position.y = centerY;
    }
  }

  return { nodes, edges };
}
