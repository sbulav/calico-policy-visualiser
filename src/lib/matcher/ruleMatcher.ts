/**
 * Rule matcher — tests whether a single Calico rule matches a given traffic spec.
 *
 * DISCLAIMER: This is a best-effort emulation of Calico's rule matching logic
 * for educational and visualization purposes. It is NOT the actual Calico
 * data-plane engine. Real Calico evaluates rules in the kernel (eBPF or
 * iptables) with full context from the Kubernetes API. This emulation may
 * differ in edge cases. Do not rely on it for production security decisions.
 */

import type { Rule, EntityRule, Port } from '../../types/calico';
import type { TrafficSpec, RuleMatchResult, FieldMatchDetail } from '../../types/matcher';
import { cidrContainsIp, portMatchesSpec } from '../ipUtils';
import { evaluateSelector } from './selectorParser';

/**
 * Test whether a single rule matches the given traffic specification.
 *
 * For ingress rules, the traffic spec describes the *source* and the rule's
 * `source` entity is matched against it. For egress rules, the spec describes
 * the *destination* and `destination` is matched.
 *
 * Fields that the user didn't provide are marked as "indeterminate" — the rule
 * may or may not match on that field. A rule is considered matching only when
 * all evaluated fields match (AND semantics, per Calico).
 */
export function matchRule(
  rule: Rule,
  direction: 'ingress' | 'egress',
  spec: TrafficSpec,
): RuleMatchResult {
  const details: FieldMatchDetail[] = [];
  let hasFailure = false;
  let hasIndeterminate = false;

  // --- Protocol matching ---
  if (rule.protocol) {
    if (spec.protocol) {
      const ruleProto = String(rule.protocol).toUpperCase();
      const specProto = spec.protocol.toUpperCase();
      const matched = ruleProto === specProto;
      details.push({
        field: 'protocol',
        matched,
        reason: matched
          ? `Protocol ${specProto} matches`
          : `Protocol ${specProto} does not match required ${ruleProto}`,
      });
      if (!matched) hasFailure = true;
    } else {
      details.push({
        field: 'protocol',
        matched: false,
        indeterminate: true,
        reason: `Rule requires protocol ${rule.protocol}, not specified in test`,
      });
      hasIndeterminate = true;
    }
  }

  if (rule.notProtocol) {
    if (spec.protocol) {
      const ruleProto = String(rule.notProtocol).toUpperCase();
      const specProto = spec.protocol.toUpperCase();
      const matched = ruleProto !== specProto;
      details.push({
        field: 'notProtocol',
        matched,
        reason: matched
          ? `Protocol ${specProto} is not excluded (${ruleProto})`
          : `Protocol ${specProto} is excluded by notProtocol`,
      });
      if (!matched) hasFailure = true;
    } else {
      details.push({
        field: 'notProtocol',
        matched: false,
        indeterminate: true,
        reason: `Rule excludes protocol ${rule.notProtocol}, not specified in test`,
      });
      hasIndeterminate = true;
    }
  }

  // --- Same-side entity (source for ingress, destination for egress) ---
  const entity = direction === 'ingress' ? rule.source : rule.destination;
  if (entity) {
    matchEntity(entity, spec, details);
  }

  // --- Opposite-side entity (destination for ingress, source for egress) ---
  // Calico also evaluates constraints on the other side of the rule.
  // For the access tester, the opposite side describes the "self" endpoint
  // (the pod the policy applies to). We evaluate what we can.
  const opposite = direction === 'ingress' ? rule.destination : rule.source;
  if (opposite) {
    matchOppositePorts(opposite, spec, direction, details);
  }

  // --- Aggregate ---
  for (const d of details) {
    if (!d.matched && !d.indeterminate) hasFailure = true;
    if (d.indeterminate) hasIndeterminate = true;
  }

  const matches = !hasFailure && !hasIndeterminate;
  const reason = summarizeMatch(details, hasFailure, hasIndeterminate);

  return { matches, indeterminate: hasIndeterminate && !hasFailure, details, reason };
}

// ---- Entity field matching ----

function matchEntity(
  entity: EntityRule,
  spec: TrafficSpec,
  details: FieldMatchDetail[],
): void {
  // --- nets (CIDRs) ---
  if (entity.nets && entity.nets.length > 0) {
    if (spec.ip) {
      const matched = entity.nets.some(cidr => {
        // Handle bare IPs without prefix (treat as /32)
        const normalized = cidr.includes('/') ? cidr : `${cidr}/32`;
        return cidrContainsIp(normalized, spec.ip!);
      });
      details.push({
        field: 'nets',
        matched,
        reason: matched
          ? `IP ${spec.ip} is within allowed CIDRs`
          : `IP ${spec.ip} is not within any of: ${entity.nets.join(', ')}`,
      });
    } else {
      details.push({
        field: 'nets',
        matched: false,
        indeterminate: true,
        reason: `Rule requires IP in ${entity.nets.join(', ')}, no IP specified`,
      });
    }
  }

  // --- notNets ---
  if (entity.notNets && entity.notNets.length > 0) {
    if (spec.ip) {
      const excluded = entity.notNets.some(cidr => {
        const normalized = cidr.includes('/') ? cidr : `${cidr}/32`;
        return cidrContainsIp(normalized, spec.ip!);
      });
      details.push({
        field: 'notNets',
        matched: !excluded,
        reason: excluded
          ? `IP ${spec.ip} is excluded by notNets`
          : `IP ${spec.ip} is not in excluded ranges`,
      });
    } else {
      details.push({
        field: 'notNets',
        matched: false,
        indeterminate: true,
        reason: `Rule excludes IPs in ${entity.notNets.join(', ')}, no IP specified`,
      });
    }
  }

  // --- selector (label selector) ---
  if (entity.selector) {
    if (spec.labels && Object.keys(spec.labels).length > 0) {
      try {
        const matched = evaluateSelector(entity.selector, spec.labels);
        details.push({
          field: 'selector',
          matched,
          reason: matched
            ? `Labels match selector: ${entity.selector}`
            : `Labels do not match selector: ${entity.selector}`,
        });
      } catch (e) {
        details.push({
          field: 'selector',
          matched: false,
          indeterminate: true,
          reason: `Cannot parse selector: ${entity.selector} (${e instanceof Error ? e.message : String(e)})`,
        });
      }
    } else {
      details.push({
        field: 'selector',
        matched: false,
        indeterminate: true,
        reason: `Rule requires selector match: ${entity.selector}, no labels specified`,
      });
    }
  }

  // --- notSelector ---
  if (entity.notSelector) {
    if (spec.labels && Object.keys(spec.labels).length > 0) {
      try {
        const selectorMatches = evaluateSelector(entity.notSelector, spec.labels);
        details.push({
          field: 'notSelector',
          matched: !selectorMatches,
          reason: selectorMatches
            ? `Labels match excluded selector: ${entity.notSelector}`
            : `Labels do not match excluded selector (good)`,
        });
      } catch (e) {
        details.push({
          field: 'notSelector',
          matched: false,
          indeterminate: true,
          reason: `Cannot parse notSelector: ${entity.notSelector} (${e instanceof Error ? e.message : String(e)})`,
        });
      }
    } else {
      details.push({
        field: 'notSelector',
        matched: false,
        indeterminate: true,
        reason: `Rule has notSelector: ${entity.notSelector}, no labels specified`,
      });
    }
  }

  // --- namespaceSelector ---
  if (entity.namespaceSelector) {
    if (spec.namespaceLabels && Object.keys(spec.namespaceLabels).length > 0) {
      try {
        const matched = evaluateSelector(entity.namespaceSelector, spec.namespaceLabels);
        details.push({
          field: 'namespaceSelector',
          matched,
          reason: matched
            ? `Namespace labels match: ${entity.namespaceSelector}`
            : `Namespace labels do not match: ${entity.namespaceSelector}`,
         });
      } catch {
        details.push({
          field: 'namespaceSelector',
          matched: false,
          indeterminate: true,
          reason: `Cannot parse namespaceSelector: ${entity.namespaceSelector}`,
        });
      }
    } else if (spec.namespace) {
      // User provided namespace name but not labels. Calico namespace selectors
      // often use projectcalico.org/name which equals the namespace name.
      // Try with that synthetic label.
      try {
        const syntheticLabels: Record<string, string> = {
          'projectcalico.org/name': spec.namespace,
          'kubernetes.io/metadata.name': spec.namespace,
        };
        const matched = evaluateSelector(entity.namespaceSelector, syntheticLabels);
        details.push({
          field: 'namespaceSelector',
          matched,
          reason: matched
            ? `Namespace '${spec.namespace}' matches: ${entity.namespaceSelector} (via standard labels)`
            : `Namespace '${spec.namespace}' does not match: ${entity.namespaceSelector} (checked standard labels only)`,
        });
      } catch {
        details.push({
          field: 'namespaceSelector',
          matched: false,
          indeterminate: true,
          reason: `Cannot evaluate namespaceSelector: ${entity.namespaceSelector}`,
        });
      }
    } else {
      details.push({
        field: 'namespaceSelector',
        matched: false,
        indeterminate: true,
        reason: `Rule requires namespaceSelector: ${entity.namespaceSelector}, no namespace info specified`,
      });
    }
  }

  // --- ports ---
  if (entity.ports && entity.ports.length > 0) {
    if (spec.port !== undefined) {
      const matched = matchPortList(spec.port, entity.ports);
      details.push({
        field: 'ports',
        matched,
        reason: matched
          ? `Port ${spec.port} matches allowed ports`
          : `Port ${spec.port} does not match any of: ${formatPortList(entity.ports)}`,
      });
    } else {
      details.push({
        field: 'ports',
        matched: false,
        indeterminate: true,
        reason: `Rule allows ports ${formatPortList(entity.ports)}, no port specified`,
      });
    }
  }

  // --- notPorts ---
  if (entity.notPorts && entity.notPorts.length > 0) {
    if (spec.port !== undefined) {
      const excluded = matchPortList(spec.port, entity.notPorts);
      details.push({
        field: 'notPorts',
        matched: !excluded,
        reason: excluded
          ? `Port ${spec.port} is excluded by notPorts`
          : `Port ${spec.port} is not in excluded ports`,
      });
    } else {
      details.push({
        field: 'notPorts',
        matched: false,
        indeterminate: true,
        reason: `Rule excludes ports ${formatPortList(entity.notPorts)}, no port specified`,
      });
    }
  }

  // --- serviceAccounts ---
  if (entity.serviceAccounts) {
    if (entity.serviceAccounts.names && entity.serviceAccounts.names.length > 0) {
      if (spec.serviceAccountName) {
        const matched = entity.serviceAccounts.names.includes(spec.serviceAccountName);
        details.push({
          field: 'serviceAccounts.names',
          matched,
          reason: matched
            ? `ServiceAccount '${spec.serviceAccountName}' is in allowed list`
            : `ServiceAccount '${spec.serviceAccountName}' is not in: ${entity.serviceAccounts.names.join(', ')}`,
        });
      } else {
        details.push({
          field: 'serviceAccounts.names',
          matched: false,
          indeterminate: true,
          reason: `Rule requires SA in [${entity.serviceAccounts.names.join(', ')}], no SA specified`,
        });
      }
    }
    if (entity.serviceAccounts.selector) {
      // SA selector requires SA labels — we don't model those, so indeterminate
      details.push({
        field: 'serviceAccounts.selector',
        matched: false,
        indeterminate: true,
        reason: `Rule has SA selector: ${entity.serviceAccounts.selector} (SA label matching not supported)`,
      });
    }
  }

  // --- services ---
  if (entity.services) {
    if (spec.serviceName && spec.serviceNamespace) {
      const nameMatch = entity.services.name === spec.serviceName;
      const nsMatch = entity.services.namespace === spec.serviceNamespace;
      const matched = nameMatch && nsMatch;
      details.push({
        field: 'services',
        matched,
        reason: matched
          ? `Service ${spec.serviceNamespace}/${spec.serviceName} matches`
          : `Service ${spec.serviceNamespace}/${spec.serviceName} does not match required ${entity.services.namespace}/${entity.services.name}`,
      });
    } else if (spec.serviceName) {
      // Name provided but no namespace — partial match
      const nameMatch = entity.services.name === spec.serviceName;
      details.push({
        field: 'services',
        matched: false,
        indeterminate: true,
        reason: nameMatch
          ? `Service name '${spec.serviceName}' matches, but namespace not specified (required: ${entity.services.namespace})`
          : `Service name '${spec.serviceName}' does not match required '${entity.services.name}'`,
      });
    } else {
      details.push({
        field: 'services',
        matched: false,
        indeterminate: true,
        reason: `Rule targets service ${entity.services.namespace}/${entity.services.name}, no service specified`,
      });
    }
  }
}

/**
 * Match opposite-side port constraints.
 * For ingress, the "destination" entity on the rule constrains the policy endpoint's port.
 * For egress, the "source" entity constrains the policy endpoint's port.
 * We check port constraints if the user provided a port.
 */
function matchOppositePorts(
  opposite: EntityRule,
  spec: TrafficSpec,
  direction: 'ingress' | 'egress',
  details: FieldMatchDetail[],
): void {
  const side = direction === 'ingress' ? 'destination' : 'source';

  if (opposite.ports && opposite.ports.length > 0) {
    if (spec.port !== undefined) {
      const matched = matchPortList(spec.port, opposite.ports);
      details.push({
        field: `${side}.ports`,
        matched,
        reason: matched
          ? `Port ${spec.port} matches ${side} port constraint`
          : `Port ${spec.port} does not match ${side} ports: ${formatPortList(opposite.ports)}`,
      });
    } else {
      details.push({
        field: `${side}.ports`,
        matched: false,
        indeterminate: true,
        reason: `Rule constrains ${side} ports ${formatPortList(opposite.ports)}, no port specified`,
      });
    }
  }

  if (opposite.notPorts && opposite.notPorts.length > 0) {
    if (spec.port !== undefined) {
      const excluded = matchPortList(spec.port, opposite.notPorts);
      details.push({
        field: `${side}.notPorts`,
        matched: !excluded,
        reason: excluded
          ? `Port ${spec.port} is excluded by ${side} notPorts`
          : `Port ${spec.port} is not in excluded ${side} ports`,
      });
    } else {
      details.push({
        field: `${side}.notPorts`,
        matched: false,
        indeterminate: true,
        reason: `Rule excludes ${side} ports ${formatPortList(opposite.notPorts)}, no port specified`,
      });
    }
  }

  // Opposite-side selectors, nets, etc. constrain the policy endpoint itself.
  // Since we're testing external traffic, these aren't something the user provides.
  // We skip them as they describe the pod the policy is applied to, not the tested traffic.
  // We could evaluate them against policy.selector but that's a different concern.
  if (opposite.selector || opposite.nets || opposite.namespaceSelector) {
    details.push({
      field: `${side}.constraints`,
      matched: false,
      indeterminate: true,
      reason: `Rule has ${side}-side constraints (selector/nets) on the policy endpoint — not evaluated in this test`,
    });
  }
}

// ---- Helpers ----

function matchPortList(port: number, ports: Port[]): boolean {
  return ports.some(p => portMatchesSpec(port, p));
}

function formatPortList(ports: Port[]): string {
  return ports.map(p => String(p)).join(', ');
}

function summarizeMatch(
  details: FieldMatchDetail[],
  hasFailure: boolean,
  hasIndeterminate: boolean,
): string {
  if (details.length === 0) return 'No constraints — matches all traffic';

  if (hasFailure) {
    const failures = details.filter(d => !d.matched && !d.indeterminate);
    return `No match: ${failures.map(f => f.reason).join('; ')}`;
  }

  if (hasIndeterminate) {
    const unknowns = details.filter(d => d.indeterminate);
    return `Indeterminate: ${unknowns.map(u => u.field).join(', ')} not specified`;
  }

  return 'All constraints matched';
}
