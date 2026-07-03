import type { Rule, EntityRule, Port } from '../types/calico';
import { formatPort } from './formatPort';

export type RuleDirection = 'ingress' | 'egress';

/**
 * Resolve the two sides of a rule for a given direction.
 *
 * For ingress rules the "entity" side is the source; for egress it's the
 * destination. The "opposite" side carries match criteria for the other
 * end of the connection (destination for ingress, source for egress).
 */
export function getRuleEntities(rule: Rule, direction: RuleDirection): {
  entity: EntityRule | undefined;
  opposite: EntityRule | undefined;
} {
  return direction === 'ingress'
    ? { entity: rule.source, opposite: rule.destination }
    : { entity: rule.destination, opposite: rule.source };
}

export function formatPorts(ports?: Port[]): string[] {
  if (!ports || ports.length === 0) return [];
  return ports.map(formatPort);
}

/** Inline up to `maxInline` CIDRs, otherwise summarize with a count and noun. */
export function summarizeNets(nets: string[], noun: string, maxInline = 3): string {
  if (nets.length <= maxInline) return nets.join(', ');
  return `${nets.length} ${noun}`;
}

const WELL_KNOWN_PORTS: Record<number, string> = {
  53: 'DNS',
  80: 'HTTP',
  443: 'HTTPS',
  22: 'SSH',
  25: 'SMTP',
  110: 'POP3',
  143: 'IMAP',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  27017: 'MongoDB',
  8080: 'HTTP-ALT',
  8443: 'HTTPS-ALT',
  9090: 'Prometheus',
  9093: 'Alertmanager',
  2379: 'etcd',
  6443: 'K8s API',
  10250: 'Kubelet',
};

export function describeWellKnownPort(port: Port): string {
  const p = typeof port === 'number' ? port : parseInt(port, 10);
  if (isNaN(p)) return '';
  return WELL_KNOWN_PORTS[p] || '';
}

/** Format a port, appending its well-known service name when recognized (e.g. "443 (HTTPS)"). */
export function formatPortWithWellKnown(port: Port): string {
  const wellKnown = describeWellKnownPort(port);
  const portStr = formatPort(port);
  return wellKnown ? `${portStr} (${wellKnown})` : portStr;
}
