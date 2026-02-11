// Shared IPv4 utilities used by both graph transformation and access tester

import type { Port } from '../types/calico';

export function ipToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function cidrContainsIp(cidr: string, ip: string): boolean {
  // Guard against null/undefined values that can slip through from incomplete YAML
  if (typeof cidr !== 'string' || typeof ip !== 'string') return false;
  const [cidrIp, bits] = cidr.split('/');
  const prefix = bits !== undefined ? Number(bits) : 32;
  // JS bit shifts are modulo 32, so << 32 wraps to << 0. Handle /0 explicitly.
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipToNum(cidrIp) & mask) === (ipToNum(ip) & mask);
}

// Private/internal IP ranges that cover typical cluster networks
export const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];

// Check if a set of CIDRs covers all private ranges (broad deny/allow of cluster)
export function coversAllPrivateRanges(nets: string[]): boolean {
  // Filter out any non-string values that may have slipped through from YAML parsing
  const validNets = nets.filter((n): n is string => typeof n === 'string');
  return PRIVATE_RANGES.every(pr => {
    const [prIp, prBits] = pr.split('/');
    const prPrefix = Number(prBits);
    return validNets.some(n => {
      const [nIp, nBits] = n.split('/');
      const nPrefix = Number(nBits);
      // n covers pr if n's prefix is shorter/equal and n's network contains pr's network
      if (nPrefix > prPrefix) return false;
      const mask = (~0 << (32 - nPrefix)) >>> 0;
      return (ipToNum(nIp) & mask) === (ipToNum(prIp) & mask);
    });
  });
}

/** Check whether a string looks like a valid IPv4 address */
export function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && p === String(n);
  });
}

/** Check whether a Calico port value is valid.
 *  - number: must be an integer in the range 0–65535
 *  - string containing ':': port range — both ends must be valid ports and start <= end
 *  - string without ':': named port (always considered valid)
 */
export function isValidPort(port: Port): boolean {
  if (typeof port === 'number') {
    return Number.isInteger(port) && port >= 0 && port <= 65535;
  }
  // String port — could be a range "start:end" or a named port
  if (port.includes(':')) {
    const parts = port.split(':');
    if (parts.length !== 2) return false;
    const start = Number(parts[0]);
    const end = Number(parts[1]);
    return (
      Number.isInteger(start) && start >= 0 && start <= 65535 &&
      Number.isInteger(end) && end >= 0 && end <= 65535 &&
      start <= end
    );
  }
  // Named port — Calico allows arbitrary named ports; always valid
  return true;
}

/** Check whether a CIDR string (e.g. "10.0.0.0/8") is valid IPv4 CIDR notation.
 *  - Must contain exactly one '/'
 *  - IP part must be a valid IPv4 address (4 octets, each 0–255)
 *  - Prefix length must be an integer 0–32
 */
export function isValidCidr(cidr: string): boolean {
  if (typeof cidr !== 'string') return false;
  const slashIdx = cidr.indexOf('/');
  if (slashIdx === -1) return false;
  // Ensure exactly one '/'
  if (cidr.indexOf('/', slashIdx + 1) !== -1) return false;

  const ip = cidr.substring(0, slashIdx);
  const prefixStr = cidr.substring(slashIdx + 1);

  if (!isValidIPv4(ip)) return false;

  const prefix = Number(prefixStr);
  return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32 && prefixStr === String(prefix);
}

/** Check whether a port number or range is matched by a Calico port spec */
export function portMatchesSpec(port: number, spec: number | string): boolean {
  if (typeof spec === 'number') return port === spec;
  // String can be a named port (can't resolve without container spec) or a range "start:end"
  if (spec.includes(':')) {
    const [startStr, endStr] = spec.split(':');
    const start = Number(startStr);
    const end = Number(endStr);
    if (!Number.isNaN(start) && !Number.isNaN(end)) {
      return port >= start && port <= end;
    }
  }
  // Named port — can't match without container spec, treat as no match
  return false;
}
