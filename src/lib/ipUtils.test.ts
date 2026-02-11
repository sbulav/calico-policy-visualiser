import { describe, it, expect } from 'vitest';
import { cidrContainsIp, coversAllPrivateRanges, isValidPort, isValidCidr } from './ipUtils';

describe('cidrContainsIp — defensive guards', () => {
  it('returns false when cidr is null', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(cidrContainsIp(null as any, '10.0.0.1')).toBe(false);
  });

  it('returns false when cidr is undefined', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(cidrContainsIp(undefined as any, '10.0.0.1')).toBe(false);
  });

  it('returns false when ip is null', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(cidrContainsIp('10.0.0.0/8', null as any)).toBe(false);
  });

  it('still works correctly for valid inputs', () => {
    expect(cidrContainsIp('10.0.0.0/8', '10.1.2.3')).toBe(true);
    expect(cidrContainsIp('10.0.0.0/8', '192.168.1.1')).toBe(false);
    expect(cidrContainsIp('0.0.0.0/0', '1.2.3.4')).toBe(true);
  });
});

describe('coversAllPrivateRanges — defensive guards', () => {
  it('does not crash when nets contains null elements', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const nets = ['10.0.0.0/8', null as any, '172.16.0.0/12'];
    expect(() => coversAllPrivateRanges(nets)).not.toThrow();
  });

  it('returns false when a single range does not cover all private ranges', () => {
    expect(coversAllPrivateRanges(['10.0.0.0/8'])).toBe(false);
  });

  it('returns true when all private ranges are covered', () => {
    expect(coversAllPrivateRanges(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isValidPort
// ---------------------------------------------------------------------------

describe('isValidPort', () => {
  it('accepts valid numeric ports', () => {
    expect(isValidPort(0)).toBe(true);
    expect(isValidPort(80)).toBe(true);
    expect(isValidPort(443)).toBe(true);
    expect(isValidPort(65535)).toBe(true);
  });

  it('rejects out-of-range numeric ports', () => {
    expect(isValidPort(-1)).toBe(false);
    expect(isValidPort(65536)).toBe(false);
    expect(isValidPort(99999)).toBe(false);
    expect(isValidPort(100000)).toBe(false);
  });

  it('rejects non-integer numeric ports', () => {
    expect(isValidPort(80.5)).toBe(false);
    expect(isValidPort(NaN)).toBe(false);
    expect(isValidPort(Infinity)).toBe(false);
  });

  it('accepts valid port ranges', () => {
    expect(isValidPort('80:443')).toBe(true);
    expect(isValidPort('0:65535')).toBe(true);
    expect(isValidPort('8080:8080')).toBe(true);
  });

  it('rejects invalid port ranges', () => {
    expect(isValidPort('443:80')).toBe(false);    // start > end
    expect(isValidPort('80:99999')).toBe(false);   // end out of range
    expect(isValidPort('-1:80')).toBe(false);       // start out of range
    expect(isValidPort('abc:443')).toBe(false);     // non-numeric start
    expect(isValidPort('80:abc')).toBe(false);      // non-numeric end
    expect(isValidPort('1:2:3')).toBe(false);       // too many colons
  });

  it('accepts named ports (any string without colon)', () => {
    expect(isValidPort('http')).toBe(true);
    expect(isValidPort('dns')).toBe(true);
    expect(isValidPort('my-custom-port')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isValidCidr
// ---------------------------------------------------------------------------

describe('isValidCidr', () => {
  it('accepts valid CIDR notation', () => {
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('192.168.1.0/24')).toBe(true);
    expect(isValidCidr('0.0.0.0/0')).toBe(true);
    expect(isValidCidr('255.255.255.255/32')).toBe(true);
    expect(isValidCidr('172.16.0.0/12')).toBe(true);
  });

  it('rejects invalid IP octets', () => {
    expect(isValidCidr('256.0.0.0/8')).toBe(false);
    expect(isValidCidr('999.999.999.999/8')).toBe(false);
    expect(isValidCidr('10.0.0.300/24')).toBe(false);
    expect(isValidCidr('-1.0.0.0/8')).toBe(false);
  });

  it('rejects invalid prefix lengths', () => {
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
    expect(isValidCidr('10.0.0.0/-1')).toBe(false);
    expect(isValidCidr('10.0.0.0/abc')).toBe(false);
    expect(isValidCidr('10.0.0.0/8.5')).toBe(false);
  });

  it('rejects missing prefix', () => {
    expect(isValidCidr('10.0.0.0')).toBe(false);
  });

  it('rejects multiple slashes', () => {
    expect(isValidCidr('10.0.0.0/8/16')).toBe(false);
  });

  it('rejects malformed IP parts', () => {
    expect(isValidCidr('10.0.0/8')).toBe(false);     // only 3 octets
    expect(isValidCidr('10.0.0.0.0/8')).toBe(false);  // 5 octets
    expect(isValidCidr('/8')).toBe(false);              // no IP
    expect(isValidCidr('abc.def.ghi.jkl/8')).toBe(false);
  });

  it('rejects leading zeros in octets', () => {
    // isValidIPv4 requires p === String(n), so '010' !== '10'
    expect(isValidCidr('010.0.0.0/8')).toBe(false);
  });

  it('rejects leading zeros in prefix', () => {
    expect(isValidCidr('10.0.0.0/08')).toBe(false);
  });

  it('rejects non-string input', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(isValidCidr(null as any)).toBe(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(isValidCidr(undefined as any)).toBe(false);
  });
});
