import type { Port } from '../types/calico';

export function formatPort(port: Port): string {
  if (typeof port === 'number') return String(port);
  return port;
}
