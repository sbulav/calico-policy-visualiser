import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';

type DecodePolicyResult = {
  yaml: string | null;
  error: string | null;
};

// Upper bound for YAML loaded from deep links or remote URLs.
// Real policies are a few KB; this guards against DoS via huge
// (or decompression-amplified) payloads parsed on the main thread.
export const MAX_POLICY_YAML_CHARS = 1_000_000;

export function decodePolicyParam(value: string): DecodePolicyResult {
  if (!value) {
    return { yaml: null, error: 'Policy parameter is empty.' };
  }

  if (value.length > MAX_POLICY_YAML_CHARS) {
    return { yaml: null, error: 'Deep link policy payload is too large.' };
  }

  if (value.startsWith('lz:')) {
    const encoded = value.slice(3);
    if (!encoded) {
      return { yaml: null, error: 'Deep link policy payload is empty.' };
    }

    const decompressed = decompressFromEncodedURIComponent(encoded);
    if (!decompressed) {
      return { yaml: null, error: 'Failed to decompress deep link policy payload.' };
    }

    if (decompressed.length > MAX_POLICY_YAML_CHARS) {
      return { yaml: null, error: 'Deep link policy payload is too large.' };
    }

    return { yaml: decompressed, error: null };
  }

  return { yaml: value, error: null };
}

export function encodePolicyParam(yaml: string, compress: boolean): string {
  if (compress) {
    return `lz:${compressToEncodedURIComponent(yaml)}`;
  }

  return encodeURIComponent(yaml);
}
