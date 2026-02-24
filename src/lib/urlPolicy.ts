import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';

type DecodePolicyResult = {
  yaml: string | null;
  error: string | null;
};

export function decodePolicyParam(value: string): DecodePolicyResult {
  if (!value) {
    return { yaml: null, error: 'Policy parameter is empty.' };
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
