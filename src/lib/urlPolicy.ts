import { decompressFromEncodedURIComponent } from 'lz-string';

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
      return { yaml: null, error: 'Compressed policy payload is empty.' };
    }

    const decompressed = decompressFromEncodedURIComponent(encoded);
    if (!decompressed) {
      return { yaml: null, error: 'Failed to decompress policy parameter.' };
    }

    return { yaml: decompressed, error: null };
  }

  return { yaml: value, error: null };
}
