import type { KubernetesLabelSelector } from '../../types/calico';

function quote(value: string): string {
  return `'${value.replace(/'/g, "\\'")}'`;
}

export function labelSelectorToExpression(selector: KubernetesLabelSelector | undefined): string | undefined {
  if (!selector) return undefined;

  const parts: string[] = [];

  if (selector.matchLabels) {
    for (const [key, value] of Object.entries(selector.matchLabels)) {
      parts.push(`${key} == ${quote(value)}`);
    }
  }

  if (selector.matchExpressions) {
    for (const expr of selector.matchExpressions) {
      if (expr.operator === 'Exists') {
        parts.push(`has(${expr.key})`);
      } else if (expr.operator === 'DoesNotExist') {
        parts.push(`!has(${expr.key})`);
      } else if (expr.operator === 'In') {
        const values = expr.values ?? [];
        if (values.length === 0) {
          parts.push('has(__k8s_invalid__) && !has(__k8s_invalid__)');
        } else {
          parts.push(`${expr.key} in {${values.map(quote).join(', ')}}`);
        }
      } else if (expr.operator === 'NotIn') {
        const values = expr.values ?? [];
        if (values.length === 0) {
          continue;
        }
        parts.push(`${expr.key} not in {${values.map(quote).join(', ')}}`);
      }
    }
  }

  if (parts.length === 0) {
    return 'all()';
  }

  return parts.join(' && ');
}
