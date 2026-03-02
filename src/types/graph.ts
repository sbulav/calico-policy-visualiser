import type { RuleAction, PolicySource } from './calico';

// Categories for grouping rules in the visualization
export type RuleCategory = 'outsideCluster' | 'inNamespace' | 'inCluster';

// Line range in the YAML source (1-based, inclusive)
export interface SourceRange {
  startLine: number;
  endLine: number;
}

export interface RuleDetail {
  action: RuleAction;
  protocol?: string;
  ports?: string[];
  nets?: string[];
  notNets?: string[];
  selector?: string;
  notSelector?: string;
  namespaceSelector?: string;
  notPorts?: string[];
  services?: { name: string; namespace: string };
  serviceAccounts?: { names?: string[]; selector?: string };
  description: string;
  // Opposite-side entity data (destination for ingress, source for egress)
  dstPorts?: string[];
  dstSelector?: string;
  dstNets?: string[];
  srcPorts?: string[];
  srcSelector?: string;
  srcNets?: string[];
  // YAML source line range for this rule (for editor highlighting)
  sourceRange?: SourceRange;
}

export type InferredState = 'allowed' | 'denied' | 'uncertain';

export interface InferredStatus {
  label: string;
  state: InferredState;
  reason: string;
}

export interface CategoryGroup {
  category: RuleCategory;
  label: string;
  rules: RuleDetail[];
  hasAllow: boolean;
  hasDeny: boolean;
  hasLog: boolean;
  inferredStatuses?: InferredStatus[];
}

export interface PolicyNodeData {
  policySource: PolicySource;
  name: string;
  namespace?: string;
  kind: string;
  selector: string;
  tier: string;
  order?: number;
  namespaceSelector?: string;
  serviceAccountSelector?: string;
  ingressDefault: string;
  egressDefault: string;
  effectiveIngressDefault: 'allow' | 'deny';
  effectiveEgressDefault: 'allow' | 'deny';
  // Policy-level flags
  applyOnForward?: boolean;
  preDNAT?: boolean;
  doNotTrack?: boolean;
  // Index signature for React Flow compatibility
  [key: string]: unknown;
}

export interface RuleNodeData {
  category: RuleCategory;
  label: string;
  direction: 'ingress' | 'egress';
  groups: CategoryGroup;
  unmanaged?: boolean;
  // Index signature for React Flow compatibility
  [key: string]: unknown;
}

export interface PolicyEdgeData {
  action: RuleAction;
  rules: RuleDetail[];
  category: RuleCategory;
  // Index signature for React Flow compatibility
  [key: string]: unknown;
}
